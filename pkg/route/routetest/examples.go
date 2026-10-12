package routetest

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"vecta-kms/pkg/fips/fipstest"
)

// Examples proves a service's hand-written REST examples (the dashboard's
// REST API tab) against its real handlers. A service test is one call:
//
//	routetest.Examples(t, routetest.ExampleSet{Service: "secrets", Serve: serve})
//
// Each example is sent as written. The route must exist; the body must
// decode; and the answer the example shows must be the one the service
// gives: where the call succeeds every field of the example response must be
// in the real one, and where it does not the example may show only the note
// that discovered routes carry. So nothing the tab shows as a response is a
// guess (docs/DECISIONS.md, 2026-10-12). In strict FIPS mode a refused call
// is not held against its example.
//
// The examples are exported by web/dashboard/scripts/generate-rest-catalog.mjs.
// REST_EXAMPLES_DUMP=1 prints what the service answers; REST_EXAMPLES_OUT=<file>
// writes it, to write an example from.
type ExampleSet struct {
	Service string
	// Serve sends one request to the service as a caller who may do
	// everything in Tenant.
	Serve func(http.ResponseWriter, *http.Request)
	// Tenant fills {{tenant_id}}; "t1" when empty.
	Tenant string
	// Values fills other {{placeholders}} and the "<...>" hints of a body by
	// field name, before anything the examples themselves produce.
	Values map[string]string
	// ValuesFor gives one example its own values (a key per example whose
	// call changes state).
	ValuesFor func(id string) map[string]string
	// Aliases names, for a placeholder, the produced value it stands for:
	// {"cert_id": "certificate_id"} where the service answers
	// {"certificate": {"id": ...}}.
	Aliases map[string]string
	// First lists examples to run before the others, in order: the ones whose
	// answers later examples need.
	First []string
	// Skip names examples that are not sent, with the reason: a call that
	// would reach outside the test (scan a network). Such an example may show
	// only the note.
	Skip map[string]string
	// Min is the least number of examples expected (0: at least one).
	Min int
}

// Example is one exported example.
type Example struct {
	ID       string         `json:"id"`
	Service  string         `json:"service"`
	Method   string         `json:"method"`
	Path     string         `json:"pathTemplate"`
	Body     string         `json:"bodyTemplate"`
	Response map[string]any `json:"responseExample"`
}

// ExampleNote is the response a route shows when no answer was obtained for it.
const ExampleNote = "Execute endpoint to inspect the live response payload."

const examplesFile = "../../web/dashboard/src/generated/restApiExamples.generated.json"

var (
	examplePlaceholder = regexp.MustCompile(`\{\{([a-zA-Z0-9_]+)\}\}`)
	// A route's {param}, which the tab turns into its {{param}} placeholder.
	exampleRouteParam = regexp.MustCompile(`(^|[^{])\{([a-zA-Z0-9_]+)\}`)
)

// LoadExamples returns a service's exported examples.
func LoadExamples(t testing.TB, service string) []Example {
	t.Helper()
	raw, err := os.ReadFile(examplesFile)
	if err != nil {
		t.Fatal(err)
	}
	var all, out []Example
	if err := json.Unmarshal(raw, &all); err != nil {
		t.Fatal(err)
	}
	for _, ex := range all {
		if ex.Service == service {
			out = append(out, ex)
		}
	}
	return out
}

func methodRank(method string) int {
	switch method {
	case http.MethodPost:
		return 0
	case http.MethodPut, http.MethodPatch:
		return 1
	case http.MethodDelete:
		return 3
	}
	return 2
}

// Examples runs the set and fails t for each example that does not hold.
func Examples(t *testing.T, set ExampleSet) {
	t.Helper()
	examples := LoadExamples(t, set.Service)
	if len(examples) == 0 || len(examples) < set.Min {
		t.Fatalf("%d examples exported for %s", len(examples), set.Service)
	}
	first := map[string]int{}
	for i, id := range set.First {
		first[id] = i + 1
	}
	// Creators before readers, removals last, so an example can use what an
	// earlier one made.
	sort.SliceStable(examples, func(i, j int) bool {
		a, b := first[examples[i].ID], first[examples[j].ID]
		if (a != 0) != (b != 0) {
			return a != 0
		}
		if a != b {
			return a < b
		}
		return methodRank(examples[i].Method) < methodRank(examples[j].Method)
	})
	tenant := set.Tenant
	if tenant == "" {
		tenant = "t1"
	}
	produced := map[string]string{}
	value := func(id, name string) (string, bool) {
		if name == "tenant_id" {
			return tenant, true
		}
		if set.ValuesFor != nil {
			if v, ok := set.ValuesFor(id)[name]; ok {
				return v, true
			}
		}
		if v, ok := set.Values[name]; ok {
			return v, true
		}
		if alias, ok := set.Aliases[name]; ok {
			name = alias
		}
		v, ok := produced[name]
		return v, ok
	}
	fill := func(id, text string) string {
		text = exampleRouteParam.ReplaceAllString(text, "$1{{$2}}")
		return examplePlaceholder.ReplaceAllStringFunc(text, func(m string) string {
			name := m[2 : len(m)-2]
			if v, ok := value(id, name); ok {
				return v
			}
			return "sample"
		})
	}
	// A body value written as "<...>" stands for another example's answer.
	withAnswers := func(id, body string) string {
		var fields map[string]any
		if json.Unmarshal([]byte(body), &fields) != nil {
			return body
		}
		changed := false
		for name, v := range fields {
			if text, isText := v.(string); isText && strings.HasPrefix(text, "<") {
				if real, ok := value(id, name); ok {
					fields[name], changed = real, true
				}
			}
			// ["<token from tokenize>"]: a list of one such answer.
			if list, isList := v.([]any); isList && len(list) > 0 {
				if text, isText := list[0].(string); isText && strings.HasPrefix(text, "<") {
					if real, ok := value(id, strings.TrimSuffix(name, "s")); ok {
						fields[name], changed = []any{real}, true
					}
				}
			}
		}
		if !changed {
			return body
		}
		out, _ := json.Marshal(fields)
		return string(out)
	}
	remember := func(prefix string, obj map[string]any) {
		for name, v := range obj {
			text, isText := v.(string)
			if !isText || text == "" {
				continue
			}
			if name == "id" && prefix != "" {
				produced[prefix+"_id"] = text
			}
			// The latest id wins (the object just made); any other field keeps
			// the first answer that carried it.
			if _, taken := produced[name]; !taken || name == "id" {
				produced[name] = text
			}
		}
	}

	answers := map[string]map[string]any{}
	compared := 0
	for _, ex := range examples {
		note, shown := ex.Response["note"].(string)
		showsAnswer := !(shown && note == ExampleNote && len(ex.Response) == 1)
		if why, skip := set.Skip[ex.ID]; skip {
			if showsAnswer {
				t.Errorf("%s is not sent here (%s), so it may show only the note", ex.ID, why)
			}
			answers[ex.ID] = map[string]any{"status": 0, "body": "not sent: " + why}
			continue
		}
		path := fill(ex.ID, ex.Path)
		body := withAnswers(ex.ID, fill(ex.ID, ex.Body))
		req := httptest.NewRequest(ex.Method, path, bytes.NewBufferString(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("X-Tenant-ID", tenant) // as the playground sends it
		w := httptest.NewRecorder()
		set.Serve(w, req)
		text := strings.TrimSpace(w.Body.String())
		answers[ex.ID] = map[string]any{"status": w.Code, "body": json.RawMessage(orNull(text))}
		if os.Getenv("REST_EXAMPLES_DUMP") != "" {
			t.Logf("%s %s %s -> %d %s", ex.ID, ex.Method, path, w.Code, text)
		}
		switch {
		case w.Code == http.StatusNotFound && strings.Contains(text, "404 page not found"), w.Code == http.StatusMethodNotAllowed:
			t.Errorf("%s: %s %s is not a route of %s (%d)", ex.ID, ex.Method, ex.Path, set.Service, w.Code)
			continue
		case strings.Contains(text, "unknown field"), strings.Contains(text, "cannot unmarshal"), strings.Contains(text, "invalid character"):
			t.Errorf("%s: the example body does not decode: %s", ex.ID, text)
			continue
		}
		if w.Code < 200 || w.Code > 299 {
			// Strict FIPS mode refuses what is not approved, and what a test
			// double cannot back with real key material. The response is
			// compared in the modes where the call succeeds.
			if showsAnswer && !fipstest.Strict() {
				t.Errorf("%s: the example shows a response, but the call answered %d (%s): make it succeed here, or show the note", ex.ID, w.Code, text)
			}
			continue
		}
		var got map[string]any
		if json.Unmarshal(w.Body.Bytes(), &got) != nil {
			if showsAnswer {
				t.Errorf("%s: the example shows a JSON object; the service answered %q", ex.ID, text)
			}
			continue
		}
		remember("", got)
		for name, v := range got {
			switch inner := v.(type) {
			case map[string]any:
				remember(name, inner)
			case []any: // the first of a list: {"items": [{"token": ...}]}
				if obj, ok := firstObject(inner); ok {
					for field, fv := range obj {
						if text, isText := fv.(string); isText && text != "" && field != "id" {
							if _, taken := produced[field]; !taken {
								produced[field] = text
							}
						}
					}
				}
			}
		}
		if !showsAnswer {
			continue
		}
		var missing []string
		for field := range ex.Response {
			if _, ok := got[field]; !ok {
				missing = append(missing, field)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			t.Errorf("%s: the example response shows %v, which the service did not return (%s)", ex.ID, missing, text)
			continue
		}
		compared++
	}
	if out := os.Getenv("REST_EXAMPLES_OUT"); out != "" {
		raw, _ := json.MarshalIndent(answers, "", "  ")
		if err := os.WriteFile(out, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("%s: %d examples sent; response compared for %d", set.Service, len(examples), compared)
}

func firstObject(list []any) (map[string]any, bool) {
	if len(list) == 0 {
		return nil, false
	}
	obj, ok := list[0].(map[string]any)
	return obj, ok
}

func orNull(text string) string {
	if json.Valid([]byte(text)) {
		return text
	}
	raw, _ := json.Marshal(text)
	return string(raw)
}
