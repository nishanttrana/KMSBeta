package main

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"vecta-kms/pkg/cryptocatalog"
)

// What a name stands for (8.1.0-beta, widened in 9.2.0-beta). A usage rule
// matches a literal: Cipher.getInstance("DES"). Code often names the
// algorithm some other way, and each way below is turned back into the
// literal before the rules run:
//
//   - a name the file assigns a string or a key size (ALG = "DES");
//   - a function with no arguments that only returns such a literal
//     (String alg() { return "DES"; });
//   - a format call or an interpolated string whose parts are all known
//     (String.format("%s/CBC/PKCS5Padding", ALG), f"{ALG}-cbc");
//   - a constant another file of the same scan defines (Constants.ALG),
//     for names written as constants: UPPER_CASE, or an exported Go name.
//
// It is still text, not evaluation: one literal per name and place, no
// arithmetic, no arguments, no control flow. A name with more than
// maxConstValues different values is a variable and is left alone. A finding
// resolved this way says through which name, and where it was assigned.

// constValue is a literal a name stands for.
type constValue struct {
	lit  string // as written where the name is read: "DES" or 1024
	line int
	file string // "" in the file being read; the defining file otherwise
}

const (
	constMods = `(?:(?:export|public|private|protected|internal|static|final|const|let|var|val|mut|readonly|pub|my|our|local)\s+)*`
	constLit  = `(?:"([^"\\\n]{1,64})"|'([^'\\\n]{1,64})'|(\d{3,5}))`
	constTail = `\s*;?\s*$`
)

var (
	// type name = value (Java, C#, C), name = value, name: type = value.
	reConst = regexp.MustCompile(`^\s*` + constMods + `(?:[A-Za-z_][\w.<>\[\]]*\s+)?([$@]?[A-Za-z_][\w.$]*)\s*(?::\s*[\w.<>\[\]&' ]+?\s*)?=\s*` + constLit + constTail)
	// Go: name := value, const name = value, var name type = value.
	reConstGo = regexp.MustCompile(`^\s*(?:const\s+|var\s+)?([A-Za-z_]\w*)(?:\s+[\w.\[\]*]+)?\s*(:?=)\s*` + constLit + constTail)
	// C: #define NAME value.
	reDefine     = regexp.MustCompile(`^\s*#\s*define\s+([A-Za-z_]\w*)\s+` + constLit + `\s*$`)
	reUpperConst = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

	// A function with no arguments: its opening line in a brace language
	// (with a Go receiver or a return type), in Python and in Ruby.
	reFuncBrace  = regexp.MustCompile(`^(?:[\w<>\[\],.?*&@]+\s+)*(?:\([^()]*\)\s*)?([A-Za-z_$][\w$]*)\s*\(\s*\)\s*(?:(?::|->)\s*[\w.<>\[\]&' ?]+|[\w.<>\[\]*&]+)?(?:\s+throws\s+[\w., ]+)?\s*\{$`)
	reFuncPython = regexp.MustCompile(`^def\s+([A-Za-z_]\w*)\s*\(\s*(?:self|cls)?\s*\)\s*(?:->\s*[\w.\[\]]+\s*)?:$`)
	reFuncRuby   = regexp.MustCompile(`^def\s+([A-Za-z_]\w*)\s*(?:\(\s*\))?$`)
	// The whole function on one line, or written as an expression.
	reFuncInline = regexp.MustCompile(`(?:^|\s)([A-Za-z_$][\w$]*)\s*\(\s*\)\s*(?:(?::|->)\s*[\w.<>\[\]&' ?]+|[\w.<>\[\]*&]+)?\s*\{\s*return\s+` + constLit + `\s*;?\s*\}$`)
	reFuncExpr   = regexp.MustCompile(`(?:^|\s)([A-Za-z_$][\w$]*)\s*(?:=\s*\(\s*\)\s*=>|\(\s*\)\s*(?::\s*[\w.<>?]+\s*)?(?:=>|=))\s*` + constLit + constTail)
	reReturnLit  = regexp.MustCompile(`^return\s+` + constLit + `\s*;?\s*\}?$`)
	reBareLit    = regexp.MustCompile(`^` + constLit + `$`)

	notFunctions = map[string]bool{"if": true, "for": true, "while": true, "switch": true, "catch": true, "else": true, "do": true,
		"try": true, "return": true, "new": true, "function": true, "func": true, "fn": true, "fun": true, "def": true, "synchronized": true}
)

// constName is the key a name is kept and looked up by: its last segment,
// without a sigil.
func constName(ident string) string {
	if i := strings.LastIndexByte(ident, '.'); i >= 0 {
		ident = ident[i+1:]
	}
	return strings.TrimLeft(ident, "$@")
}

func litOf(m []string, at int) string {
	if m[at+2] != "" {
		return m[at+2]
	}
	return `"` + m[at] + m[at+1] + `"`
}

// fileConsts collects what the names of one file stand for: assignments
// under the name, functions under name+"()". exported are the names another
// file may read (constantStyle).
func fileConsts(ext string, sts []statement, raw []byte) (all map[string][]constValue, exported map[string]bool) {
	all, exported = map[string][]constValue{}, map[string]bool{}
	add := func(name, lit string, line int) {
		for _, v := range all[name] {
			if v.lit == lit {
				return
			}
		}
		all[name] = append(all[name], constValue{lit: lit, line: line})
	}
	var (
		fn      string // the zero-argument function being read
		fnVals  []constValue
		fnOther bool // it also returns something that is not a literal
	)
	closeFn := func() {
		if fn != "" && !fnOther {
			for _, v := range fnVals {
				add(fn+"()", v.lit, v.line)
			}
		}
		fn, fnVals, fnOther = "", nil, false
	}
	for _, st := range sts {
		if st.toks == nil {
			continue
		}
		flat := strings.Join(strings.Fields(st.text), " ")
		if goExt[ext] {
			if m := reConstGo.FindStringSubmatch(flat); m != nil {
				add(constName(m[1]), litOf(m, 3), st.line)
				// A declaration, not ":=", of an exported name.
				if m[2] == "=" && m[1][0] >= 'A' && m[1][0] <= 'Z' {
					exported[m[1]] = true
				}
			}
		} else if m := reConst.FindStringSubmatch(flat); m != nil {
			name := constName(m[1])
			add(name, litOf(m, 2), st.line)
			if reUpperConst.MatchString(name) && len(name) >= 3 {
				exported[name] = true
			}
		}
		if m := reFuncInline.FindStringSubmatch(flat); m != nil && !notFunctions[m[1]] {
			add(m[1]+"()", litOf(m, 2), st.line)
			continue
		}
		if m := reFuncExpr.FindStringSubmatch(flat); m != nil && !notFunctions[m[1]] {
			add(m[1]+"()", litOf(m, 2), st.line)
			continue
		}
		def := reFuncBrace
		if pythonExt[ext] {
			def = reFuncPython
		} else if rubyExt[ext] {
			def = reFuncRuby
		}
		if m := def.FindStringSubmatch(flat); m != nil && !notFunctions[m[1]] {
			closeFn()
			fn = m[1]
			continue
		}
		if fn == "" {
			continue
		}
		switch m := reReturnLit.FindStringSubmatch(flat); {
		case m != nil:
			fnVals = append(fnVals, constValue{lit: litOf(m, 1), line: st.line})
		case strings.HasPrefix(flat, "return"):
			fnOther = true
		case rubyExt[ext] && len(fnVals) == 0:
			// Ruby returns its last expression: a body that is one literal.
			if m := reBareLit.FindStringSubmatch(flat); m != nil {
				fnVals = append(fnVals, constValue{lit: litOf(m, 1), line: st.line})
			} else if flat != "end" {
				fnOther = true
			}
		case strings.HasPrefix(flat, "def ") || strings.HasPrefix(flat, "func ") || strings.HasPrefix(flat, "function "):
			closeFn() // a function with arguments begins: the one being read is over
		}
	}
	closeFn()
	if cExt[ext] {
		// "#" is no comment in C, but a #define is read from the raw line:
		// its value is not an expression.
		for i, line := range strings.Split(string(raw), "\n") {
			if len(line) <= maxUsageLine && strings.Contains(line, "define") {
				if m := reDefine.FindStringSubmatch(strings.TrimRight(line, "\r")); m != nil {
					add(m[1], litOf(m, 2), i+1)
					if reUpperConst.MatchString(m[1]) && len(m[1]) >= 3 {
						exported[m[1]] = true
					}
				}
			}
		}
	}
	for name, vals := range all {
		if len(vals) > maxConstValues {
			delete(all, name)
			delete(exported, name)
		}
	}
	return all, exported
}

// constantStyle: a read that names a constant some file exports, as code
// writes one: UPPER_CASE (bare or behind a qualifier), or in Go an
// exported name (bare within the package, or pkg.Name).
func constantStyle(ext, ident string) bool {
	name := constName(ident)
	if reUpperConst.MatchString(name) && len(name) >= 3 {
		return true
	}
	return goExt[ext] && name != "" && name[0] >= 'A' && name[0] <= 'Z' && strings.Count(ident, ".") <= 1
}

// readsConstant reports whether the name at toks[i] is read there as a
// value: not called, not assigned to, and written as the file would write
// its own name (bare, this.name, self.name, or a constant behind any
// qualifier).
func readsConstant(ext string, toks []token, i int) bool {
	id := toks[i].text
	name := constName(id)
	if dot := strings.LastIndexByte(id, '.'); dot >= 0 {
		if q := id[:dot]; q != "this" && q != "self" && q != "$this" && !constantStyle(ext, id) {
			return false
		}
	}
	next, j := neighbour(toks, i, 1)
	if j >= 0 && isPunct(next, '(') {
		return false
	}
	if j >= 0 && isPunct(next, '=') && !(j+1 < len(toks) && isPunct(toks[j+1], '=')) {
		return false // an assignment or a named argument: key_size=...
	}
	if j >= 0 && isPunct(next, ':') && j+1 < len(toks) && isPunct(toks[j+1], '=') {
		return false
	}
	return ownMember(toks, i, name)
}

// ownMember: a member of something else (obj->name, Type::name) is the
// file's own only when it is spelled as a constant.
func ownMember(toks []token, i int, name string) bool {
	if prev, k := neighbour(toks, i, -1); k > 0 && ((isPunct(prev, '>') && isPunct(toks[k-1], '-')) || (isPunct(prev, ':') && isPunct(toks[k-1], ':'))) {
		owner, _ := neighbour(toks, k-1, -1)
		return reUpperConst.MatchString(name) || owner.text == "$this" || owner.text == "self"
	}
	return true
}

// callsNoArgs reports whether toks[i] is called with no arguments there,
// and the index of the closing parenthesis.
func callsNoArgs(toks []token, i int) (int, bool) {
	if id := toks[i].text; strings.Contains(id, ".") && !strings.HasPrefix(id, "this.") && !strings.HasPrefix(id, "self.") {
		return 0, false
	}
	open, j := neighbour(toks, i, 1)
	if j < 0 || !isPunct(open, '(') {
		return 0, false
	}
	shut, k := neighbour(toks, j, 1)
	if k < 0 || !isPunct(shut, ')') {
		return 0, false
	}
	return k, ownMember(toks, i, constName(toks[i].text))
}

// placeholders are the ways a string names a value inside itself. kind
// picks which apply (interpolating).
var placeholders = map[string]*regexp.Regexp{
	"dollar": regexp.MustCompile(`\$\{\s*([A-Za-z_][\w.]*)\s*\}|\$([A-Za-z_]\w*)`),
	"brace":  regexp.MustCompile(`\{\s*([A-Za-z_][\w.]*)\s*\}()`),
	"hash":   regexp.MustCompile(`#\{\s*([A-Za-z_@][\w.]*)\s*\}()`),
	"php":    regexp.MustCompile(`\{\$([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)`),
}

// interpolating says how the string at toks[i] takes values, "" if it does
// not, and whether the token before it is a prefix to drop (f"...", $"...").
func interpolating(ext string, toks []token, i int) (string, bool) {
	q := toks[i].text[0]
	prefix := ""
	if i > 0 {
		prefix = toks[i-1].text
	}
	switch {
	case q == '`' && jsExt[ext]:
		return "dollar", false
	case pythonExt[ext] && i > 0 && toks[i-1].kind == tokIdent && (strings.EqualFold(prefix, "f") || strings.EqualFold(prefix, "rf") || strings.EqualFold(prefix, "fr")):
		return "brace", true
	case csExt[ext] && prefix == "$":
		return "brace", true
	case q == '"' && (ext == ".kt" || ext == ".groovy" || ext == ".scala"):
		return "dollar", ext == ".scala" && toks[i-1].kind == tokIdent && prefix == "s"
	case q == '"' && rubyExt[ext]:
		return "hash", false
	case q == '"' && phpExt[ext]:
		return "php", false
	}
	return "", false
}

// lookup gives what a name stands for where it is read: the file's own
// value, or a constant another file exports. It records the names it was
// asked for and could not answer (needs).
type lookup struct {
	ext    string
	local  map[string][]constValue
	shared map[string][]constValue // nil: this file alone
	needs  map[string]bool
}

func (l *lookup) values(ident string, call bool) []constValue {
	name := constName(ident)
	if call {
		return l.local[name+"()"]
	}
	if v := l.local[name]; len(v) > 0 {
		return v
	}
	if !constantStyle(l.ext, ident) {
		return nil
	}
	if v := l.shared[name]; len(v) > 0 && len(v) <= maxConstValues {
		return v
	}
	if l.needs != nil && len(l.needs) < maxNeeds {
		l.needs[name] = true
	}
	return nil
}

const maxNeeds = 64

// site is one place in a statement where a name stands for a value.
type site struct {
	from, to int    // tokens toks[from:to] are replaced
	inString bool   // a placeholder inside the string at toks[from]
	key      string // what varies together: the name, or name()
	vals     []constValue
}

// sites finds the places in a statement that can be resolved.
func sites(st statement, l *lookup) []site {
	var out []site
	for i, t := range st.toks {
		switch t.kind {
		case tokIdent:
			if end, ok := callsNoArgs(st.toks, i); ok {
				if v := l.values(t.text, true); len(v) > 0 {
					out = append(out, site{from: i, to: end + 1, key: constName(t.text) + "()", vals: v})
				}
				continue
			}
			if readsConstant(l.ext, st.toks, i) {
				if v := l.values(t.text, false); len(v) > 0 {
					out = append(out, site{from: i, to: i + 1, key: constName(t.text), vals: v})
				}
			}
		case tokString:
			kind, _ := interpolating(l.ext, st.toks, i)
			if kind == "" {
				continue
			}
			for _, m := range placeholders[kind].FindAllStringSubmatch(t.text, -1) {
				id := m[1] + m[2]
				if v := l.values(id, false); len(v) > 0 {
					out = append(out, site{from: i, to: i + 1, inString: true, key: constName(id), vals: v})
				}
			}
		}
	}
	return out
}

func unquote(lit string) string {
	if len(lit) >= 2 && (lit[0] == '"' || lit[0] == '\'') {
		return lit[1 : len(lit)-1]
	}
	return lit
}

// render writes the statement with each name replaced by the value choice
// gives it.
func render(ext string, st statement, at []site, choice map[string]constValue) string {
	byTok := map[int]site{}
	inString := map[int]bool{}
	for _, s := range at {
		if s.inString {
			inString[s.from] = true
		} else {
			byTok[s.from] = s
		}
	}
	var sb strings.Builder
	for i := 0; i < len(st.toks); i++ {
		t := st.toks[i]
		if s, ok := byTok[i]; ok {
			sb.WriteString(choice[s.key].lit)
			i = s.to - 1
			continue
		}
		if i+1 < len(st.toks) && inString[i+1] {
			if _, drop := interpolating(ext, st.toks, i+1); drop {
				continue // the f of f"...", the $ of $"..."
			}
		}
		if inString[i] {
			kind, _ := interpolating(ext, st.toks, i)
			text := placeholders[kind].ReplaceAllStringFunc(t.text, func(ph string) string {
				m := placeholders[kind].FindStringSubmatch(ph)
				if v, ok := choice[constName(m[1]+m[2])]; ok {
					return unquote(v.lit)
				}
				return ph
			})
			if t.text[0] == '`' {
				text = `"` + text[1:len(text)-1] + `"` // the rules read quoted literals
			}
			sb.WriteString(text)
			continue
		}
		sb.WriteString(t.text)
	}
	return sb.String()
}

const fmtArgs = `((?:\s*,\s*(?:"[^"\n]*"|'[^'\n]*'|\d+))*)\s*,?\s*\)`

var (
	reFormatCall = regexp.MustCompile(`(?:String\.[Ff]ormat|fmt\.Sprintf|\bsprintf|\bformat!)\(\s*"((?:[^"\\\n]|\\.)*)"` + fmtArgs)
	rePyFormat   = regexp.MustCompile(`(["'])((?:[^"'\\\n]|\\.)*)["']\.format\(\s*((?:"[^"\n]*"|'[^'\n]*'|\d+)(?:\s*,\s*(?:"[^"\n]*"|'[^'\n]*'|\d+))*)\s*\)`)
	rePyPercent  = regexp.MustCompile(`(["'])((?:[^"'\\\n]|\\.)*)["']\s*%\s*(?:\(\s*((?:"[^"\n]*"|'[^'\n]*'|\d+)(?:\s*,\s*(?:"[^"\n]*"|'[^'\n]*'|\d+))*)\s*,?\s*\)|("[^"\n]*"|'[^'\n]*'|\d+))`)
	reFmtVerb    = regexp.MustCompile(`%[sdvSq]|\{\d*\}|\{:\w*\}`)
	reFmtArg     = regexp.MustCompile(`"[^"\n]*"|'[^'\n]*'|\d+`)
)

// applyFormat fills a format string's verbs with literal arguments. ok is
// false unless every verb gets one and every argument is used.
func applyFormat(format, args string) (string, bool) {
	vals := reFmtArg.FindAllString(args, -1)
	n := 0
	out := reFmtVerb.ReplaceAllStringFunc(format, func(verb string) string {
		if n >= len(vals) {
			n++
			return verb
		}
		n++
		return unquote(vals[n-1])
	})
	return out, n == len(vals) && n > 0
}

// foldFormats rewrites format calls whose arguments are all literals into
// the literal they produce. Line breaks inside a call are kept after it.
func foldFormats(ext, text string) string {
	fold := func(re *regexp.Regexp, format, args int) {
		text = re.ReplaceAllStringFunc(text, func(call string) string {
			m := re.FindStringSubmatch(call)
			a := m[args]
			if a == "" && args+1 < len(m) {
				a = m[args+1]
			}
			out, ok := applyFormat(m[format], a)
			if !ok {
				return call
			}
			return `"` + out + `"` + strings.Repeat("\n", strings.Count(call, "\n"))
		})
	}
	if !strings.Contains(text, "ormat") && !strings.Contains(text, "printf") && !strings.Contains(text, "%") {
		return text
	}
	fold(reFormatCall, 1, 2)
	if pythonExt[ext] {
		fold(rePyFormat, 2, 3)
		fold(rePyPercent, 2, 3)
	}
	return text
}

// scanStatement applies the rules to a statement as written and with its
// names resolved. shared marks findings that needed another file.
func scanStatement(ext string, st statement, l *lookup, seen map[string]bool) []finding {
	lineOf := func(text string) func(int) int {
		return func(off int) int { return st.line + strings.Count(text[:off], "\n") }
	}
	plain := foldFormats(ext, st.text)
	out := matchUsage(ext, plain, lineOf(plain), seen, nil)
	if st.toks == nil {
		return out
	}
	at := sites(st, l)
	if len(at) == 0 {
		return out
	}
	keys := map[string][]constValue{}
	var order []string
	for _, s := range at {
		if _, ok := keys[s.key]; !ok {
			order = append(order, s.key)
		}
		keys[s.key] = s.vals
	}
	base := map[string]constValue{}
	for _, k := range order {
		base[k] = keys[k][0]
	}
	try := func(choice map[string]constValue) {
		text := foldFormats(ext, render(ext, st, at, choice))
		via := func(match string) map[string]interface{} {
			meta := map[string]interface{}{}
			var names []string
			for _, k := range order {
				if strings.Contains(match, unquote(choice[k].lit)) {
					names = append(names, k)
				}
			}
			if len(names) == 0 {
				names = order
			}
			sort.Strings(names)
			first := choice[names[0]]
			meta["via"], meta["assigned_line"] = strings.Join(names, ", "), first.line
			if first.file != "" {
				meta["defined_in"] = first.file
			}
			return meta
		}
		out = append(out, matchUsage(ext, text, lineOf(text), seen, via)...)
	}
	try(base)
	for _, k := range order {
		for _, v := range keys[k][1:] {
			choice := map[string]constValue{}
			for name, val := range base {
				choice[name] = val
			}
			choice[k] = v
			try(choice)
		}
	}
	return out
}

// matchUsage applies the rules to text. lineAt gives the line of an offset
// in it; seen keeps one finding per line and algorithm; via, when set,
// gives what is recorded with a finding from the text that matched.
func matchUsage(ext, text string, lineAt func(int) int, seen map[string]bool, via func(match string) map[string]interface{}) []finding {
	var out []finding
	for _, r := range usageRules {
		if r.exts != nil && !r.exts[ext] {
			continue
		}
		if r.exts == nil && !configExt[ext] && ext != "" && !scriptExt[ext] {
			// Directive rules read configuration and scripts, not code.
			continue
		}
		for _, loc := range r.re.FindAllStringSubmatchIndex(text, -1) {
			m := make([]string, len(loc)/2)
			for g := range m {
				if loc[2*g] >= 0 {
					m[g] = text[loc[2*g]:loc[2*g+1]]
				}
			}
			// The line the match starts on (a rule may match the line break
			// before it).
			off := loc[0]
			for off < loc[1] && (text[off] == '\n' || text[off] == ' ' || text[off] == '\t') {
				off++
			}
			n := lineAt(off)
			for _, alg := range r.algs(m) {
				// The catalogue's own spelling (TLSv1 -> TLS-1.0, 3DES -> 3TDEA).
				if e, ok := cryptocatalog.Lookup(alg); ok {
					alg = e.Algorithm
				}
				key := alg + "|" + strconv.Itoa(n)
				// A name that still holds a placeholder ("$family/CBC",
				// "%s-cbc") names no algorithm.
				if alg == "" || seen[key] || strings.ContainsAny(alg, "${}%#") {
					continue
				}
				seen[key] = true
				meta := map[string]interface{}{"api": r.api}
				if via != nil {
					for k, v := range via(m[0]) {
						meta[k] = v
					}
				}
				out = append(out, finding{kind: "crypto_usage", algorithm: alg, name: alg + " · " + r.api, line: n, meta: meta})
			}
		}
	}
	return out
}
