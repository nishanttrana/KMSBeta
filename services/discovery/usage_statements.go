package main

import (
	"regexp"
	"strconv"
	"strings"

	"vecta-kms/pkg/cryptocatalog"
)

// Usage rules read statements, not lines (8.1.0-beta). Until now each rule
// saw one line, so three ordinary ways of writing a call were missed:
//
//	Cipher.getInstance(            the argument on the next line
//	    "DES/CBC/PKCS5Padding");
//	Cipher.getInstance("DES" +     the name built from pieces
//	    "/CBC/PKCS5Padding");
//	String ALG = "DES";            the name held in a variable
//	Cipher.getInstance(ALG);
//
// A source file is now cut into statements: a line and the lines that
// continue it (an open parenthesis, a trailing or leading "+", a trailing
// backslash in scripts and configuration). Adjacent string literals joined
// by the language's operator are folded into one. A name that the same
// file assigns a string or a key size is replaced by that value where it is
// read, and the finding says which name and where it was assigned.
//
// It stays deterministic and local: strings and comments are told apart by
// a tokeniser, not by evaluating code. Not resolved: a value from another
// file, a function's result, a format string, or a name assigned more than
// maxConstValues different values (that is a variable, not a constant).

const (
	maxStatementLines = 12
	maxConstValues    = 4
)

type tokKind byte

const (
	tokString tokKind = iota // a quoted literal, quotes included
	tokIdent                 // a name, with its dots and a leading $ or @
	tokPunct                 // one other character
	tokSpace                 // white space, or the line break between two lines
)

type token struct {
	kind tokKind
	text string
}

// codeExt: a programming language, whose statements continue across lines
// and whose strings and comments the tokeniser knows.
func codeExt(ext string) bool {
	for _, set := range []map[string]bool{javaLike, pythonExt, goExt, jsExt, csExt, cExt, phpExt, rubyExt, rustExt} {
		if set[ext] {
			return true
		}
	}
	return false
}

func identStart(c byte) bool {
	return c == '_' || c == '$' || c == '@' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func identPart(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// tokenize cuts one line of code into tokens and drops a trailing comment.
// A quote that never closes on the line is punctuation (a Rust lifetime, an
// apostrophe), so it can't hide the rest of the line.
func tokenize(ext, line string) []token {
	var (
		out   []token
		hash  bool
		slash bool
	)
	for _, m := range commentsAt[ext] {
		hash = hash || m == "#"
		slash = slash || m == "//"
	}
	for i := 0; i < len(line); {
		c := line[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			j := i
			for j < len(line) && (line[j] == ' ' || line[j] == '\t' || line[j] == '\r') {
				j++
			}
			out = append(out, token{tokSpace, line[i:j]})
			i = j
		case c == '"' || c == '\'' || c == '`':
			j := i + 1
			for j < len(line) && line[j] != c {
				if line[j] == '\\' && c != '`' {
					j++
				}
				j++
			}
			if j >= len(line) {
				out = append(out, token{tokPunct, line[i : i+1]})
				i++
				continue
			}
			out = append(out, token{tokString, line[i : j+1]})
			i = j + 1
		case (hash && c == '#') || (slash && c == '/' && i+1 < len(line) && line[i+1] == '/'):
			return out
		case identStart(c):
			j := i + 1
			for j < len(line) && (identPart(line[j]) || (line[j] == '.' && j+1 < len(line) && identStart(line[j+1]))) {
				j++
			}
			out = append(out, token{tokIdent, line[i:j]})
			i = j
		default:
			out = append(out, token{tokPunct, line[i : i+1]})
			i++
		}
	}
	return out
}

func isPunct(t token, c byte) bool { return t.kind == tokPunct && t.text[0] == c }

// neighbour returns the nearest token that is not space from i in direction
// step, and its index (-1: none).
func neighbour(toks []token, i, step int) (token, int) {
	for i += step; i >= 0 && i < len(toks); i += step {
		if toks[i].kind != tokSpace {
			return toks[i], i
		}
	}
	return token{}, -1
}

// fold joins string literals the language concatenates: "a" + "b"
// everywhere, 'a' . 'b' in PHP, and "a" "b" side by side in Python and C.
// Line breaks inside what it removes are kept after the joined literal, so
// a later match is still on its own line.
func fold(ext string, toks []token) []token {
	out := make([]token, 0, len(toks))
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.kind != tokString {
			out = append(out, t)
			continue
		}
		breaks := 0
		for {
			next, j := neighbour(toks, i, 1)
			end := -1
			switch {
			case j < 0:
			case isPunct(next, '+') || (phpExt[ext] && isPunct(next, '.')):
				_, end = neighbour(toks, j, 1)
			case next.kind == tokString && (pythonExt[ext] || cExt[ext]):
				end = j
			}
			if end < 0 || toks[end].kind != tokString || toks[end].text[0] != t.text[0] {
				break
			}
			for _, g := range toks[i+1 : end] {
				breaks += strings.Count(g.text, "\n")
			}
			t.text = t.text[:len(t.text)-1] + toks[end].text[1:]
			i = end
		}
		out = append(out, t)
		if breaks > 0 {
			out = append(out, token{tokSpace, strings.Repeat("\n", breaks)})
		}
	}
	return out
}

// statement is one logical line of a file.
type statement struct {
	toks []token // nil for a file that is not code: text is the line itself
	text string
	line int // its first line, from 1
}

func tokensText(toks []token) string {
	var sb strings.Builder
	for _, t := range toks {
		sb.WriteString(t.text)
	}
	return sb.String()
}

// statements cuts a file into statements. Comment lines and lines too long
// to be hand-written are skipped, as before.
func statements(ext string, raw []byte) []statement {
	lines := strings.Split(string(raw), "\n")
	code := codeExt(ext)
	var out []statement
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if len(line) > maxUsageLine || isComment(ext, line) {
			continue
		}
		st := statement{line: i + 1}
		if !code {
			// Scripts and configuration: a trailing backslash continues the
			// line. The whole command is reported where it starts.
			text := strings.TrimRight(line, "\r")
			for n := 1; strings.HasSuffix(text, "\\") && i+1 < len(lines) && n < maxStatementLines && len(lines[i+1]) <= maxUsageLine; n++ {
				i++
				text = strings.TrimSuffix(text, "\\") + " " + strings.TrimSpace(strings.TrimRight(lines[i], "\r"))
			}
			st.text = text
			out = append(out, st)
			continue
		}
		toks := tokenize(ext, line)
		depth := parenDepth(toks)
		for n := 1; i+1 < len(lines) && n < maxStatementLines; n++ {
			next := lines[i+1]
			if len(next) > maxUsageLine {
				break
			}
			if isComment(ext, next) {
				// Inside a statement a comment line is skipped; after one
				// that is complete it ends the statement.
				if depth <= 0 && !endsWithPlus(toks) {
					break
				}
				toks = append(toks, token{tokSpace, "\n"})
				i++
				continue
			}
			nt := tokenize(ext, next)
			if depth <= 0 && !endsWithPlus(toks) && !startsWithPlus(nt) {
				break
			}
			toks = append(append(toks, token{tokSpace, "\n"}), nt...)
			depth += parenDepth(nt)
			i++
		}
		st.toks = fold(ext, toks)
		st.text = tokensText(st.toks)
		out = append(out, st)
	}
	return out
}

func parenDepth(toks []token) int {
	d := 0
	for _, t := range toks {
		if isPunct(t, '(') {
			d++
		} else if isPunct(t, ')') {
			d--
		}
	}
	return d
}

func endsWithPlus(toks []token) bool {
	t, i := neighbour(toks, len(toks), -1)
	if i < 0 || !isPunct(t, '+') {
		return false
	}
	// "i++" ends a statement; "a +" continues one.
	prev, j := neighbour(toks, i, -1)
	return !(j == i-1 && isPunct(prev, '+'))
}

func startsWithPlus(toks []token) bool {
	t, i := neighbour(toks, -1, 1)
	if i < 0 || !isPunct(t, '+') {
		return false
	}
	return !(i+1 < len(toks) && isPunct(toks[i+1], '+'))
}

// constValue is a literal a file assigns to a name.
type constValue struct {
	lit  string // as it is written where the name is read: "DES" or 1024
	line int
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
	reConstGo = regexp.MustCompile(`^\s*(?:const\s+|var\s+)?([A-Za-z_]\w*)(?:\s+[\w.\[\]*]+)?\s*:?=\s*` + constLit + constTail)
	// C: #define NAME value.
	reDefine     = regexp.MustCompile(`^\s*#\s*define\s+([A-Za-z_]\w*)\s+` + constLit + `\s*$`)
	reUpperConst = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
)

// constName is the key a name is kept and looked up by: its last segment,
// without a sigil.
func constName(ident string) string {
	if i := strings.LastIndexByte(ident, '.'); i >= 0 {
		ident = ident[i+1:]
	}
	return strings.TrimLeft(ident, "$@")
}

// constants collects the names a file assigns a string or a key size to. A
// name with more than maxConstValues different values is dropped.
func constants(ext string, sts []statement, raw []byte) map[string][]constValue {
	out := map[string][]constValue{}
	add := func(m []string, line int) {
		if m == nil {
			return
		}
		lit := m[4]
		if lit == "" {
			lit = `"` + m[2] + m[3] + `"`
		}
		name := constName(m[1])
		for _, v := range out[name] {
			if v.lit == lit {
				return
			}
		}
		out[name] = append(out[name], constValue{lit, line})
	}
	re := reConst
	if goExt[ext] {
		re = reConstGo
	}
	for _, st := range sts {
		if st.toks == nil {
			continue
		}
		add(re.FindStringSubmatch(strings.Join(strings.Fields(st.text), " ")), st.line)
	}
	if cExt[ext] {
		// "#" is no comment in C, but a #define is read from the raw line:
		// its value is not an expression.
		for i, line := range strings.Split(string(raw), "\n") {
			if len(line) <= maxUsageLine && strings.Contains(line, "define") {
				add(reDefine.FindStringSubmatch(strings.TrimRight(line, "\r")), i+1)
			}
		}
	}
	for name, vals := range out {
		if len(vals) > maxConstValues {
			delete(out, name)
		}
	}
	return out
}

// readsConstant reports whether the name at toks[i] is read there as a
// value: not called, not assigned to, and written as the file would write
// its own name (bare, this.name, self.name, or an upper-case constant
// behind any qualifier).
func readsConstant(toks []token, i int) bool {
	id := toks[i].text
	name := constName(id)
	if dot := strings.LastIndexByte(id, '.'); dot >= 0 {
		if q := id[:dot]; q != "this" && q != "self" && q != "$this" && !reUpperConst.MatchString(name) {
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
	// A member of something else (obj->name, Type::name) is the file's own
	// only when it is spelled as a constant.
	if prev, k := neighbour(toks, i, -1); k > 0 && ((isPunct(prev, '>') && isPunct(toks[k-1], '-')) || (isPunct(prev, ':') && isPunct(toks[k-1], ':'))) {
		owner, _ := neighbour(toks, k-1, -1)
		if !reUpperConst.MatchString(name) && owner.text != "$this" && owner.text != "self" {
			return false
		}
	}
	return true
}

// usageScan applies the usage rules to a whole file.
func usageScan(ext string, raw []byte) []finding {
	sts := statements(ext, raw)
	consts := constants(ext, sts, raw)
	var out []finding
	for _, st := range sts {
		seen := map[string]bool{}
		lineAt := func(off int) int { return st.line + strings.Count(st.text[:off], "\n") }
		out = append(out, matchUsage(ext, st.text, lineAt, seen, nil)...)
		if len(consts) == 0 {
			continue
		}
		tried := map[string]bool{}
		for i, t := range st.toks {
			name := constName(t.text)
			if t.kind != tokIdent || tried[name] || len(consts[name]) == 0 || !readsConstant(st.toks, i) {
				continue
			}
			tried[name] = true
			for _, v := range consts[name] {
				if v.line == st.line {
					continue // the assignment itself
				}
				var sb strings.Builder
				for k, u := range st.toks {
					if u.kind == tokIdent && constName(u.text) == name && readsConstant(st.toks, k) {
						sb.WriteString(v.lit)
					} else {
						sb.WriteString(u.text)
					}
				}
				variant := sb.String()
				at := func(off int) int { return st.line + strings.Count(variant[:off], "\n") }
				out = append(out, matchUsage(ext, variant, at, seen, map[string]interface{}{"via": name, "assigned_line": v.line})...)
			}
		}
	}
	return out
}

// matchUsage applies the rules to text. lineAt gives the line of an offset
// in it; seen keeps one finding per line and algorithm; extra is recorded
// with each finding.
func matchUsage(ext, text string, lineAt func(int) int, seen map[string]bool, extra map[string]interface{}) []finding {
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
				if alg == "" || seen[key] {
					continue
				}
				seen[key] = true
				meta := map[string]interface{}{"api": r.api}
				for k, v := range extra {
					meta[k] = v
				}
				out = append(out, finding{kind: "crypto_usage", algorithm: alg, name: alg + " · " + r.api, line: n, meta: meta})
			}
		}
	}
	return out
}
