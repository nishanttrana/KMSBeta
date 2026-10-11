package main

import (
	"strings"
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
// It stays deterministic: strings and comments are told apart by a
// tokeniser, not by evaluating code. What a name can stand for, in this
// file and across the files of a scan, is in usage_resolve.go and
// usage_unit.go. A name assigned more than maxConstValues different values
// is a variable, not a constant, and is not resolved.

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
