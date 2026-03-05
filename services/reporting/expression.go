package main

import (
	"fmt"
	"strings"
	"unicode"
)

// ExprNode represents a node in the parsed expression tree.
type ExprNode interface {
	Evaluate(fields map[string]string) bool
}

type comparisonNode struct {
	field    string
	operator string
	value    string
}

func (n *comparisonNode) Evaluate(fields map[string]string) bool {
	fieldVal := strings.ToLower(strings.TrimSpace(fields[n.field]))
	val := strings.ToLower(strings.TrimSpace(n.value))
	switch n.operator {
	case "==":
		return fieldVal == val
	case "!=":
		return fieldVal != val
	case "contains":
		return strings.Contains(fieldVal, val)
	case "startswith":
		return strings.HasPrefix(fieldVal, val)
	case "matches":
		return matchPattern(fieldVal, val)
	default:
		return false
	}
}

type andNode struct {
	left, right ExprNode
}

func (n *andNode) Evaluate(fields map[string]string) bool {
	return n.left.Evaluate(fields) && n.right.Evaluate(fields)
}

type orNode struct {
	left, right ExprNode
}

func (n *orNode) Evaluate(fields map[string]string) bool {
	return n.left.Evaluate(fields) || n.right.Evaluate(fields)
}

// Allowed fields for expression matching
var allowedFields = map[string]bool{
	"action":      true,
	"severity":    true,
	"actor_id":    true,
	"source_ip":   true,
	"service":     true,
	"target_type": true,
	"target_id":   true,
}

// Allowed operators
var allowedOperators = map[string]bool{
	"==":         true,
	"!=":         true,
	"contains":   true,
	"startswith": true,
	"matches":    true,
}

// tokenize splits an expression string into tokens, respecting quoted strings.
func tokenize(expr string) []string {
	var tokens []string
	expr = strings.TrimSpace(expr)
	i := 0
	for i < len(expr) {
		// Skip whitespace
		if unicode.IsSpace(rune(expr[i])) {
			i++
			continue
		}
		// Quoted string
		if expr[i] == '"' {
			j := i + 1
			for j < len(expr) && expr[j] != '"' {
				if expr[j] == '\\' && j+1 < len(expr) {
					j++ // skip escaped char
				}
				j++
			}
			if j < len(expr) {
				j++ // include closing quote
			}
			tokens = append(tokens, expr[i:j])
			i = j
			continue
		}
		// Parentheses
		if expr[i] == '(' || expr[i] == ')' {
			tokens = append(tokens, string(expr[i]))
			i++
			continue
		}
		// Two-char operators: ==, !=
		if i+1 < len(expr) && (expr[i:i+2] == "==" || expr[i:i+2] == "!=") {
			tokens = append(tokens, expr[i:i+2])
			i += 2
			continue
		}
		// Word token (field name, operator name, AND, OR)
		j := i
		for j < len(expr) && !unicode.IsSpace(rune(expr[j])) && expr[j] != '(' && expr[j] != ')' && expr[j] != '"' && expr[j] != '=' && expr[j] != '!' {
			j++
		}
		if j > i {
			tokens = append(tokens, expr[i:j])
			i = j
			continue
		}
		// Single unknown character — skip
		i++
	}
	return tokens
}

type parser struct {
	tokens []string
	pos    int
}

func (p *parser) peek() string {
	if p.pos >= len(p.tokens) {
		return ""
	}
	return p.tokens[p.pos]
}

func (p *parser) next() string {
	t := p.peek()
	if t != "" {
		p.pos++
	}
	return t
}

func (p *parser) parseOr() (ExprNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "OR") {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &orNode{left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseAnd() (ExprNode, error) {
	left, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "AND") {
		p.next()
		right, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		left = &andNode{left: left, right: right}
	}
	return left, nil
}

func (p *parser) parsePrimary() (ExprNode, error) {
	if p.peek() == "(" {
		p.next() // consume "("
		node, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("expected ')' at position %d", p.pos)
		}
		p.next() // consume ")"
		return node, nil
	}
	return p.parseComparison()
}

func (p *parser) parseComparison() (ExprNode, error) {
	field := strings.ToLower(strings.TrimSpace(p.next()))
	if field == "" {
		return nil, fmt.Errorf("expected field name at position %d", p.pos)
	}
	if !allowedFields[field] {
		return nil, fmt.Errorf("unknown field %q (allowed: action, severity, actor_id, source_ip, service, target_type, target_id)", field)
	}
	op := strings.ToLower(strings.TrimSpace(p.next()))
	if op == "" {
		return nil, fmt.Errorf("expected operator after field %q at position %d", field, p.pos)
	}
	if !allowedOperators[op] {
		return nil, fmt.Errorf("unknown operator %q (allowed: ==, !=, matches, contains, startsWith)", op)
	}
	valToken := p.next()
	if valToken == "" {
		return nil, fmt.Errorf("expected value after operator %q at position %d", op, p.pos)
	}
	// Strip quotes from value
	val := valToken
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		val = val[1 : len(val)-1]
		// Unescape
		val = strings.ReplaceAll(val, `\"`, `"`)
		val = strings.ReplaceAll(val, `\\`, `\`)
	}
	return &comparisonNode{field: field, operator: op, value: val}, nil
}

// ParseExpression parses an expression string into an evaluatable tree.
func ParseExpression(expr string) (ExprNode, error) {
	trimmed := strings.TrimSpace(expr)
	if trimmed == "" {
		return nil, fmt.Errorf("empty expression")
	}
	tokens := tokenize(trimmed)
	if len(tokens) == 0 {
		return nil, fmt.Errorf("empty expression")
	}
	p := &parser{tokens: tokens, pos: 0}
	node, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.tokens) {
		return nil, fmt.Errorf("unexpected token %q at position %d", p.tokens[p.pos], p.pos)
	}
	return node, nil
}

// ValidateExpression checks if an expression string is syntactically valid.
// An empty expression is valid (treated as no-op).
func ValidateExpression(expr string) error {
	if strings.TrimSpace(expr) == "" {
		return nil
	}
	_, err := ParseExpression(expr)
	return err
}

// EvaluateExpression parses and evaluates an expression against event fields.
// An empty expression returns false.
func EvaluateExpression(expr string, fields map[string]string) (bool, error) {
	if strings.TrimSpace(expr) == "" {
		return false, nil
	}
	node, err := ParseExpression(expr)
	if err != nil {
		return false, err
	}
	return node.Evaluate(fields), nil
}
