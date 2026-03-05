package main

import "testing"

func TestExpressionSimpleEqual(t *testing.T) {
	fields := map[string]string{"action": "key.exported", "severity": "high", "actor_id": "admin"}
	ok, err := EvaluateExpression(`action == "key.exported"`, fields)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected true for action == key.exported")
	}
}

func TestExpressionNotEqual(t *testing.T) {
	fields := map[string]string{"action": "key.exported", "actor_id": "admin"}
	ok, err := EvaluateExpression(`actor_id != "system"`, fields)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected true for actor_id != system")
	}
}

func TestExpressionContains(t *testing.T) {
	fields := map[string]string{"source_ip": "10.0.1.42"}
	ok, err := EvaluateExpression(`source_ip contains "10.0"`, fields)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected true")
	}
}

func TestExpressionStartsWith(t *testing.T) {
	fields := map[string]string{"action": "key.exported"}
	ok, err := EvaluateExpression(`action startsWith "key."`, fields)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected true")
	}
}

func TestExpressionMatches(t *testing.T) {
	fields := map[string]string{"action": "key.exported"}
	ok, err := EvaluateExpression(`action matches "key.*"`, fields)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected true for glob match")
	}
}

func TestExpressionAnd(t *testing.T) {
	fields := map[string]string{"action": "key.exported", "severity": "critical"}
	ok, err := EvaluateExpression(`action == "key.exported" AND severity == "critical"`, fields)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected true for AND")
	}
}

func TestExpressionAndFalse(t *testing.T) {
	fields := map[string]string{"action": "key.exported", "severity": "info"}
	ok, err := EvaluateExpression(`action == "key.exported" AND severity == "critical"`, fields)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected false for AND with mismatched severity")
	}
}

func TestExpressionOr(t *testing.T) {
	fields := map[string]string{"action": "cert.revoked"}
	ok, err := EvaluateExpression(`action == "key.exported" OR action == "cert.revoked"`, fields)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected true for OR")
	}
}

func TestExpressionParentheses(t *testing.T) {
	fields := map[string]string{"action": "key.destroyed", "severity": "critical"}
	ok, err := EvaluateExpression(`(action == "key.exported" OR action == "key.destroyed") AND severity != "info"`, fields)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected true for grouped OR + AND")
	}
}

func TestExpressionInvalidField(t *testing.T) {
	_, err := EvaluateExpression(`unknown_field == "value"`, nil)
	if err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestExpressionInvalidOperator(t *testing.T) {
	_, err := EvaluateExpression(`action >= "value"`, nil)
	if err == nil {
		t.Fatal("expected error for invalid operator")
	}
}

func TestExpressionEmpty(t *testing.T) {
	ok, err := EvaluateExpression("", nil)
	if err != nil {
		t.Fatalf("unexpected error for empty: %v", err)
	}
	if ok {
		t.Fatal("expected false for empty expression")
	}
}

func TestExpressionMissingValue(t *testing.T) {
	_, err := EvaluateExpression(`action ==`, nil)
	if err == nil {
		t.Fatal("expected error for missing value")
	}
}

func TestValidateExpressionValid(t *testing.T) {
	err := ValidateExpression(`action matches "key.*" AND severity != "info"`)
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestValidateExpressionInvalid(t *testing.T) {
	err := ValidateExpression(`badfield == "x"`)
	if err == nil {
		t.Fatal("expected validation error for bad field")
	}
}

func TestValidateExpressionEmptyOk(t *testing.T) {
	err := ValidateExpression("")
	if err != nil {
		t.Fatalf("empty expression should validate: %v", err)
	}
}

func TestExpressionCaseInsensitive(t *testing.T) {
	fields := map[string]string{"action": "KEY.EXPORTED"}
	ok, err := EvaluateExpression(`action == "key.exported"`, fields)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected case-insensitive match")
	}
}
