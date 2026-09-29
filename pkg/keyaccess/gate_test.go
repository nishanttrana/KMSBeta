package keyaccess

import (
	"context"
	"errors"
	"testing"
)

type stubClient struct {
	out EvaluateResponse
	err error
}

func (s stubClient) Evaluate(context.Context, EvaluateRequest) (EvaluateResponse, error) {
	return s.out, s.err
}

func TestGateFromEnvDeployment(t *testing.T) {
	cases := []struct {
		profiles string
		deployed bool
	}{
		{"", true}, // unknown fails closed
		{"   ", true},
		{"secrets,key_access_justifications,event_streaming", true},
		{"secrets, key_access_justifications", true},
		{"secrets,ekm_database,event_streaming", false},
		{"key_access_justifications_extra", false},
	}
	for _, c := range cases {
		t.Setenv(ProfilesEnv, c.profiles)
		if got := GateFromEnv(0).IsDeployed(); got != c.deployed {
			t.Fatalf("profiles %q: deployed=%v, want %v", c.profiles, got, c.deployed)
		}
	}
}

func TestGateNeverAllowsOnFailure(t *testing.T) {
	ctx := context.Background()
	for name, g := range map[string]Gate{
		"zero value":   {},
		"client error": Deployed(stubClient{err: errors.New("dial tcp: connection refused")}),
		"empty action": Deployed(stubClient{}),
	} {
		out, err := g.Evaluate(ctx, EvaluateRequest{})
		if !errors.Is(err, ErrUnavailable) || out.Action != "" {
			t.Fatalf("%s: %+v %v, want ErrUnavailable and no decision", name, out, err)
		}
	}
	out, err := NotDeployed().Evaluate(ctx, EvaluateRequest{})
	if err != nil || out.Action != "allow" || out.Reason != ReasonNotDeployed {
		t.Fatalf("not deployed: %+v %v", out, err)
	}
	out, err = Deployed(stubClient{out: EvaluateResponse{Action: "deny", Reason: "no code"}}).Evaluate(ctx, EvaluateRequest{})
	if err != nil || out.Action != "deny" {
		t.Fatalf("deployed decision not passed through: %+v %v", out, err)
	}
}
