package keyaccess

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	// Profile is the compose profile (deployment.yaml feature) that deploys
	// the key access justifications service.
	Profile = "key_access_justifications"
	// ProfilesEnv carries the deployment's compose profiles into a service.
	// docker-compose.yml sets it from COMPOSE_PROFILES, which every installer
	// derives from infra/deployment/deployment.yaml.
	ProfilesEnv = "VECTA_DEPLOYED_PROFILES"

	// ReasonNotDeployed is the decision reason when the deployment leaves the
	// service out: the operation runs without a justification check.
	ReasonNotDeployed = "key_access_not_deployed"
	// ReasonUnavailable is the refusal reason when the service is deployed
	// (or its deployment is unknown) and gives no decision.
	ReasonUnavailable = "key_access_unavailable"
)

// ErrUnavailable means key access is deployed but gave no decision; the
// caller refuses the operation (424 key_access_unavailable).
var ErrUnavailable = errors.New("key access justification service is unavailable")

// Gate is the one key access decision for ekm, cloud and hyok. The zero
// value fails closed: deployed, with no client, so every evaluation refuses.
type Gate struct {
	client      Client
	notDeployed bool
}

// Deployed returns a gate that asks client for every decision.
func Deployed(client Client) Gate { return Gate{client: client} }

// NotDeployed returns a gate for a deployment without the service: every
// operation is allowed with reason key_access_not_deployed.
func NotDeployed() Gate { return Gate{notDeployed: true} }

// GateFromEnv builds the gate from VECTA_DEPLOYED_PROFILES and KEY_ACCESS_URL.
// Only a known profile list without key_access_justifications means "not
// deployed"; an unset or empty list is unknown and fails closed.
func GateFromEnv(timeout time.Duration) Gate {
	if !deployedIn(os.Getenv(ProfilesEnv)) {
		return NotDeployed()
	}
	return Deployed(NewHTTPClient(os.Getenv("KEY_ACCESS_URL"), timeout))
}

func deployedIn(profiles string) bool {
	if strings.TrimSpace(profiles) == "" {
		return true
	}
	for _, p := range strings.Split(profiles, ",") {
		if strings.TrimSpace(p) == Profile {
			return true
		}
	}
	return false
}

// IsDeployed reports whether evaluations go to the key access service.
func (g Gate) IsDeployed() bool { return !g.notDeployed }

// Evaluate returns the service's decision, the not-deployed allow, or an
// error wrapping ErrUnavailable. It never turns a failure into an allow.
func (g Gate) Evaluate(ctx context.Context, req EvaluateRequest) (EvaluateResponse, error) {
	if g.notDeployed {
		return EvaluateResponse{Action: "allow", Reason: ReasonNotDeployed}, nil
	}
	if g.client == nil {
		return EvaluateResponse{}, fmt.Errorf("%w: no client configured", ErrUnavailable)
	}
	out, err := g.client.Evaluate(ctx, req)
	if err != nil {
		return EvaluateResponse{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if strings.TrimSpace(out.Action) == "" {
		return EvaluateResponse{}, fmt.Errorf("%w: decision has no action", ErrUnavailable)
	}
	return out, nil
}
