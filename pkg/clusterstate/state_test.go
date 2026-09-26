package clusterstate

import (
	"context"
	"testing"
)

func TestMemberDetectionAndPrimaryJobs(t *testing.T) {
	ctx := context.Background()
	t.Cleanup(func() { SetDefault(nil) })

	SetDefault(nil)
	if Default().Get(ctx).IsMember() || !RunsPrimaryJobs(ctx) {
		t.Fatal("a node without cluster state is standalone and runs primary jobs")
	}
	// A follower row without a primary URL or credential cannot forward, so it
	// is not treated as a member.
	SetDefault(Static(State{Role: RoleFollower}))
	if Default().Get(ctx).IsMember() {
		t.Fatal("an incomplete follower state must not count as a member")
	}
	SetDefault(Static(State{Role: RoleFollower, PrimaryURL: "https://p:8210", ForwardCredential: "c"}))
	if !Default().Get(ctx).IsMember() || RunsPrimaryJobs(ctx) {
		t.Fatal("a member must forward writes and must not run primary jobs")
	}
}
