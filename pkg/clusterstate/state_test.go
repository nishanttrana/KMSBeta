package clusterstate

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync/atomic"
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

func TestChainNode(t *testing.T) {
	for _, c := range []struct {
		st   State
		want string
	}{
		{State{}, ""},
		{State{NodeID: "n1"}, ""}, // standalone: nothing replicates
		{State{NodeID: "n1", Role: RolePrimary}, "n1"},
		{State{NodeID: "n2", Role: RoleFollower}, "n2"},
	} {
		if got := c.st.ChainNode(); got != c.want {
			t.Fatalf("%+v: chain node %q, want %q", c.st, got, c.want)
		}
	}
}

// Until the database is attached (the process has no mTLS identity yet), a
// node must not run primary-only jobs: it may be a member.
func TestPendingReaderHoldsPrimaryJobs(t *testing.T) {
	r := NewPendingReader()
	SetDefault(r)
	defer SetDefault(nil)
	if RunsPrimaryJobs(context.Background()) {
		t.Fatal("primary jobs must wait while the role is unknown")
	}
	r.Attach(nil)
	if !RunsPrimaryJobs(context.Background()) {
		t.Fatal("once attached, a node without cluster state runs primary jobs")
	}
}

// countingDriver fails every query and counts them.
type countingDriver struct{ queries *atomic.Int64 }

func (d countingDriver) Open(string) (driver.Conn, error) { return countingConn(d), nil }

type countingConn countingDriver

func (c countingConn) Prepare(string) (driver.Stmt, error) {
	c.queries.Add(1)
	return nil, errors.New(`relation "cluster_local_state" does not exist`)
}
func (countingConn) Close() error              { return nil }
func (countingConn) Begin() (driver.Tx, error) { return nil, errors.New("no transactions") }

// A node without the table (no cluster manager deployed) is standalone, and
// the failed lookup is cached: every service asked Postgres on every call,
// thousands of failed queries an hour on an idle node.
func TestMissingTableIsCachedAsStandalone(t *testing.T) {
	var queries atomic.Int64
	sql.Register("clusterstate-missing-table", countingDriver{&queries})
	db, err := sql.Open("clusterstate-missing-table", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck
	r := NewReader(db)
	for i := 0; i < 50; i++ {
		if r.Get(context.Background()).IsMember() {
			t.Fatal("a node without the table was treated as a member")
		}
	}
	if n := queries.Load(); n != 1 {
		t.Fatalf("%d queries for 50 lookups inside the TTL, want 1", n)
	}
}
