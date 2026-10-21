package clustercatalog

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var createTableRE = regexp.MustCompile(`(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(%[Is]|[a-z0-9_]+)`)

// Tables in SQL that targets customer-owned external databases (dataprotect
// external token vault providers), not the KMS database.
var externalSchemaTables = map[string]bool{"dbo": true, "token_vault_records": true}

func repoTables(t *testing.T) map[string]string {
	t.Helper()
	root := filepath.Join("..", "..", "services")
	found := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		isSQL := strings.HasSuffix(path, ".sql") && strings.Contains(path, string(filepath.Separator)+"migrations"+string(filepath.Separator))
		isGo := strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go")
		if !isSQL && !isGo {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range createTableRE.FindAllStringSubmatch(string(raw), -1) {
			name := strings.ToLower(m[1])
			if name == "%i" || name == "%s" || externalSchemaTables[name] {
				continue // partition templates are published via their root table
			}
			if _, seen := found[name]; !seen {
				found[name] = path
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// Every table a service creates is classified, so a new table cannot silently
// be replicated or silently be left out of a cluster.
func TestEveryTableIsClassified(t *testing.T) {
	for table, path := range repoTables(t) {
		if class, _ := Classify(table); class == ClassUnknown {
			t.Errorf("table %s (%s) is not classified in pkg/clustercatalog: add it to Replicated, NodeLocal or SharedAppend", table, path)
		}
	}
}

func TestCatalogHasNoStaleOrDuplicateEntries(t *testing.T) {
	existing := repoTables(t)
	seen := map[string]string{}
	check := func(table, where string) {
		if prev, dup := seen[table]; dup {
			t.Errorf("table %s is classified twice (%s and %s)", table, prev, where)
		}
		seen[table] = where
		if _, ok := existing[table]; !ok {
			t.Errorf("catalogue entry %s (%s) matches no table in the repo", table, where)
		}
	}
	for c, ts := range Replicated {
		for _, tbl := range ts {
			check(tbl, "Replicated["+c+"]")
		}
	}
	for tbl := range NodeLocal {
		check(tbl, "NodeLocal")
	}
	for tbl := range SharedAppend {
		check(tbl, "SharedAppend")
	}
}

func TestCoreComponentsAlwaysIncluded(t *testing.T) {
	got := strings.Join(WithCore([]string{"dataprotect", "keycore"}), ",")
	if got != "auth,dataprotect,governance,keycore,policy" {
		t.Fatalf("WithCore = %s", got)
	}
	if class, _ := Classify("auth_sessions"); class != ClassNodeLocal {
		t.Fatal("sessions must stay node-local")
	}
	if class, comp := Classify("keys"); class != ClassReplicated || comp != "keycore" {
		t.Fatalf("keys must replicate with keycore, got %s %s", class, comp)
	}
	if SubscriptionName("node-2", "byok") != "vecta_sub_node_2_byok" || PublicationName("byok") != "vecta_pub_byok" {
		t.Fatal("unexpected publication/subscription naming")
	}
}

// createWithBodyRE captures a CREATE TABLE statement up to the end of its
// column list.
var createWithBodyRE = regexp.MustCompile(`(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z0-9_]+)\s*\((.*?)\)\s*;`)
var sequenceRE = regexp.MustCompile(`(?i)\b[a-z_][a-z0-9_]*\s+(BIG|SMALL)?SERIAL\b|\bGENERATED\s+(ALWAYS|BY\s+DEFAULT)\s+AS\s+IDENTITY\b|\bnextval\s*\(`)

// Logical replication does not carry sequences, so after a failover the new
// primary's would restart below the IDs it already holds and reuse them. A
// replicated table takes its IDs from the application instead.
func TestReplicatedTablesUseNoSequence(t *testing.T) {
	root := filepath.Join("..", "..", "services")
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".sql") || !strings.Contains(path, string(filepath.Separator)+"migrations"+string(filepath.Separator)) {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range createWithBodyRE.FindAllStringSubmatch(string(raw), -1) {
			if class, _ := Classify(m[1]); class == ClassReplicated && sequenceRE.MatchString(m[2]) {
				t.Errorf("replicated table %s (%s) takes IDs from a sequence", m[1], path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The check sees a sequence where there is one.
	if !sequenceRE.MatchString("id BIGSERIAL PRIMARY KEY") || !sequenceRE.MatchString("id BIGINT GENERATED ALWAYS AS IDENTITY") {
		t.Fatal("sequence pattern misses a sequence")
	}
	if sequenceRE.MatchString("fingerprint TEXT NOT NULL DEFAULT '',\n    serial TEXT NOT NULL") {
		t.Fatal("a column named serial is not a sequence")
	}
}
