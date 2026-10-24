package main

import (
	"encoding/json"
	"testing"
	"time"
)

// A day's renewals can come from several CAs. The schedule entry named only
// the first certificate's CA, so a day of 30 certificates from two CAs read
// as 30 for one of them (13.62.0-beta). Each CA is now listed with its share.
func TestRenewalScheduleListsEveryCAOfADay(t *testing.T) {
	day := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	item := func(cert, caID, caName, bucket string) CertRenewalInfo {
		return CertRenewalInfo{CertID: cert, CAID: caID, CAName: caName, MassRenewalBucket: bucket, RiskLevel: "low",
			WindowStart: day, WindowEnd: day.Add(time.Hour), ScheduledRenewalAt: day}
	}
	summary := buildCertRenewalSummary("t1", []CertRenewalInfo{
		item("c1", "ca_a", "issuing-a", "2026-10-29"),
		item("c2", "ca_b", "issuing-b", "2026-10-29"),
		item("c3", "ca_b", "issuing-b", "2026-10-29"),
		item("c4", "ca_a", "issuing-a", "2026-11-02"),
	}, ACMEProtocolOptions{}) // every window starts at the same time: the day breaks the tie

	if len(summary.CADirectedSchedule) != 2 {
		t.Fatalf("want one entry per day, got %d", len(summary.CADirectedSchedule))
	}
	first := summary.CADirectedSchedule[0]
	if first.Bucket != "2026-10-29" || first.Count != 3 {
		t.Fatalf("first day = %s with %d, want 2026-10-29 with 3", first.Bucket, first.Count)
	}
	want := []CertRenewalScheduleCA{{CAID: "ca_b", CAName: "issuing-b", Count: 2}, {CAID: "ca_a", CAName: "issuing-a", Count: 1}}
	if len(first.CAs) != len(want) || first.CAs[0] != want[0] || first.CAs[1] != want[1] {
		t.Fatalf("CAs = %+v, want %+v", first.CAs, want)
	}
	sum := 0
	for _, ca := range first.CAs {
		sum += ca.Count
	}
	if sum != first.Count {
		t.Fatalf("CA shares add to %d, entry counts %d", sum, first.Count)
	}

	// ca_id and ca_name name a CA only when it is the day's only CA.
	if first.CAID != "" || first.CAName != "" {
		t.Fatalf("a day of two CAs names %q/%q", first.CAID, first.CAName)
	}
	second := summary.CADirectedSchedule[1]
	if second.CAID != "ca_a" || second.CAName != "issuing-a" {
		t.Fatalf("a day of one CA names %q/%q, want ca_a/issuing-a", second.CAID, second.CAName)
	}
	raw, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["cas"]) == "" || string(fields["ca_name"]) != `""` {
		t.Fatalf("entry JSON = %s", raw)
	}
}
