// +build ignore

// nats-bootstrap.go — Pre-create JetStream streams for local development.
// This ensures all services can publish audit events without stream name conflicts.
package main

import (
	"fmt"
	"os"

	"github.com/nats-io/nats.go"
)

func main() {
	url := os.Getenv("NATS_URL")
	if url == "" {
		url = "nats://localhost:4222"
	}

	nc, err := nats.Connect(url, nats.Name("kms-bootstrap"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "nats connect: %v\n", err)
		os.Exit(1)
	}
	defer nc.Close()

	js, err := nc.JetStream()
	if err != nil {
		fmt.Fprintf(os.Stderr, "jetstream: %v\n", err)
		os.Exit(1)
	}

	// Delete any existing streams that may conflict
	for name := range js.StreamNames() {
		_ = js.DeleteStream(name)
	}

	// Create unified audit stream covering all service audit subjects
	streams := []struct {
		Name     string
		Subjects []string
	}{
		{"AUDIT", []string{"audit.>"}},
		{"CLUSTER_SYNC", []string{"cluster.sync.>"}},
	}

	for _, s := range streams {
		if _, err := js.AddStream(&nats.StreamConfig{
			Name:     s.Name,
			Subjects: s.Subjects,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "create stream %s: %v\n", s.Name, err)
		}
	}
}
