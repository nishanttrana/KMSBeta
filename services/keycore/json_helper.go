package main

import "encoding/json"

// mustMarshalJSON returns the JSON encoding or an empty byte slice on
// error. Used by background workers that emit audit events where a
// marshal error is preferable to crashing — the dead-letter pipeline
// will catch an empty payload and surface it as a defect.
func mustMarshalJSON(v any) []byte {
	out, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return out
}
