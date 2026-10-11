// How a service response body is read. Every body goes through
// parseServiceJSON (tests/unit/zeroTime.test.ts lists the exceptions).

// Go encodes an unset time.Time as year 1. It means "no time": shown as a
// timestamp, or tested for truth, it reads as evidence that something ran.
const GO_ZERO_TIME = "0001-01-01T00:00:00Z";

export function parseServiceJSON<T = unknown>(text: string): T {
  return JSON.parse(text, (_key, value) => (value === GO_ZERO_TIME ? "" : value)) as T;
}
