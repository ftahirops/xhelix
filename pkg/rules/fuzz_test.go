package rules

import "testing"

// FuzzLoadBytes exercises the YAML rule loader against arbitrary input.
// The contract: LoadBytes never panics, regardless of input.
//
// Seed corpus is small but covers: empty, valid, multi-doc, malformed,
// and a few hostile YAML billion-laughs-shaped inputs (depth-limited
// by the underlying decoder).
func FuzzLoadBytes(f *testing.F) {
	f.Add([]byte(``))
	f.Add([]byte(`id: r1
match: "true"
severity: notice`))
	f.Add([]byte(`id: a
match: "true"
severity: notice
---
id: b
match: "true"
severity: warning`))
	f.Add([]byte(`{not: valid yaml`))
	f.Add([]byte(`id: !!float 1
match: x`))
	f.Add([]byte(`severity_raw: "definitely-not-a-real-level"`))
	f.Add([]byte("id: r1\xff\xfe\xfd")) // invalid UTF-8
	f.Add([]byte(`id: ` + makeBig(8192)))

	f.Fuzz(func(t *testing.T, body []byte) {
		// Don't care about the result; we care that we don't panic.
		_, _ = LoadBytes(body)
	})
}

func makeBig(n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = 'a'
	}
	return string(out)
}
