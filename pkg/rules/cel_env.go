package rules

import (
	"github.com/google/cel-go/cel"
)

// buildEnv constructs the CEL environment with xhelix-specific
// variable declarations.
//
// We use map<string, dyn> for event/parent/etc. so rule authors can
// access fields by name without us declaring a strongly-typed Go
// struct binding. The downside is no compile-time type checking on
// nested fields; we accept that for v0.1 simplicity.
func buildEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("event", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("parent", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("tree", cel.ListType(cel.MapType(cel.StringType, cel.DynType))),
		cel.Variable("path", cel.StringType),
		cel.Variable("host", cel.StringType),
	)
}
