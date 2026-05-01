package policycel

import (
	"regexp"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
)

var taintContainsOneArg = regexp.MustCompile(`\btaint_contains\(\s*"([^"\\]*(?:\\.[^"\\]*)*)"\s*\)`)

func TaintEnvOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Variable("taint", cel.ListType(cel.StringType)),
		cel.Function("taint_contains",
			cel.Overload("taint_contains_dyn_string",
				[]*cel.Type{cel.DynType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(taintContainsBinding),
			),
		),
	}
}

func RewritePRGTaintContains(expression string) string {
	return taintContainsOneArg.ReplaceAllString(expression, `taint_contains(input.taint, "$1")`)
}

func RewritePolicyPackTaintContains(expression string) string {
	return taintContainsOneArg.ReplaceAllString(expression, `taint_contains(taint, "$1")`)
}

func taintContainsBinding(lhs, rhs ref.Val) ref.Val {
	container, ok := lhs.(traits.Container)
	if !ok {
		return types.False
	}
	return container.Contains(rhs)
}
