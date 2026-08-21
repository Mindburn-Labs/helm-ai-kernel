package ui

import (
	"fmt"
	"strings"
)

// ConsumeOperatorFormat peels catalog --format text|json (and notes --json)
// from argv so Dispatch can enforce the output-format contract before a
// command starts work. Domain --format flags (receipt format ids, skill
// types) must not call this.
//
// --format=json is reported via jsonOut so the caller can inject the legacy
// --json alias. --json tokens are left in rest for the command's own parser.
func ConsumeOperatorFormat(args []string) (rest []string, jsonOut bool, err error) {
	rest = make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			rest = append(rest, args[i:]...)
			break
		}
		lower := strings.ToLower(arg)
		switch {
		case lower == "--json":
			jsonOut = true
			rest = append(rest, arg)
		case strings.HasPrefix(lower, "--json="):
			if v, perr := parseBoolToken(arg[len("--json="):]); perr == nil && v {
				jsonOut = true
			}
			rest = append(rest, arg)
		case lower == "--format":
			if i+1 >= len(args) {
				return nil, false, fmt.Errorf("invalid --format %q: expected text|json", "")
			}
			i++
			format, ferr := ParseFormat(args[i])
			if ferr != nil {
				return nil, false, ferr
			}
			if format.IsJSON() {
				jsonOut = true
			}
		case strings.HasPrefix(lower, "--format="):
			eq := strings.Index(arg, "=")
			format, ferr := ParseFormat(arg[eq+1:])
			if ferr != nil {
				return nil, false, ferr
			}
			if format.IsJSON() {
				jsonOut = true
			}
		default:
			rest = append(rest, arg)
		}
	}
	return rest, jsonOut, nil
}

func parseBoolToken(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "t", "true", "yes":
		return true, nil
	case "0", "f", "false", "no":
		return false, nil
	default:
		return false, fmt.Errorf("invalid bool %q", s)
	}
}

// WithJSONAlias appends --json when jsonOut is set and the flag is absent.
func WithJSONAlias(args []string, jsonOut bool) []string {
	if !jsonOut {
		return args
	}
	for _, arg := range args {
		if arg == "--json" || strings.HasPrefix(arg, "--json=") {
			return args
		}
	}
	return append(append([]string{}, args...), "--json")
}
