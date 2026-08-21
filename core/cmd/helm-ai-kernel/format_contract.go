package main

import (
	"io"
	"strings"

	cliui "github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
)

// operatorFormatCollision names catalog commands whose --format is a domain
// flag, not the output selector. Dispatch must not consume --format there.
var operatorFormatCollision = map[string]string{
	"verify": "leaf --format is a receipt format id on decision-receipt",
	"import": "leaf --format is an import format id",
	"skills": "leaf --format selects codex-skill vs codex-plugin",
}

// operatorFormatDocumentExempt names commands that accept the catalog
// --format contract (unknown values fail closed) but are not required to
// emit a JSON operator document. Reasons stay on HELM-429.
var operatorFormatDocumentExempt = map[string]string{
	"tui":         "TUI-only; no operator data stream",
	"completion":  "emits a shell script, not text|json operator data",
	"server":      "listener; bind is not an inspect document",
	"serve":       "listener; bind is not an inspect document",
	"proxy":       "listener; bind is not an inspect document",
	"spend-proxy": "listener; bind is not an inspect document",
	"dev":         "listener; bind is not an inspect document",
	"connect":     "listener; bind is not an inspect document",
	"login":       "listener; bind is not an inspect document",
	"up":          "listener; bind is not an inspect document",
	"onboard":     "listener unless --dry-run; TUI refuses binds",
	"quickstart":  "listener unless --dry-run; TUI refuses binds",
}

// operatorFormatPassthrough keeps --format in argv. These commands register
// --format themselves (or own a text|json format string). Stripping it
// breaks plan compile's JSON-only refusal and RequestedFormat last-wins.
var operatorFormatPassthrough = map[string]string{
	"plan":         "RegisterFormat default JSON; --format=text must remain to refuse",
	"doctor":       "RegisterFormat + RequestedFormat",
	"freeze":       "RegisterFormat + RequestedFormat",
	"unfreeze":     "RegisterFormat + RequestedFormat",
	"incident":     "RegisterFormat + RequestedFormat",
	"brief":        "RegisterFormat + RequestedFormat",
	"receipts":     "RegisterFormat + RequestedFormat",
	"risk-summary": "RegisterFormat + RequestedFormat",
	"setup":        "RegisterFormat + RequestedFormat",
	"trust":        "RegisterFormat + RequestedFormat",
	"report":       "owns --format text|json as a native string flag",
}

func catalogFormatContract(name string) string {
	if _, ok := operatorFormatCollision[name]; ok {
		return "collision"
	}
	if _, ok := operatorFormatDocumentExempt[name]; ok {
		return "exempt"
	}
	return "text|json"
}

func operatorJSONRequested(args []string) bool {
	_, jsonOut, err := cliui.ConsumeOperatorFormat(args)
	return err == nil && jsonOut
}

func versionOnlyFormatArgs(args []string) bool {
	for _, arg := range args {
		if arg == "--json" || arg == "--format" || strings.HasPrefix(arg, "--json=") || strings.HasPrefix(arg, "--format=") {
			continue
		}
		if arg == "text" || arg == "json" {
			continue
		}
		return false
	}
	return len(args) > 0
}

// relocateLeadingOperatorFormat moves a leading run of output-format flags
// that sits immediately before the first positional subcommand to just after
// that subcommand. `receipts --format=json status` becomes
// `receipts status --format=json`. Flag-only argv is left untouched so value
// positions like `--effect --format=text` keep their historical scan rules.
func relocateLeadingOperatorFormat(args []string) []string {
	if len(args) == 0 {
		return args
	}
	var leading []string
	i := 0
	for i < len(args) {
		arg := args[i]
		if arg == "--" {
			return args
		}
		if arg == "--format" {
			leading = append(leading, arg)
			if i+1 < len(args) {
				i++
				leading = append(leading, args[i])
			}
			i++
			continue
		}
		if strings.HasPrefix(arg, "--format=") || arg == "--json" || strings.HasPrefix(arg, "--json=") {
			leading = append(leading, arg)
			i++
			continue
		}
		break
	}
	if len(leading) == 0 || i >= len(args) || strings.HasPrefix(args[i], "-") {
		return args
	}
	out := make([]string, 0, len(args))
	out = append(out, args[i])
	out = append(out, leading...)
	out = append(out, args[i+1:]...)
	return out
}

func rejectUnknownFormatTokens(args []string) error {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		lower := strings.ToLower(arg)
		switch {
		case lower == "--format":
			if i+1 >= len(args) {
				_, err := cliui.ParseFormat("")
				return err
			}
			i++
			if _, err := cliui.ParseFormat(args[i]); err != nil {
				return err
			}
		case strings.HasPrefix(lower, "--format="):
			eq := strings.Index(arg, "=")
			if _, err := cliui.ParseFormat(arg[eq+1:]); err != nil {
				return err
			}
		}
	}
	return nil
}

func applyOperatorFormat(name string, args []string, stderr io.Writer) ([]string, int, bool) {
	if _, ok := operatorFormatCollision[name]; ok {
		return args, 0, true
	}
	if err := rejectUnknownFormatTokens(args); err != nil {
		return nil, cliui.WriteError(stderr, cliui.UsageErrorf(name, "%s", err.Error())), false
	}
	args = relocateLeadingOperatorFormat(args)
	rest, jsonOut, err := cliui.ConsumeOperatorFormat(args)
	if err != nil {
		return nil, cliui.WriteError(stderr, cliui.UsageErrorf(name, "%s", err.Error())), false
	}
	if _, ok := operatorFormatPassthrough[name]; ok {
		return args, 0, true
	}
	return cliui.WithJSONAlias(rest, jsonOut), 0, true
}
