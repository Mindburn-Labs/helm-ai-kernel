# Mindburn API key environment

For `helm mcp serve --auth static-header`, supply the credential through
`MINDBURN_HELM_API_KEY`. It takes precedence when both names are set.

`HELM_API_KEY` remains a deprecated fallback for existing deployments. Using
the fallback writes one warning when the authentication handler is created;
the warning never contains the credential. An absent credential still refuses
startup. HTTP authentication headers are unchanged.

The Go, Python and TypeScript SDK constructors accept an explicit credential;
they do not acquire one from the environment automatically. Resolve the
Mindburn-specific environment variable in the calling application and pass it
to the constructor. Keep credentials in the environment or an appropriate
secret store, never in source, command arguments or receipts.
