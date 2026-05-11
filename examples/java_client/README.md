# Java Client Example

Shows HELM integration with the Java SDK.

## Prerequisites

- HELM running at `http://port 3000` (`docker compose up -d`)
- Java 17+

## Source Example

`Main.java` is a small integration source file that uses
`labs.mindburn.helm.HelmClient`. This directory does not carry its own Maven
project; use it as source material for a JVM service or run the SDK package
gate below.

```bash
make test-sdk-java
```

## Expected Output

The example prints chat-completion, conformance, and health sections. The exact
verdict, reason code, and gate count depend on the policy and HELM server you
run locally.
