# Java Client Example

Shows HELM integration with the Java SDK.

## Prerequisites

- HELM running at `http://localhost:8080` (`docker compose up -d`)
- Java 17+

## Run

```bash
javac -cp ../../sdk/java/target/classes Main.java
java -cp .:../../sdk/java/target/classes Main
```

Or use the SDK JAR directly after `mvn package` in `sdk/java/`.

## Expected Output

```
Chat Completions: Denied: DENY_TOOL_NOT_FOUND
Conformance: PASS (12 gates)
```
