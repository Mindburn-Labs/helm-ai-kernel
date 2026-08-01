# HELM SDK - Java

Typed Java client for the retained HELM kernel API.

## Package Status

Package metadata in this source tree targets a future Maven Central coordinate.
The current source target is `0.8.0`.
This source target does not claim that remote artifacts have been published;
verify Maven Central or published version-status evidence before using a
coordinate. After the tag-driven release completes, use the verified version:

```xml
<dependency>
  <groupId>io.github.mindburnlabs</groupId>
  <artifactId>helm-sdk</artifactId>
  <version>&lt;version&gt;</version>
</dependency>
```

## Local Development

```bash
mvn -q test package
```

## Generated Sources

`TypesGen.java` is generated from `api/openapi/helm.openapi.yaml`. Protobuf
bindings under `src/main/java/helm/**` are generated from `protocols/proto/`.

## Usage

```java
import labs.mindburn.helm.HelmClient;
import labs.mindburn.helm.TypesGen.ChatCompletionRequest;
import labs.mindburn.helm.TypesGen.ChatCompletionRequestMessagesInner;

import java.util.List;

class Example {
  public static void main(String[] args) {
    HelmClient client = new HelmClient("http://127.0.0.1:7714");
    ChatCompletionRequest req = new ChatCompletionRequest()
        .model("gpt-4")
        .messages(List.of(new ChatCompletionRequestMessagesInner()
            .role(ChatCompletionRequestMessagesInner.RoleEnum.USER)
            .content("hello")));
    System.out.println(client.chatCompletions(req));
  }
}
```

## Execution Boundary Methods

`HelmClient` exposes methods for evidence envelope manifests, boundary records
and checkpoints, conformance vectors, MCP quarantine and authorization
profiles, sandbox profiles and grants, authz snapshots, approvals, budgets,
telemetry export, and coexistence capabilities. These methods mirror public
OpenAPI execution-boundary routes without making external evidence envelopes
authoritative.

`evaluateDecision` accepts `TypesGen.EvaluateRequest` only. Set non-blank
`tool`, `effect_level`, and `session_id`; it returns the receipt-bearing
`TypesGen.EvaluateResponse`.

## Source target

The client accepts canonical typed evaluation and receipt-bearing V5 responses.
Use a published coordinate only after registry evidence verifies it.
