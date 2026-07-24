# HELM SDK - Java

Typed Java client for the retained HELM kernel API.

## Package Status

Package metadata in this source tree targets the future Maven Central
coordinate `io.github.mindburnlabs:helm-sdk:0.7.5`. This source target does not
claim that remote artifacts have been published; verify Maven Central or the
published version-status evidence before using the coordinate. After the
tag-driven release completes, the dependency declaration is:

```xml
<dependency>
  <groupId>io.github.mindburnlabs</groupId>
  <artifactId>helm-sdk</artifactId>
  <version>0.7.5</version>
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

## Release Notes

`0.7.5` is a security patch: fail-closed production receipt signing and a golang.org/x/text update for GO-2026-5970. The kernel's Boundary Enforcement Profile is retained, along with the OpenAPI client surface
and protobuf message bindings.
