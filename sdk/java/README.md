# HELM SDK - Java

Typed Java client for the retained HELM kernel API.

## Coordinates

```xml
<dependency>
  <groupId>com.github.Mindburn-Labs</groupId>
  <artifactId>helm-sdk</artifactId>
  <version>0.5.0</version>
</dependency>
```

The Maven publish workflow owns the `com.github.Mindburn-Labs:helm-sdk`
coordinate. JitPack release availability is verified during OSS readiness and
must not be claimed for `0.5.0` until the GitHub release exists.

Package metadata declares version `0.5.0` in `pom.xml`.

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

`0.5.0` is the cleaned OSS kernel baseline with the retained OpenAPI client surface and protobuf message bindings.
