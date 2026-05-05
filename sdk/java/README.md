# HELM SDK — Java

Typed Java client for the retained HELM kernel API.

## Coordinate

```xml
<dependency>
  <groupId>com.github.Mindburn-Labs</groupId>
  <artifactId>helm-sdk</artifactId>
  <version>0.4.0</version>
</dependency>
```

Published Maven version is `0.4.0` and is declared in `pom.xml`.

## Local Development

```bash
mvn -q test package
```

## Generated Sources

`TypesGen.java` is generated from `api/openapi/helm.openapi.yaml`. Protobuf bindings under `src/main/java/helm/**` are generated from `protocols/proto/`.

## Usage

```java
import labs.mindburn.helm.HelmClient;
import labs.mindburn.helm.TypesGen.ChatCompletionRequest;
import labs.mindburn.helm.TypesGen.ChatCompletionRequestMessagesInner;

import java.util.List;

class Example {
  public static void main(String[] args) {
    HelmClient client = new HelmClient("http://localhost:8080");
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

`HelmClient` exposes typed methods for `createEvidenceEnvelopeManifest`, `listNegativeConformanceVectors`, `listMcpRegistry`, `discoverMcpServer`, `approveMcpServer`, `listSandboxBackendProfiles`, and `inspectSandboxGrant`. These methods mirror the public OpenAPI execution-boundary routes without making external evidence envelopes authoritative.

## Release Notes

`0.4.0` is the cleaned OSS kernel baseline with the retained OpenAPI client surface and protobuf message bindings.
