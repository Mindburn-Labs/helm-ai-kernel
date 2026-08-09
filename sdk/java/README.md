# HELM SDK - Java

Typed Java client for the retained HELM kernel API.

## Package Status

Package metadata in this source tree targets a future Maven Central coordinate.
The current source target is `0.8.3`.
This source target does not claim that remote artifacts have been published or
that the endpoint surface is conformance-certified; verify Maven Central and
tagged release evidence before using a coordinate. After the tag-driven
release completes, use the verified version:

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

`TypesGen.java` is generated from `api/openapi/helm.openapi.yaml` by
`scripts/sdk/gen.sh`; do not hand-edit it. Protobuf bindings under
`src/main/java/helm/**` are generated from `protocols/proto/`.

## JSON Mapping

Typed request/response bodies use Jackson (`jackson-databind`), honoring the
generated `@JsonProperty` wire names and restoring typed getters on decode.
Gson remains for the deprecated dynamic `evaluateDecision(Object)` method and
other untyped `JsonElement` pass-through methods. `HelmClient.health()` returns
the raw plain-text `/healthz` body.

Models generated from schemas with `additionalProperties: true` are plain
beans rather than `HashMap<String, Object>` subclasses, so serializers retain
their declared fields. Undeclared properties round-trip through
`putAdditionalProperty(key, value)` / `getAdditionalProperty(key)` /
`getAdditionalProperties()`. Code that previously consumed these models as a
`Map` must migrate to typed accessors plus the additional-properties container.

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

For a protected tenant-scoped route, pass the API key and explicit server-bound
tenant and principal IDs. Existing one- and two-argument constructors remain
available for public routes.

```java
HelmClient client = new HelmClient(
    "http://127.0.0.1:7714",
    System.getenv("HELM_ADMIN_API_KEY"),
    "tenant-id",
    "principal-id"
);
```

## Execution Boundary Methods

`HelmClient` exposes methods for evidence envelope manifests, boundary records
and checkpoints, conformance vectors, MCP quarantine and authorization
profiles, sandbox profiles and grants, authz snapshots, approvals, budgets,
telemetry export, and coexistence capabilities. These methods mirror public
OpenAPI execution-boundary routes without making external evidence envelopes
authoritative.

`evaluateDecisionV5` accepts `TypesGen.EvaluateRequest`; set non-blank `tool`,
`effect_level`, and `session_id` to receive a receipt-bearing
`TypesGen.EvaluateResponse`. The deprecated `evaluateDecision(Object)` method
remains for legacy dynamic callers.

## Source target

The client accepts canonical typed evaluation and receipt-bearing V5 responses.
Use a published coordinate only after registry evidence verifies it.
