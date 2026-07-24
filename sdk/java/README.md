# HELM SDK - Java

Typed Java client for the retained HELM kernel API.

## Package Status

The sources in this tree are available in the repository and pass
`make test-sdk-java` (including real HTTP loopback tests) and
`make sdk-openapi-check`. That source availability is not a published or
conformance-certified artifact: package metadata in this source tree targets
the future Maven Central coordinate `io.github.mindburnlabs:helm-sdk:0.7.5`,
and no claim is made that remote artifacts have been published or that the
full endpoint surface is conformance-certified until tagged release evidence
exists. Verify Maven Central or the published version-status evidence before
using the coordinate. After the tag-driven release completes, the dependency
declaration is:

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

`TypesGen.java` is generated from `api/openapi/helm.openapi.yaml` by
`scripts/sdk/gen.sh`; do not hand-edit it. Protobuf bindings under
`src/main/java/helm/**` are generated from `protocols/proto/`.

## JSON Mapping

Typed request/response bodies are serialized with Jackson
(`jackson-databind`), honoring the generated `@JsonProperty` wire names and
restoring typed getters on decode. Gson is retained only for the untyped
`JsonElement` pass-through methods. `HelmClient.health()` returns the raw
plain-text `/healthz` body.

Models generated from schemas with `additionalProperties: true` no longer
extend `HashMap<String, Object>` (a `Map` superclass makes JSON serializers
treat the whole model as a bare map and drop the declared accessor-backed
fields). They are plain beans whose undeclared properties round-trip through
`putAdditionalProperty(key, value)` / `getAdditionalProperty(key)` /
`getAdditionalProperties()`. Migration: code that used these models as a
`Map` (lookup, iteration, `put`) must switch to the typed accessors plus the
additional-properties container.

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
