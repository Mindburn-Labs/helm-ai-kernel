# HELM SDK - Java

Typed Java client for the retained HELM kernel API.

## Package Status

Package metadata in this source tree targets the future Maven Central
coordinate `io.github.mindburnlabs:helm-sdk:0.7.2`. This source target does not
claim that remote artifacts have been published; verify Maven Central or the
published version-status evidence before using the coordinate. After the
tag-driven release completes, the dependency declaration is:

```xml
<dependency>
  <groupId>io.github.mindburnlabs</groupId>
  <artifactId>helm-sdk</artifactId>
  <version>0.7.2</version>
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
import labs.mindburn.helm.TypesGen.DecisionRequest;

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

    HelmClient evaluator = new HelmClient(
        "http://127.0.0.1:7714",
        System.getenv("HELM_ADMIN_API_KEY"),
        "tenant-a",
        "operator-a"
    );
    DecisionRequest decisionRequest = new DecisionRequest()
        .action("EXECUTE_TOOL")
        .resource("local.echo");
    System.out.println(evaluator.evaluateDecision(decisionRequest).getVerdict());
  }
}
```

`evaluateDecision` requires API key, tenant ID, and principal ID; use the
five-argument constructor to add a workspace ID when a scoped emergency-stop
fence is active. It serializes only `action`, `resource`, and optional
`context`; body identity and legacy evaluator payloads are not accepted.

The evaluator path has dedicated request/response conformance coverage. It is
not evidence that every generated Java model is runtime-certified: the broader
generated-model mapping repair is tracked in [HELM-173](https://linear.app/mindburn/issue/HELM-173).

## Execution Boundary Methods

`HelmClient` exposes methods for evidence envelope manifests, boundary records
and checkpoints, conformance vectors, MCP quarantine and authorization
profiles, sandbox profiles and grants, authz snapshots, approvals, budgets,
telemetry export, and coexistence capabilities. These methods mirror public
OpenAPI execution-boundary routes without making external evidence envelopes
authoritative.

## Release Notes

`0.7.2` is the release-hardening patch with the retained OpenAPI client surface
and protobuf message bindings.
