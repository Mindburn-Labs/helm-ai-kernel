// HELM SDK Example — Java
// Shows: chat completions, denial handling, conformance.
// Requires: sdk/java built first (mvn compile in sdk/java)

import labs.mindburn.helm.HelmClient;
import labs.mindburn.helm.TypesGen.*;

import java.util.List;

public class Main {
    public static void main(String[] args) {
        var helm = new HelmClient(
                System.getenv().getOrDefault("HELM_URL", "http://127.0.0.1:7714"),
                requiredEnv("HELM_ADMIN_API_KEY"),
                requiredEnv("HELM_TENANT_ID"),
                requiredEnv("HELM_PRINCIPAL_ID"),
                optionalEnv("HELM_WORKSPACE_ID"),
                requiredEnv("HELM_SESSION_ID"));

        // 1. Chat completions (governed by HELM)
        System.out.println("=== Chat Completions ===");
        try {
            var req = new ChatCompletionRequest()
                    .model("gpt-4")
                    .messages(List.of(new ChatCompletionRequestMessagesInner()
                            .role(ChatCompletionRequestMessagesInner.RoleEnum.USER)
                            .content("List files in /tmp")));
            var res = helm.chatCompletions(req);
            if (res.getChoices() != null && !res.getChoices().isEmpty()
                    && res.getChoices().get(0).getMessage() != null) {
                System.out.println("Response: " + res.getChoices().get(0).getMessage().getContent());
            }
        } catch (HelmClient.HelmApiException e) {
            System.out.println("Denied: " + e.reasonCode + " — " + e.getMessage());
        }

        // 2. Conformance
        System.out.println("\n=== Conformance ===");
        try {
            var conf = helm.conformanceRun(new ConformanceRequest().level(ConformanceRequest.LevelEnum.L2));
            System.out.println("Verdict: " + conf.getVerdict() + " Gates: " + conf.getGates() + " Failed: " + conf.getFailed());
        } catch (HelmClient.HelmApiException e) {
            System.out.println("Conformance error: " + e.reasonCode);
        }

        // 3. Health
        System.out.println("\n=== Health ===");
        try {
            var h = helm.health();
            System.out.println("Status: " + h);
        } catch (Exception e) {
            System.out.println("Health failed: " + e.getMessage());
        }
    }

    private static String requiredEnv(String name) {
        String value = optionalEnv(name);
        if (value == null) {
            System.err.println(name + " is required for the governed serve runtime");
            System.exit(2);
        }
        return value;
    }

    private static String optionalEnv(String name) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? null : value;
    }
}
