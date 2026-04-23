// HELM SDK Example — Java
// Shows: chat completions, denial handling, conformance.
// Requires: sdk/java built first (mvn compile in sdk/java)

import labs.mindburn.helm.HelmClient;
import labs.mindburn.helm.TypesGen.*;

import java.util.List;

public class Main {
    public static void main(String[] args) {
        var helm = new HelmClient("http://localhost:8080");

        // 1. Chat completions (governed by HELM)
        System.out.println("=== Chat Completions ===");
        try {
            var req = new ChatCompletionRequest();
            req.model = "gpt-4";
            req.messages = List.of(new ChatMessage("user", "List files in /tmp"));
            var res = helm.chatCompletions(req);
            if (res.choices != null && !res.choices.isEmpty()) {
                System.out.println("Response: " + res.choices.get(0).message.content);
            }
        } catch (HelmClient.HelmApiException e) {
            System.out.println("Denied: " + e.reasonCode + " — " + e.getMessage());
        }

        // 2. Conformance
        System.out.println("\n=== Conformance ===");
        try {
            var conf = helm.conformanceRun(new ConformanceRequest("L2"));
            System.out.println("Verdict: " + conf.verdict + " Gates: " + conf.gates + " Failed: " + conf.failed);
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
}
