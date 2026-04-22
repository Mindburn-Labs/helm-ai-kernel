// HELM SDK Example — Rust
// Shows: chat completions, denial handling, conformance.
// Run: cargo run --example rust_client

use helm_sdk::{ChatCompletionRequest, ChatMessage, ConformanceRequest, HelmClient};

fn main() {
    let client = HelmClient::new("http://localhost:8080");

    // 1. Chat completions (governed by HELM)
    println!("=== Chat Completions ===");
    match client.chat_completions(&ChatCompletionRequest {
        model: "gpt-4".into(),
        messages: vec![ChatMessage {
            role: "user".into(),
            content: "List files in /tmp".into(),
            tool_call_id: None,
        }],
        tools: None,
        temperature: None,
        max_tokens: None,
        stream: None,
    }) {
        Ok(res) => {
            if let Some(choice) = res.choices.first() {
                println!("Response: {:?}", choice.message.content);
            }
        }
        Err(e) => println!("Denied: {:?} — {}", e.reason_code, e.message),
    }

    // 2. Conformance
    println!("\n=== Conformance ===");
    match client.conformance_run(&ConformanceRequest {
        level: "L2".into(),
        profile: None,
    }) {
        Ok(conf) => println!(
            "Verdict: {} Gates: {} Failed: {}",
            conf.verdict, conf.gates, conf.failed
        ),
        Err(e) => println!("Conformance error: {:?}", e.reason_code),
    }

    // 3. Health
    println!("\n=== Health ===");
    match client.health() {
        Ok(h) => println!("Status: {}", h),
        Err(e) => println!("Health failed: {}", e),
    }
}
