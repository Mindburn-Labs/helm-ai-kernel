// HELM SDK Example — Rust
// Shows: chat completions, denial handling, conformance.
// Run: cargo run --example rust_client

use helm_sdk::{
    ChatCompletionRequest, ChatCompletionRequestMessagesInner,
    ChatCompletionRequestMessagesInnerRole, ConformanceRequest, ConformanceRequestLevel,
    HelmClient,
};
use std::env;

fn main() {
    let base_url = env::var("HELM_URL").unwrap_or_else(|_| "http://127.0.0.1:7714".into());
    let client = HelmClient::new(&base_url)
        .with_api_key(required_env("HELM_ADMIN_API_KEY"))
        .with_identity(
            required_env("HELM_TENANT_ID"),
            required_env("HELM_PRINCIPAL_ID"),
        )
        .with_session_id(required_env("HELM_SESSION_ID"));
    let client = match env::var("HELM_WORKSPACE_ID") {
        Ok(workspace_id) if !workspace_id.trim().is_empty() => {
            client.with_workspace_id(workspace_id)
        }
        _ => client,
    };

    // 1. Chat completions (governed by HELM)
    println!("=== Chat Completions ===");
    let request = ChatCompletionRequest::new(
        "gpt-4".into(),
        vec![ChatCompletionRequestMessagesInner::new(
            ChatCompletionRequestMessagesInnerRole::User,
            "List files in /tmp".into(),
        )],
    );
    match client.chat_completions(&request) {
        Ok(res) => {
            if let Some(choice) = res.choices.as_deref().and_then(|choices| choices.first()) {
                if let Some(message) = choice.message.as_deref() {
                    println!("Response: {:?}", message.content);
                }
            }
        }
        Err(e) => println!("Denied: {:?} — {}", e.reason_code, e.message),
    }

    // 2. Conformance
    println!("\n=== Conformance ===");
    match client.conformance_run(&ConformanceRequest::new(ConformanceRequestLevel::L2)) {
        Ok(conf) => println!(
            "Verdict: {:?} Gates: {:?} Failed: {:?}",
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

fn required_env(name: &str) -> String {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            eprintln!("{name} is required for the governed serve runtime");
            std::process::exit(2);
        })
}
