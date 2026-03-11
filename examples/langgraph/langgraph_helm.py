"""
LangGraph + HELM Integration Example

Routes a LangGraph agentic pipeline through a HELM-governed proxy,
producing receipts and EvidencePack for every LLM decision.

Prerequisites:
    pip install langgraph langchain-openai helm

Environment:
    HELM_PROXY_URL  - HELM proxy URL (default: http://localhost:8080)
    OPENAI_API_KEY  - OpenAI API key (forwarded by proxy)
"""

import os
import json
from typing import TypedDict, Annotated

# LangGraph imports
try:
    from langgraph.graph import StateGraph, END
    from langchain_openai import ChatOpenAI
except ImportError:
    print("Install dependencies: pip install langgraph langchain-openai")
    raise SystemExit(1)


# --- Configuration ---
HELM_PROXY_URL = os.getenv("HELM_PROXY_URL", "http://localhost:8080")


# --- State Definition ---
class AgentState(TypedDict):
    """State that flows through the agentic graph."""
    messages: list[dict]
    decision: str
    receipt_id: str


# --- HELM-governed LLM ---
def create_helm_llm():
    """Create an OpenAI LLM that routes through the HELM proxy."""
    return ChatOpenAI(
        model="gpt-4o-mini",
        base_url=f"{HELM_PROXY_URL}/v1",
        # HELM proxy forwards to provider; receipts are produced automatically
        default_headers={
            "X-Helm-Session": "langgraph-example",
            "X-Helm-Principal": "agent:langgraph",
        },
    )


# --- Graph Nodes ---
def evaluate_node(state: AgentState) -> AgentState:
    """Decision node: evaluate intent through HELM-governed LLM."""
    llm = create_helm_llm()

    messages = state["messages"]
    response = llm.invoke(messages)

    return {
        **state,
        "decision": response.content,
        "messages": messages + [{"role": "assistant", "content": response.content}],
    }


def should_continue(state: AgentState) -> str:
    """Routing logic: if decision includes 'EXECUTE', proceed; otherwise end."""
    if "EXECUTE" in state.get("decision", "").upper():
        return "execute"
    return "end"


def execute_node(state: AgentState) -> AgentState:
    """Execute the approved action (stub — real tool calls go here)."""
    print(f"[EXECUTE] Action approved by HELM: {state['decision'][:80]}")
    return state


# --- Build the Graph ---
def build_graph():
    """Build the LangGraph agent with HELM governance."""
    workflow = StateGraph(AgentState)

    workflow.add_node("evaluate", evaluate_node)
    workflow.add_node("execute", execute_node)

    workflow.set_entry_point("evaluate")
    workflow.add_conditional_edges("evaluate", should_continue, {
        "execute": "execute",
        "end": END,
    })
    workflow.add_edge("execute", END)

    return workflow.compile()


# --- Main ---
if __name__ == "__main__":
    print("🛡️ LangGraph + HELM Integration Example")
    print(f"   Proxy: {HELM_PROXY_URL}")
    print()

    graph = build_graph()

    # Example: ask the agent to do something
    result = graph.invoke({
        "messages": [
            {"role": "user", "content": "Summarize the top 3 Python testing libraries."}
        ],
        "decision": "",
        "receipt_id": "",
    })

    print(f"\n✅ Agent completed")
    print(f"   Decision: {result['decision'][:100]}...")
    print(f"\n📦 EvidencePack produced by HELM proxy at {HELM_PROXY_URL}")
    print(f"   Export: helm export --session langgraph-example")
    print(f"   Verify: helm verify --bundle ./evidencepack --json")
