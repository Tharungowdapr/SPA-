"""LangGraph investigation workflow (used when `langgraph` is installed; otherwise the plain loop runs).

gather_evidence -> classify -> [llm_refine if an LLM is available] -> finalize
Nodes are plain functions over a state dict, so the graph runs fully without an LLM.
All tools are read-only; the final output is a recommendation that a human must approve.
"""
from __future__ import annotations

from typing import Any, Callable, TypedDict


class State(TypedDict, total=False):
    user_id: str
    risk: float
    evidence: dict
    report: dict
    llm_error: str


def langgraph_available() -> bool:
    try:
        import langgraph.graph  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def build_graph(gather: Callable[[str], dict], classify: Callable[[str, dict, float], dict],
                refine: Callable[[str, dict, dict], dict] | None):
    from langgraph.graph import END, StateGraph

    def n_gather(st: State) -> State:
        return {"evidence": gather(st["user_id"])}

    def n_classify(st: State) -> State:
        rep = classify(st["user_id"], st["evidence"], st.get("risk", 0.0))
        rep["mode"] = "rule-based"
        return {"report": rep}

    def n_refine(st: State) -> State:
        try:
            rep = dict(st["report"])
            rep.update(refine(st["user_id"], st["evidence"], st["report"]))
            rep["mode"] = "llm"
            return {"report": rep}
        except Exception as exc:  # noqa: BLE001 - graceful degradation keeps the rule-based report
            return {"llm_error": type(exc).__name__}

    def route(_: State) -> str:
        return "llm_refine" if refine is not None else "finalize"

    def n_final(st: State) -> State:
        rep = dict(st["report"])
        if st.get("llm_error"):
            rep["llm_error"] = st["llm_error"]
        rep["evidence"] = st["evidence"]
        rep["requires_approval"] = True
        rep["engine"] = "langgraph"
        return {"report": rep}

    g: Any = StateGraph(State)
    g.add_node("gather_evidence", n_gather)
    g.add_node("classify", n_classify)
    g.add_node("llm_refine", n_refine)
    g.add_node("finalize", n_final)
    g.set_entry_point("gather_evidence")
    g.add_edge("gather_evidence", "classify")
    g.add_conditional_edges("classify", route, {"llm_refine": "llm_refine", "finalize": "finalize"})
    g.add_edge("llm_refine", "finalize")
    g.add_edge("finalize", END)
    return g.compile()
