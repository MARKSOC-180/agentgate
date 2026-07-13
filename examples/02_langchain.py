"""
02_langchain.py — 用 AgentGate 包装 LangChain 工具(框架无关的 wrap 模式)。

无需安装 LangChain 也能看懂接入方式：核心就是 gate.wrap() 把任意 callable
变成「受控工具」。若已安装 langchain-core，取消下方 OPTIONAL 块的注释即可
直接挂到 LangChain agent 上。
"""

from agentgate import Gateway, Policy

policy = Policy(
    deny_tools={"shell_exec"},
    destructive_tools={"delete_records"},
    require_approval_tools={"delete_records"},
)
gate = Gateway(policy=policy, audit_path="langchain_audit.ndjson",
               trace_path="langchain_trace.ndjson")


def search_customers(query: str) -> str:
    return f"found 3 customers matching {query!r}"


def delete_records(table: str) -> str:
    return f"deleted all rows from {table}"


# ---- AgentGate 受控工具(任何框架都能用) ----
safe_search = gate.wrap("search_customers", search_customers)
safe_delete = gate.wrap("delete_records", delete_records, destructive=True)

if __name__ == "__main__":
    print(safe_search({"query": "acme"}, principal="agent-1"))
    print(safe_delete({"table": "orders"}, principal="agent-1"))  # -> blocked / held

# ---- OPTIONAL: LangChain Tool 挂载(需 pip install langchain-core) ----
try:
    from langchain_core.tools import StructuredTool

    lc_search = StructuredTool.from_function(
        func=lambda query: safe_search({"query": query}, principal="langchain-agent").output,
        name="search_customers",
        description="Search CRM customers",
    )
    # agent = create_react_agent(..., tools=[lc_search, ...])
except ImportError:
    pass
