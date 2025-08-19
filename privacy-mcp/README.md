# Local Privacy Guardian MCP

A zero-trust **file firewall for AI**. It intercepts file access from AI tools via MCP, enforces least-privilege policies, **redacts sensitive data** inline, and emits **tamper-evident audit logs**—so users can use AI on their machines without leaking secrets or PII.

---

## 1. Problem & Value
Modern AI tools can read local files or upload data to the cloud without guardrails. Users and developers routinely expose **PII/PHI/PCI** and secrets (tokens, keys) in prompts and RAG pipelines.

**Value:** Before any AI client touches local data, enforce **deny-by-default** access, **minimize** data via redaction, and create **verifiable evidence** of what was shared.
