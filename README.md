# Local Privacy Guardian MCP

A zero-trust **file firewall for AI**. It intercepts file access from AI tools via MCP, enforces least-privilege policies, **redacts sensitive data** inline, and emits **tamper-evident audit logs**—so users can use AI on their machines without leaking secrets or PII.

---

## 1. Problem & Value
Modern AI tools can read local files or upload data to the cloud without guardrails. Users and developers routinely expose **PII/PHI/PCI** and secrets (tokens, keys) in prompts and RAG pipelines.

**Value:** Before any AI client touches local data, enforce **deny-by-default** access, **minimize** data via redaction, and create **verifiable evidence** of what was shared.
## 2. Tool Definitions
### Get_policy
Purpose: Returns the current privacy enforcement policy <br>
What it does: Shows you what privacy rules and settings are currently active <br>
Use case: Understanding what privacy protections are in place before working with files or data

### Scan_text
Purpose: Scans raw text for likely PII and returns detailed findings <br>
What it does: Analyzes any text you provide and identifies PII like emails, phone numbers, names with exact character positions <br>

### Safe_read
Purpose: reads text files when enforcing privacy policy & offering optional redaction <br>
What it does: 
- Reads file content safely according to privacy rules <br>
- Automatically redact PII if requested
- May truncate large files (controlled by max_bytes parameter)
- Returns the content plus any PII findings and redaction information

Parameters:
- relpath (required): path to the file
- max_bytes (optional): limit file size read
- redact (optional): whether to automatically redact PII

### Copy_redacted_file
Purpose: Creates a privacy-safe copy of a file with PII automatically redacted <br>
What it does:
- Makes a new copy of the original file in a "./redacted" directory
- Automatically replaces detected PII with redaction markers
- Returns the path to the new redacted file plus details about what was found/redacted <br>

Parameters:
- relpath (required): original file to redact
- out_relpath (optional): custom output path for the redacted copy
