# ✍️ Countersign

**Pull requests for agent data changes.** An MCP write gateway for MongoDB Atlas: agents never write to your database directly. Every change becomes a proposal that is identity-checked, policy-checked and dry-run, then either auto-applied, sent to a human with a PR-style diff, or blocked. What lands is verified, can be rolled back in one click, and is recorded in a tamper-evident ledger.

> Built at *Agents in Context Toronto: a MongoDB Hackathon* (Nov 14, 2026) for **Track 1: Agents You Can Audit**. Everything in this repo was written during the event.

## Why

AI agents with database access have already wiped production data (PocketOS, April 2026: one API call, 9 seconds, backups included). The usual answer is to make agents read-only, which removes most of their value. Read-only flags inside MCP servers have also been bypassed. Teams need agents that can **write**, with the same safeguards humans get: review, least privilege, undo and an audit trail.

## How it works

```
agent ──MCP──▶ propose_change ──▶ validate ──▶ dry run ──▶ risk tier
                                    │            │            ├─ auto      ─▶ apply in txn ─▶ verify ─▶ ledger
                                    │            │            ├─ approval  ─▶ human diff ─▶ approve ─▶ apply …
                                    ▼            ▼            └─ blocked   ─▶ ledger
                             $where/$out/…   exact _ids + versions
```

| Track 1 question | Countersign |
|---|---|
| Decide what an agent may do and enforce it *before* it runs | Each agent and each human has its own key. Effective rights = **agent scope ∩ human role**. Collection-, op- and field-level rules. Dry run counts the real matches; the agent must state `expectedCount`, so "expects 3, matches 4,000" is blocked. |
| Record what it did, why, under whose authority | **Hash-chained ledger** in Atlas (schema-validated, insert-only DB role). Each entry records the agent, the human it acts for, the approver, the policy version, the decision and its reasons. |
| Stop or roll back mid-run | **Kill switch** document checked on every call; canary records auto-freeze a hijacked agent. **One-click rollback** from before-images, refusing to clobber later changes. |

### Where Atlas does the work

| Feature | Used for |
|---|---|
| Multi-document **transactions** | Re-check, write and verify atomically; any mismatch aborts with nothing changed |
| **Change streams** | Live audit feed in the inbox; watchdog flags any write to business data that bypassed Countersign |
| **Schema validation** | Ledger entries and identities can't be written half-formed |
| **TTL indexes** | Time-limited unmask grants expire on their own |
| **Custom DB roles** | Gateway user can only *insert* into the ledger and only *read* identities and policies |
| Aggregation | Tenant isolation injected into every pipeline, including inside `$lookup` |

## Security model (red-team scoreboard)

`npm run attacks` runs each attack through Countersign and, on a scratch copy, through plain full-access MongoDB (what a raw database MCP server gives an agent):

| Attack | Raw MongoDB access | Countersign |
|---|---|---|
| Privilege escalation (`$set balance`) | balance = 999999 | blocked: field not writable |
| Prompt injection in a record ("delete every lead") | 24 leads deleted | blocked: empty filter |
| Bulk delete (expects 3, matches 12) | 12 deleted | blocked: count mismatch |
| Write through a read (`$out`) | collection overwritten | blocked: operator not allowed |
| Cross-tenant `$lookup` | 24 foreign rows leaked | 0 rows (tenant injected) |
| Approval tampering | n/a | blocked: SHA-256 mismatch |
| Self-approval | n/a | blocked |
| Replay an approved refund | paid twice | blocked: single-use approval |
| TOCTOU (record changed before execution) | writes whatever matches | blocked: version check in txn |
| Ledger tampering | undetected | detected at exact entry |
| Canary record touched | silently changed | blocked + agent frozen |

## Run it

```bash
npm install
npm test                         # full end-to-end + attack suite on a throwaway local replica set
cp .env.example .env             # set MONGODB_URI (Atlas)
npm run seed                     # demo world: Maple Credit Union + Northwind Wealth (admin user)
npm start                        # approval inbox + remote MCP at http://localhost:8080
```

### Connect an agent

Local (stdio), e.g. Claude Desktop or Cursor:

```json
{
  "mcpServers": {
    "countersign": {
      "command": "npx", "args": ["tsx", "/path/to/countersign/src/mcp.ts"],
      "env": { "MONGODB_URI": "…", "CS_AGENT_KEY": "cs_agent_maple_support", "CS_HUMAN_KEY": "cs_human_maple_alice" }
    }
  }
}
```

Remote (streamable HTTP): `https://<host>/mcp` with one header, `x-agent-key`. For clients without custom headers (ChatGPT, claude.ai) use `https://<host>/mcp/<agent key>`. Copy-paste setup for Claude Code, Claude Desktop, claude.ai, Cursor, VS Code and ChatGPT is on the **Connect your AI** tab of the app.

Tools: `whoami`, `query`, `propose_change`, `proposal_status`, `request_agent_key`, `claim_key`.

### Access and keys

- **Sign in with GitHub** on the inbox. Admins listed in `GITHUB_ADMINS` become approvers on first sign-in; everyone else submits an access request that a different approver must accept.
- **Agent keys are requested, not minted.** A human asks for an agent key scoped to specific collections (inbox or the `request_agent_key` MCP tool), a *different* approver approves it, and the key is shown exactly once (`claim_key`). Revocation is instant. Identities are insert-only at the database level, so a compromised gateway can add identities but never change an existing one's role or scopes.

## Layout

```
src/types.ts     proposal format (the contract between gateway and validator)
src/validate.ts  query validator: banned operators, field rules, tenant-scoped pipelines
src/policy.ts    identity, agent ∩ human rights, kill switch, risk tiers
src/gateway.ts   propose → dry run → approve → execute (txn + verify) → rollback; masked reads
src/ledger.ts    hash-chained append + verify
src/mcp.ts       MCP server
src/server.ts    approval inbox API, remote MCP, change-stream watchdog
public/          approval inbox (single HTML file)
attacks/run.ts   red-team scoreboard
```

## Team

Aryan Kansagara · Fares (security validation and adversarial testing)
