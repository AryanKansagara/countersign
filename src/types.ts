// The shared contract. Fares's validator and the core gateway both speak this.
import type { ObjectId, Document } from "mongodb";

export type Op = "insertOne" | "updateOne" | "updateMany" | "deleteOne" | "deleteMany";
export const WRITE_OPS: Op[] = ["insertOne", "updateOne", "updateMany", "deleteOne", "deleteMany"];

export type Status =
  | "blocked"      // failed validation/policy; never runs
  | "pending"      // waiting for a human
  | "approved"     // approved, not yet executed (single use)
  | "consumed"     // approval claimed by the executor (atomic)
  | "applied"
  | "failed"       // TOCTOU / verification abort; nothing changed
  | "rejected"
  | "expired"
  | "rolled_back";

export interface ChangeRequest {
  collection: string;
  op: Op;
  filter?: Document;     // required for update/delete
  update?: Document;     // required for update ($set/$inc/$unset only)
  document?: Document;   // required for insert
  expectedCount: number; // agent must say how many records it means to touch
  reason: string;
}

export interface Identity {
  _id: string;                 // "agent:support-bot" | "human:alice"
  kind: "agent" | "human";
  tenantId: string;
  role?: string;               // humans: "support" | "approver" | "admin"
  scopes?: string[];           // agents: collections the agent may ever touch
  owner?: string;              // agents: the human this agent acts for by default
  keyHash: string;             // sha256 of API key
  disabled?: boolean;
}

export interface Rule {
  collection: string;
  read: boolean;
  ops: Op[];                   // write ops allowed
  writableFields: string[];
  maskedFields: string[];      // returned as "***" on reads
  autoApproveMax: number;      // <= this many records and no other trigger -> auto
  hardMax: number;             // > this many -> blocked outright
  approvalIf?: { field: string; gt: number }; // e.g. amount > 100 needs a human
}

export interface Policy {
  _id: string;                 // `${tenantId}:${role}`
  tenantId: string;
  role: string;
  rules: Rule[];
  version: number;
}

export interface Proposal extends ChangeRequest {
  _id: ObjectId;
  tenantId: string;
  agentId: string;
  onBehalfOf: string;          // human id the agent acts for
  status: Status;
  risk: { tier: "auto" | "approval" | "blocked"; reasons: string[] };
  dryRun?: { ids: ObjectId[]; versions: number[]; idsHash: string };
  nonce: string;
  expiresAt: Date;
  hash: string;                // sha256 over canonical proposal; recomputed at execution
  approvedBy?: string;
  policyVersion?: number;
  result?: Document;
  embedding?: number[];
  precedent?: { proposalId: string; score: number; reason: string } | null;
  createdAt: Date;
}
