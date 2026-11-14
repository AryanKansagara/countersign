import { col, type Ctx } from "./db.js";
import { sha256 } from "./ledger.js";
import type { ChangeRequest, Identity, Policy, Rule } from "./types.js";
import { Denied } from "./validate.js";

export async function authenticate(c: Ctx, key: string | undefined, kind: Identity["kind"]): Promise<Identity> {
  if (!key) throw new Denied(`missing ${kind} key`);
  const id = await col.identities(c).findOne({ keyHash: sha256(key) });
  if (!id || id.kind !== kind) throw new Denied(`invalid ${kind} key`);
  if (id.disabled) throw new Denied(`${id._id} is disabled`);
  return id;
}

export interface Session {
  agent: Identity;
  human: Identity;
  tenantId: string;
  policy: Policy;
  rule: (collection: string) => Rule | undefined;
}

// Effective rights = agent scope ∩ human's role policy. Permissions only ever come from here,
// never from anything the model says or anything returned from the data.
export async function resolveSession(c: Ctx, agentKey: string | undefined, humanKey: string | undefined): Promise<Session> {
  const agent = await authenticate(c, agentKey, "agent");
  const human = await authenticate(c, humanKey, "human");
  if (agent.tenantId !== human.tenantId) throw new Denied("agent and human belong to different tenants");
  await assertNotKilled(c, agent.tenantId, agent._id);
  const policy = await col.policies(c).findOne({ _id: `${human.tenantId}:${human.role}` });
  if (!policy) throw new Denied(`no policy for role ${human.role}`);
  const scopes = new Set(agent.scopes ?? []);
  return {
    agent, human, tenantId: human.tenantId, policy,
    rule: (collection) => (scopes.has(collection) ? policy.rules.find((r) => r.collection === collection) : undefined),
  };
}

// Kill switch: one document. Flip it and every running session is refused on its next call.
export async function assertNotKilled(c: Ctx, tenantId: string, agentId: string) {
  const k = await col.settings(c).findOne({ _id: "killswitch" as any });
  if (k?.all || k?.tenants?.includes(tenantId) || k?.agents?.includes(agentId)) throw new Denied("kill switch is engaged");
}

const touched = (req: ChangeRequest) =>
  req.op === "insertOne" ? Object.keys(req.document ?? {}) : Object.values(req.update ?? {}).flatMap((f: any) => Object.keys(f ?? {}));

// Risk tier from what the dry run actually found, not from what the agent claimed.
export function assessRisk(req: ChangeRequest, rule: Rule, matched: number): { tier: "auto" | "approval" | "blocked"; reasons: string[] } {
  const reasons: string[] = [];
  if (matched === 0) return { tier: "blocked", reasons: ["filter matches no records"] };
  if (matched > rule.hardMax) return { tier: "blocked", reasons: [`matches ${matched} records; hard limit is ${rule.hardMax}`] };
  if (matched !== req.expectedCount) return { tier: "blocked", reasons: [`agent expected ${req.expectedCount} record(s) but filter matches ${matched}`] };
  if (req.op.endsWith("One") && matched > 1) return { tier: "blocked", reasons: [`${req.op} filter is ambiguous (${matched} matches)`] };

  if (req.op.startsWith("delete")) reasons.push("deletes always need a human");
  if (matched > rule.autoApproveMax) reasons.push(`touches ${matched} records (auto limit ${rule.autoApproveMax})`);
  const sensitive = touched(req).filter((f) => rule.maskedFields.includes(f.split(".")[0]));
  if (sensitive.length) reasons.push(`writes sensitive field(s): ${sensitive.join(", ")}`);
  if (rule.approvalIf) {
    const { field, gt } = rule.approvalIf;
    const vals = [req.document?.[field], req.update?.$set?.[field], req.update?.$inc?.[field]].filter((v) => typeof v === "number");
    if (vals.some((v) => Math.abs(v) > gt)) reasons.push(`${field} over ${gt}`);
  }
  return { tier: reasons.length ? "approval" : "auto", reasons };
}
