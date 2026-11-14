import { randomBytes } from "node:crypto";
import { ObjectId, type Document } from "mongodb";
import { col, type Ctx } from "./db.js";
import { append, canonical, sha256 } from "./ledger.js";
import { assertNotKilled, assessRisk, authenticate, type Session } from "./policy.js";
import type { ChangeRequest, Proposal } from "./types.js";
import { buildReadPipeline, Denied, validateChange } from "./validate.js";
import { describe, embed, similar } from "./embed.js";

const TTL_MS = 15 * 60_000;

// Everything that defines "what was approved". Change any of it and the approval is void.
export const proposalHash = (p: Omit<Proposal, "hash"> | Proposal) =>
  sha256(canonical({
    id: p._id, tenantId: p.tenantId, agentId: p.agentId, onBehalfOf: p.onBehalfOf,
    collection: p.collection, op: p.op, filter: p.filter ?? null, update: p.update ?? null,
    document: p.document ?? null, expectedCount: p.expectedCount, nonce: p.nonce,
    expiresAt: p.expiresAt, idsHash: p.dryRun?.idsHash ?? null, policyVersion: p.policyVersion ?? null,
  }));

export const summarize = (p: Proposal) => ({
  proposalId: String(p._id), status: p.status, risk: p.risk, collection: p.collection, op: p.op,
  matched: p.op === "insertOne" ? 1 : p.dryRun?.ids.length ?? 0, expectedCount: p.expectedCount, result: p.result ?? null, precedent: p.precedent ?? null,
});

// ---------- propose ----------
export async function propose(c: Ctx, s: Session, req: ChangeRequest): Promise<Proposal> {
  const base = {
    _id: new ObjectId(), tenantId: s.tenantId, agentId: s.agent._id, onBehalfOf: s.human._id,
    collection: req.collection, op: req.op, filter: req.filter, update: req.update, document: req.document,
    expectedCount: req.expectedCount, reason: req.reason, nonce: randomBytes(16).toString("hex"),
    expiresAt: new Date(Date.now() + TTL_MS), createdAt: new Date(), policyVersion: s.policy.version,
  };
  const rule = s.rule(req.collection);
  let p: Proposal;
  try {
    validateChange(req, rule);
    // Canary: a trap record no honest task touches. Hitting one means the agent is compromised.
    if (req.filter && await c.data.collection(req.collection).countDocuments({ $and: [{ tenantId: s.tenantId }, req.filter, { _canary: true }] })) {
      await col.settings(c).updateOne({ _id: "killswitch" as any }, { $addToSet: { agents: s.agent._id } }, { upsert: true });
      await append(c, "alarm.canary", "gateway", { agent: s.agent._id, onBehalfOf: s.human._id, collection: req.collection });
      throw new Denied("canary record touched: agent frozen pending review");
    }
    const dryRun = await dryRunMatch(c, s.tenantId, req, rule!.hardMax);
    p = { ...base, dryRun, risk: assessRisk(req, rule!, req.op === "insertOne" ? 1 : dryRun.ids.length), status: "pending", hash: "" };
    if (p.risk.tier === "blocked") p.status = "blocked";
    else await noveltyCheck(c, p);
  } catch (e) {
    if (!(e instanceof Denied)) throw e;
    p = { ...base, risk: { tier: "blocked", reasons: [e.message] }, status: "blocked", hash: "" };
  }
  p.hash = proposalHash(p);
  await col.proposals(c).insertOne(p);
  await append(c, p.status === "blocked" ? "proposal.blocked" : "proposal.created", s.agent._id,
    { onBehalfOf: s.human._id, collection: p.collection, op: p.op, risk: p.risk, matched: p.dryRun?.ids.length ?? 0, reason: p.reason }, p._id);

  if (p.risk.tier === "auto") {
    await col.proposals(c).updateOne({ _id: p._id, status: "pending" }, { $set: { status: "approved", approvedBy: "policy:auto" } });
    await append(c, "proposal.auto_approved", "policy:auto", { policyVersion: s.policy.version }, p._id);
    return execute(c, p._id);
  }
  return p;
}

// Vector Search: has anything like this been approved before in this tenant? Unprecedented
// changes go to a human even if they're small. Fails open: novelty is an extra signal, not the wall.
const NOVELTY_MIN_HISTORY = 5;
const NOVELTY_MIN_SCORE = 0.8; // vectorSearchScore for cosine = (1 + cos) / 2
async function noveltyCheck(c: Ctx, p: Proposal) {
  try {
    p.embedding = await embed(describe(p));
    const [best] = await similar(c, p.tenantId, p.embedding, ["applied"], 1);
    p.precedent = best ? { proposalId: String(best._id), score: Number(best.score.toFixed(3)), reason: best.reason } : null;
    const history = await col.proposals(c).countDocuments({ tenantId: p.tenantId, status: "applied" });
    if (history >= NOVELTY_MIN_HISTORY && (!best || best.score < NOVELTY_MIN_SCORE)) {
      p.risk.reasons.push(`novel: nothing similar has been approved before (closest ${best ? best.score.toFixed(2) : "none"})`);
      p.risk.tier = "approval";
    }
  } catch (e: any) {
    console.error("novelty check skipped:", e.message);
  }
}

// Records exactly which documents (and which versions) the change would touch.
async function dryRunMatch(c: Ctx, tenantId: string, req: ChangeRequest, hardMax: number) {
  if (req.op === "insertOne") return { ids: [], versions: [], idsHash: sha256("insert") };
  const docs = await c.data.collection(req.collection)
    .find({ $and: [{ tenantId }, req.filter!] }, { projection: { _id: 1, _v: 1 } })
    .sort({ _id: 1 }).limit(hardMax + 1).toArray();
  const ids = docs.map((d) => d._id);
  const versions = docs.map((d) => d._v ?? 0);
  return { ids, versions, idsHash: sha256(canonical({ ids, versions })) };
}

// ---------- approve / reject ----------
export async function approve(c: Ctx, id: string, approverKey: string | undefined) {
  const human = await authenticate(c, approverKey, "human");
  const p = await col.proposals(c).findOne({ _id: new ObjectId(id) });
  if (!p) throw new Denied("no such proposal");
  if (human.tenantId !== p.tenantId) throw new Denied("approver is in a different tenant");
  if (!["approver", "admin"].includes(human.role ?? "")) throw new Denied(`role ${human.role} cannot approve`);
  if (human._id === p.onBehalfOf) throw new Denied("no self-approval: you requested this change");
  if (p.status !== "pending") throw new Denied(`proposal is ${p.status}`);
  if (proposalHash(p) !== p.hash) throw new Denied("proposal was modified after it was created");
  if (p.expiresAt < new Date()) throw new Denied("proposal expired");
  // Guard on hash too: approval binds to exactly this content.
  const r = await col.proposals(c).updateOne({ _id: p._id, status: "pending", hash: p.hash }, { $set: { status: "approved", approvedBy: human._id } });
  if (!r.modifiedCount) throw new Denied("proposal changed state concurrently");
  await append(c, "proposal.approved", human._id, { hash: p.hash }, p._id);
  return execute(c, p._id);
}

export async function reject(c: Ctx, id: string, approverKey: string | undefined, why = "") {
  const human = await authenticate(c, approverKey, "human");
  const r = await col.proposals(c).findOneAndUpdate(
    { _id: new ObjectId(id), status: "pending", tenantId: human.tenantId }, { $set: { status: "rejected", approvedBy: human._id } });
  if (!r) throw new Denied("not pending (or wrong tenant)");
  await append(c, "proposal.rejected", human._id, { why }, r._id);
  return r;
}

// ---------- execute ----------
class Abort extends Error {}

export async function execute(c: Ctx, id: ObjectId): Promise<Proposal> {
  // Single-use: only one caller can move approved -> consumed. Replays get nothing.
  const p = await col.proposals(c).findOneAndUpdate({ _id: id, status: "approved" }, { $set: { status: "consumed" } }, { returnDocument: "after" });
  if (!p) throw new Denied("approval already used or proposal not approved");
  const fail = async (status: "failed" | "expired", why: string) => {
    await col.proposals(c).updateOne({ _id: id }, { $set: { status, result: { error: why } } });
    await append(c, `proposal.${status}`, "gateway", { why }, id);
    return (await col.proposals(c).findOne({ _id: id }))!;
  };
  if (proposalHash(p) !== p.hash) return fail("failed", "hash mismatch at execution: proposal tampered");
  if (p.expiresAt < new Date()) return fail("expired", "approval expired before execution");
  try { await assertNotKilled(c, p.tenantId, p.agentId); } catch (e: any) { return fail("failed", e.message); }

  const coll = c.data.collection(p.collection);
  const session = c.client.startSession();
  try {
    let result: Document = {};
    await session.withTransaction(async () => {
      const tag = { _cs: String(p._id) };
      if (p.op === "insertOne") {
        const doc = { ...p.document, tenantId: p.tenantId, _v: 1, ...tag };
        const r = await coll.insertOne(doc, { session });
        await col.beforeImages(c).insertOne({ proposalId: p._id, collection: p.collection, docId: r.insertedId, before: null }, { session });
        result = { inserted: 1, id: String(r.insertedId) };
        return;
      }
      const ids = p.dryRun!.ids;
      // TOCTOU: re-read inside the transaction. Same docs, same versions, still matching — or abort.
      const before = await coll.find({ $and: [{ tenantId: p.tenantId }, p.filter!, { _id: { $in: ids } }] }, { session }).sort({ _id: 1 }).toArray();
      const nowHash = sha256(canonical({ ids: before.map((d) => d._id), versions: before.map((d) => d._v ?? 0) }));
      if (nowHash !== p.dryRun!.idsHash) throw new Abort(`records changed since dry run (${before.length}/${ids.length} still match at the same version)`);

      await col.beforeImages(c).insertMany(before.map((d) => ({ proposalId: p._id, collection: p.collection, docId: d._id, before: d })), { session });
      const scope = { _id: { $in: ids }, tenantId: p.tenantId };

      if (p.op.startsWith("delete")) {
        const r = await coll.deleteMany(scope, { session });
        if (r.deletedCount !== ids.length) throw new Abort(`deleted ${r.deletedCount}, expected ${ids.length}`);
        result = { deleted: r.deletedCount };
        return;
      }
      const u = p.update!;
      const update = { ...u, $set: { ...(u.$set ?? {}), ...tag }, $inc: { ...(u.$inc ?? {}), _v: 1 } };
      const r = await coll.updateMany(scope, update, { session });
      // Verify what landed, not what was sent: only declared fields changed, on exactly these docs.
      const after = await coll.find(scope, { session }).sort({ _id: 1 }).toArray();
      const allowed = new Set([...Object.values(u).flatMap((f: any) => Object.keys(f).map((k) => k.split(".")[0])), "_v", "_cs"]);
      for (let i = 0; i < before.length; i++) {
        const keys = new Set([...Object.keys(before[i]), ...Object.keys(after[i] ?? {})]);
        for (const k of keys) if (!allowed.has(k) && canonical(before[i][k]) !== canonical(after[i]?.[k])) throw new Abort(`verification failed: unexpected change to ${k}`);
      }
      if (r.matchedCount !== ids.length) throw new Abort(`matched ${r.matchedCount}, expected ${ids.length}`);
      result = { matched: r.matchedCount, modified: r.modifiedCount };
    });
    await col.proposals(c).updateOne({ _id: id }, { $set: { status: "applied", result } });
    await append(c, "proposal.applied", "gateway", { result, idsHash: p.dryRun?.idsHash }, id);
  } catch (e: any) {
    if (e instanceof Abort) return fail("failed", e.message);
    throw e;
  } finally {
    await session.endSession();
  }
  return (await col.proposals(c).findOne({ _id: id }))!;
}

// ---------- rollback ----------
export async function rollback(c: Ctx, id: string, humanKey: string | undefined) {
  const human = await authenticate(c, humanKey, "human");
  if (!["approver", "admin"].includes(human.role ?? "")) throw new Denied(`role ${human.role} cannot roll back`);
  const pid = new ObjectId(id);
  const p = await col.proposals(c).findOne({ _id: pid, tenantId: human.tenantId });
  if (!p || p.status !== "applied") throw new Denied("only applied proposals in your tenant can be rolled back");
  const coll = c.data.collection(p.collection);
  const session = c.client.startSession();
  try {
    await session.withTransaction(async () => {
      const images = await col.beforeImages(c).find({ proposalId: pid }, { session }).toArray();
      for (const img of images) {
        const cur = await coll.findOne({ _id: img.docId }, { session });
        // Don't clobber someone else's later change.
        if (cur && cur._cs !== String(pid)) throw new Denied(`record ${img.docId} was changed again after this proposal; refusing to overwrite`);
        if (!img.before) await coll.deleteOne({ _id: img.docId }, { session });
        else await coll.replaceOne({ _id: img.docId }, { ...img.before, _v: (cur?._v ?? img.before._v ?? 0) + 1, _cs: `rollback:${pid}` }, { session, upsert: true });
      }
      await col.proposals(c).updateOne({ _id: pid }, { $set: { status: "rolled_back" } }, { session });
    });
  } finally {
    await session.endSession();
  }
  await append(c, "proposal.rolled_back", human._id, {}, pid);
  return col.proposals(c).findOne({ _id: pid });
}

// ---------- read ----------
const readBudget = new Map<string, number>();
const READ_BUDGET = Number(process.env.READ_BUDGET ?? 500);

export async function read(c: Ctx, s: Session, collection: string, filter?: Document, pipeline?: Document[], limit?: number) {
  const pl = buildReadPipeline(s.tenantId, collection, (n) => !!s.rule(n)?.read, filter, pipeline, limit);
  const key = `${s.agent._id}|${s.human._id}`;
  const used = readBudget.get(key) ?? 0;
  if (used >= READ_BUDGET) throw new Denied(`read budget exhausted (${READ_BUDGET} records per session)`);
  const docs = await c.data.collection(collection).aggregate(pl).toArray();
  readBudget.set(key, used + docs.length);

  const grants = await col.grants(c).find({ tenantId: s.tenantId, humanId: s.human._id, expiresAt: { $gt: new Date() } }).toArray();
  const unmasked = new Set(grants.map((g) => g.field));
  const masked = new Set(s.policy.rules.flatMap((r) => r.maskedFields).filter((f) => !unmasked.has(f)));
  const scrub = (v: any): any =>
    Array.isArray(v) ? v.map(scrub)
    : v && typeof v === "object" && v.constructor === Object
      ? Object.fromEntries(Object.entries(v).filter(([k]) => k !== "_cs").map(([k, x]) => [k, masked.has(k) ? "***" : scrub(x)]))
      : v;
  await append(c, "data.read", s.agent._id, { onBehalfOf: s.human._id, collection, returned: docs.length, unmasked: [...unmasked] });
  return docs.map(scrub);
}

// Time-limited unmask. Expires by TTL index; nothing to clean up.
export async function grantUnmask(c: Ctx, humanKey: string | undefined, field: string, reason: string, minutes = 15) {
  const human = await authenticate(c, humanKey, "human");
  if (!reason?.trim()) throw new Denied("a reason (e.g. case number) is required");
  const g = { tenantId: human.tenantId, humanId: human._id, field, reason, expiresAt: new Date(Date.now() + minutes * 60_000) };
  await col.grants(c).insertOne(g);
  await append(c, "grant.unmask", human._id, { field, reason, minutes });
  return g;
}
