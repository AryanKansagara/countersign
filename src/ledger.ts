import { createHash } from "node:crypto";
import { BSON, type Document } from "mongodb";
const { EJSON } = BSON;
import { col, type Ctx } from "./db.js";

export const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

// Deterministic JSON: sorted keys, EJSON for ObjectId/Date. Used for every hash we compute.
export function canonical(v: unknown): string {
  const sort = (x: any): any =>
    Array.isArray(x) ? x.map(sort)
    : x && typeof x === "object" && x.constructor === Object
      ? Object.fromEntries(Object.keys(x).sort().map((k) => [k, sort(x[k])]))
      : x;
  return JSON.stringify(sort(EJSON.serialize(v as Document, { relaxed: false })));
}

const entryHash = (e: Document) =>
  sha256(canonical({ seq: e.seq, at: e.at, event: e.event, actor: e.actor, proposalId: e.proposalId ?? null, data: e.data ?? null, prevHash: e.prevHash }));

// Append-only, hash-chained. Retries if two writers race for the same seq (unique index).
export async function append(c: Ctx, event: string, actor: string, data: Document = {}, proposalId?: unknown) {
  for (let i = 0; i < 20; i++) {
    const last = await col.ledger(c).find().sort({ seq: -1 }).limit(1).next();
    const e: Document = {
      seq: (last?.seq ?? 0) + 1,
      at: new Date(),
      event,
      actor,
      proposalId: proposalId ?? null,
      data,
      prevHash: last?.hash ?? "0".repeat(64),
    };
    e.hash = entryHash(e);
    try {
      await col.ledger(c).insertOne(e);
      return e;
    } catch (err: any) {
      if (err?.code !== 11000) throw err;
    }
  }
  throw new Error("ledger contention");
}

// Walks the chain; returns the first broken seq if anything was edited or deleted.
export async function verifyChain(c: Ctx) {
  let prev = "0".repeat(64);
  let n = 0;
  for await (const e of col.ledger(c).find().sort({ seq: 1 })) {
    n++;
    if (e.seq !== n) return { ok: false, brokenAt: n, why: "missing entry" };
    if (e.prevHash !== prev) return { ok: false, brokenAt: e.seq, why: "prevHash mismatch" };
    if (entryHash(e) !== e.hash) return { ok: false, brokenAt: e.seq, why: "entry modified" };
    prev = e.hash;
  }
  return { ok: true, entries: n };
}
