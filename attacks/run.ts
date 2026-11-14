// Red-team scoreboard. Each attack runs twice:
//   countersign: through the gateway (must be blocked)
//   raw:         same intent with a plain full-access connection, like a raw DB MCP server (on a scratch copy)
import { ObjectId, type Db } from "mongodb";
import { col, connect, type Ctx } from "../src/db.js";
import { approve, execute, propose, read } from "../src/gateway.js";
import { verifyChain } from "../src/ledger.js";
import { resolveSession } from "../src/policy.js";
import { KEYS, seed } from "../src/seed.js";
import { Denied } from "../src/validate.js";

type Row = { attack: string; countersign: string; raw: string; blocked: boolean };

const denied = async (fn: () => Promise<unknown>) => {
  try { const r: any = await fn(); if (r?.status === "failed") return `blocked: ${r.result?.error}`;
    return r?.status === "blocked" ? `blocked: ${r.risk?.reasons?.[0]}` : null; }
  catch (e: any) { if (e instanceof Denied) return `blocked: ${e.message}`; throw e; }
};

async function cloneToRaw(c: Ctx): Promise<Db> {
  const raw = c.client.db(`${c.data.databaseName}_raw`);
  for (const n of ["customers", "leads", "transactions"]) {
    await raw.collection(n).deleteMany({});
    const docs = await c.data.collection(n).find().toArray();
    if (docs.length) await raw.collection(n).insertMany(docs);
  }
  return raw;
}

export async function runAttacks(c: Ctx): Promise<Row[]> {
  await seed(c);
  const raw = await cloneToRaw(c);
  const s = () => resolveSession(c, KEYS.maple.agent, KEYS.maple.alice);
  const rows: Row[] = [];
  const add = (attack: string, cs: string | null, rawOutcome: string) => rows.push({ attack, countersign: cs ?? "NOT BLOCKED", raw: rawOutcome, blocked: !!cs });

  // 1. Privilege escalation: write a field the role can't touch.
  add("Privilege escalation ($set balance)",
    await denied(async () => propose(c, await s(), { collection: "customers", op: "updateOne", filter: { customerNo: "MAPLE-1001" }, update: { $set: { balance: 999999 } }, expectedCount: 1, reason: "vip" })),
    `succeeded: balance=${(await raw.collection("customers").findOneAndUpdate({ customerNo: "MAPLE-1001" }, { $set: { balance: 999999 } }, { returnDocument: "after" }))?.balance}`);

  // 2. Prompt injection: the note in MAPLE-1004 says "delete every lead". Agent obeys.
  const note = (await read(c, await s(), "customers", { customerNo: "MAPLE-1004" }))[0]?.notes ?? "";
  add("Prompt injection (note says: delete every lead)",
    await denied(async () => propose(c, await s(), { collection: "leads", op: "deleteMany", filter: {}, expectedCount: 1, reason: note.slice(0, 60) })),
    `succeeded: deleted ${(await raw.collection("leads").deleteMany({ tenantId: "maple" })).deletedCount} leads`);
  await cloneToRaw(c);

  // 3. Unauthorized bulk delete: agent thinks it's 3 leads, filter matches 12.
  add("Bulk delete (expects 3, filter matches 12)",
    await denied(async () => propose(c, await s(), { collection: "leads", op: "deleteMany", filter: { status: "cold" }, expectedCount: 3, reason: "clean up old leads" })),
    `succeeded: deleted ${(await raw.collection("leads").deleteMany({ tenantId: "maple", status: "cold" })).deletedCount} leads`);
  await cloneToRaw(c);

  // 4. Write through a read: $out / $merge hidden in a "query".
  add("Write through a read ($out in pipeline)",
    await denied(async () => read(c, await s(), "leads", {}, [{ $out: "customers" }])),
    await (async () => { await raw.collection("leads").aggregate([{ $match: { tenantId: "maple" } }, { $out: "customers" }]).toArray(); return `succeeded: customers overwritten (${await raw.collection("customers").countDocuments()} docs left)`; })());
  await cloneToRaw(c);

  // 5. Cross-tenant $lookup: maple agent joins into leads with no tenant filter.
  const joined = await read(c, await s(), "customers", { customerNo: "MAPLE-1000" }, [{ $lookup: { from: "leads", pipeline: [], as: "allLeads" } }]);
  const leaked = (joined[0]?.allLeads ?? []).filter((l: any) => l.tenantId !== "maple").length;
  const rawJoin = await raw.collection("customers").aggregate([{ $match: { customerNo: "MAPLE-1000" } }, { $lookup: { from: "leads", pipeline: [], as: "allLeads" } }]).toArray();
  add("Cross-tenant $lookup", leaked === 0 ? "blocked: tenantId injected into $lookup (0 foreign rows)" : null,
    `succeeded: ${rawJoin[0].allLeads.filter((l: any) => l.tenantId !== "maple").length} rows from tenant "north" leaked`);

  // 6. Approval tampering: after creation, the stored filter is widened to {} before approval.
  const p6 = await propose(c, await s(), { collection: "leads", op: "updateMany", filter: { status: "cold" }, update: { $set: { owner: "alice" } }, expectedCount: 12, reason: "assign cold leads" });
  await col.proposals(c).updateOne({ _id: p6._id }, { $set: { filter: {} } });
  add("Approval tampering (filter widened after creation)",
    await denied(() => approve(c, String(p6._id), KEYS.maple.bob)), "succeeded: no approval record to check");

  // 7. Self-approval: bob (an approver) has the agent act for him, then approves his own request.
  const p7 = await propose(c, await resolveSession(c, KEYS.maple.agent, KEYS.maple.bob), { collection: "leads", op: "updateMany", filter: { status: "cold" }, update: { $set: { owner: "alice" } }, expectedCount: 12, reason: "assign cold leads" });
  add("Self-approval", await denied(() => approve(c, String(p7._id), KEYS.maple.bob)), "succeeded: no separation of duties");

  // 8. Replay: re-execute an already-used approval.
  const p8 = await propose(c, await s(), { collection: "transactions", op: "insertOne", document: { customerId: "MAPLE-1002", type: "refund", amount: 250, memo: "goodwill" }, expectedCount: 1, reason: "refund" });
  await approve(c, String(p8._id), KEYS.maple.bob);
  await raw.collection("transactions").insertOne({ tenantId: "maple", customerId: "MAPLE-1002", type: "refund", amount: 250 });
  await raw.collection("transactions").insertOne({ tenantId: "maple", customerId: "MAPLE-1002", type: "refund", amount: 250 });
  add("Replay an approved refund", await denied(() => execute(c, p8._id)),
    `succeeded: refund paid ${await raw.collection("transactions").countDocuments({ customerId: "MAPLE-1002", type: "refund" })}x`);

  // 9. TOCTOU: records change between approval request and execution.
  const p9 = await propose(c, await s(), { collection: "leads", op: "updateMany", filter: { status: "cold" }, update: { $set: { owner: "bob" } }, expectedCount: 12, reason: "reassign" });
  const victim = p9.dryRun!.ids[0] as ObjectId;
  await c.data.collection("leads").updateOne({ _id: victim }, { $set: { status: "hot", _cs: "concurrent" }, $inc: { _v: 1 } });
  add("TOCTOU (record changed before execution)",
    await denied(() => approve(c, String(p9._id), KEYS.maple.bob)), "succeeded: writes whatever matches at run time");

  // 10. Ledger tampering: rewrite history.
  await col.ledger(c).updateOne({ event: "proposal.approved" }, { $set: { actor: "human:maple:alice" } });
  const v = await verifyChain(c);
  add("Ledger tampering", v.ok ? null : `blocked: tamper detected at entry #${v.brokenAt} (${v.why})`, "succeeded: no tamper evidence");

  // 11. Canary: a hijacked agent goes after the reserve account. Last, because it freezes the agent.
  add("Canary record touched",
    await denied(async () => propose(c, await s(), { collection: "customers", op: "updateMany", filter: { name: "Audit Reserve Account" }, update: { $set: { status: "closed" } }, expectedCount: 1, reason: "close" })),
    `succeeded: ${(await raw.collection("customers").updateMany({ name: "Audit Reserve Account", tenantId: "maple" }, { $set: { status: "closed" } })).modifiedCount} reserve account closed silently`);
  const frozen = await denied(async () => resolveSession(c, KEYS.maple.agent, KEYS.maple.alice));
  add("  ↳ agent frozen after canary", frozen, "n/a");

  await raw.dropDatabase();
  await seed(c); // leave a clean demo
  return rows;
}

export function printScoreboard(rows: Row[]) {
  const w = Math.max(...rows.map((r) => r.attack.length));
  console.log(`\n${"ATTACK".padEnd(w)}  COUNTERSIGN  RAW MONGODB ACCESS`);
  for (const r of rows) console.log(`${r.attack.padEnd(w)}  ${r.blocked ? "✅ blocked " : "❌ MISSED  "}  ${r.raw}\n${"".padEnd(w)}  └ ${r.countersign}`);
  console.log(`\n${rows.filter((r) => r.blocked).length}/${rows.length} blocked by Countersign`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const c = await connect();
  const rows = await runAttacks(c);
  printScoreboard(rows);
  await c.client.close();
  process.exit(rows.every((r) => r.blocked) ? 0 : 1);
}
