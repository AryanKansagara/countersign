// End-to-end check against a throwaway replica set (transactions + change streams need one).
// Uses MONGODB_URI instead if set.
import assert from "node:assert/strict";
import { MongoMemoryReplSet } from "mongodb-memory-server";
import { printScoreboard, runAttacks } from "../attacks/run.js";
import { col, connect } from "../src/db.js";
import { approve, grantUnmask, propose, read, rollback } from "../src/gateway.js";
import { verifyChain } from "../src/ledger.js";
import { resolveSession } from "../src/policy.js";
import { KEYS, seed } from "../src/seed.js";
import { claim, decide, requestAgentKey, revoke } from "../src/auth.js";

const rs = process.env.MONGODB_URI ? null : await MongoMemoryReplSet.create({ replSet: { count: 1, storageEngine: "wiredTiger" } });
const c = await connect(process.env.MONGODB_URI ?? rs!.getUri());
process.env.DATA_DB ??= "bank";
await seed(c);
const s = () => resolveSession(c, KEYS.maple.agent, KEYS.maple.alice);

// Low-risk change runs on its own.
let p = await propose(c, await s(), { collection: "customers", op: "updateOne", filter: { customerNo: "MAPLE-1001" }, update: { $set: { tier: "plus" } }, expectedCount: 1, reason: "customer upgraded" });
assert.equal(p.status, "applied", JSON.stringify(p.risk));

// Reads are tenant-scoped and masked; a reasoned, time-limited grant unmasks.
let rows = await read(c, await s(), "customers", { region: "ON" });
assert.ok(rows.length > 0 && rows.every((r) => r.tenantId === "maple" && r.email === "***"));
await grantUnmask(c, KEYS.maple.alice, "email", "case #4411", 5);
rows = await read(c, await s(), "customers", { customerNo: "MAPLE-1001" });
assert.match(rows[0].email, /@example\.com/);

// Bulk change waits for a human, then applies, then rolls back cleanly.
p = await propose(c, await s(), { collection: "leads", op: "updateMany", filter: { status: "cold" }, update: { $set: { owner: "alice" } }, expectedCount: 12, reason: "assign stale leads" });
assert.equal(p.status, "pending");
p = await approve(c, String(p._id), KEYS.maple.bob);
assert.equal(p.status, "applied");
assert.equal(await c.data.collection("leads").countDocuments({ tenantId: "maple", owner: "alice" }), 12);
await rollback(c, String(p._id), KEYS.maple.bob);
assert.equal(await c.data.collection("leads").countDocuments({ tenantId: "maple", owner: "alice" }), 0);
assert.equal(await c.data.collection("leads").countDocuments({ tenantId: "north", owner: "alice" }), 0);

// Refund over $100 needs approval; under doesn't.
p = await propose(c, await s(), { collection: "transactions", op: "insertOne", document: { customerId: "MAPLE-1003", type: "refund", amount: 40, memo: "fee reversal" }, expectedCount: 1, reason: "fee reversal" });
assert.equal(p.status, "applied");
p = await propose(c, await s(), { collection: "transactions", op: "insertOne", document: { customerId: "MAPLE-1003", type: "refund", amount: 400, memo: "x" }, expectedCount: 1, reason: "big refund" });
assert.equal(p.status, "pending");

// Key self-service: request -> no self-approval -> approve -> claim once -> works -> revoke -> dead.
const kr = await requestAgentKey(c, KEYS.maple.alice, "report-bot", ["customers"], "monthly reports");
await assert.rejects(decide(c, KEYS.maple.alice, String(kr._id), true), /cannot approve|self/);
await decide(c, KEYS.maple.bob, String(kr._id), true);
const got = await claim(c, "human:maple:alice", String(kr._id));
await assert.rejects(claim(c, "human:maple:alice", String(kr._id)), /nothing to claim/);
const rs2 = await resolveSession(c, got.key, KEYS.maple.alice);
assert.equal(rs2.rule("customers")?.collection, "customers");
assert.equal(rs2.rule("leads"), undefined); // scoped to what was approved
await revoke(c, KEYS.maple.bob, got.identity);
await assert.rejects(resolveSession(c, got.key, KEYS.maple.alice), /revoked/);

assert.deepEqual((await verifyChain(c)).ok, true);

// Kill switch stops new calls immediately.
await col.settings(c).updateOne({ _id: "killswitch" as any }, { $addToSet: { tenants: "maple" } });
await assert.rejects(s(), /kill switch/);

const scoreboard = await runAttacks(c);
printScoreboard(scoreboard);
assert.ok(scoreboard.every((r) => r.blocked), "every attack must be blocked");

console.log("\nselftest: all good");
await c.client.close();
await rs?.stop();
