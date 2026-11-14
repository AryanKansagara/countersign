// Proves the runtime gateway DB user is least-privilege. Run with the GATEWAY uri: node --env-file=.env --import tsx test/privileges.ts
import { connect } from "../src/db.js";
const c = await connect();
const tryIt = async (name: string, fn: () => Promise<unknown>) => { try { await fn(); console.log("ALLOWED ", name); } catch (e: any) { console.log("DENIED  ", name, "-", e.codeName ?? e.message); } };
await tryIt("ledger.updateOne", () => c.cs.collection("ledger").updateOne({}, { $set: { actor: "x" } }));
await tryIt("ledger.deleteOne", () => c.cs.collection("ledger").deleteOne({ seq: 999999 }));
await tryIt("identities.updateOne", () => c.cs.collection("identities").updateOne({ _id: "nope" as any }, { $set: { role: "admin" } }));
await tryIt("policies.updateOne", () => c.cs.collection("policies").updateOne({ _id: "nope" as any }, { $set: { x: 1 } }));
await tryIt("bank.dropDatabase", () => c.data.dropDatabase());
await tryIt("ledger.find", () => c.cs.collection("ledger").findOne());
await c.client.close();
