// Simulates someone writing to business data behind Countersign's back (admin creds). The watchdog should alarm.
import { connect } from "../src/db.js";
const c = await connect();
await c.data.collection("customers").updateOne({ customerNo: "MAPLE-1010" }, { $inc: { balance: 1_000_000 } });
console.log("raw write done");
await c.client.close();
