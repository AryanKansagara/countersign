import { MongoClient, type Db, type Document } from "mongodb";
import type { Identity, Policy, Proposal } from "./types.js";

export interface Ctx {
  client: MongoClient;
  cs: Db;    // countersign control plane
  data: Db;  // the governed business data
}

export async function connect(uri = process.env.MONGODB_URI): Promise<Ctx> {
  if (!uri) throw new Error("MONGODB_URI is not set");
  const client = await new MongoClient(uri, { appName: "countersign" }).connect();
  return {
    client,
    cs: client.db(process.env.CS_DB ?? "countersign"),
    data: client.db(process.env.DATA_DB ?? "bank"),
  };
}

export const col = {
  identities: (c: Ctx) => c.cs.collection<Identity>("identities"),
  policies: (c: Ctx) => c.cs.collection<Policy>("policies"),
  proposals: (c: Ctx) => c.cs.collection<Proposal>("proposals"),
  ledger: (c: Ctx) => c.cs.collection<Document>("ledger"),
  beforeImages: (c: Ctx) => c.cs.collection<Document>("before_images"),
  grants: (c: Ctx) => c.cs.collection<Document>("grants"),
  settings: (c: Ctx) => c.cs.collection<Document>("settings"),
};

// Idempotent: schema validation + indexes. Run on every boot.
export async function setup(c: Ctx) {
  try { await setupUnsafe(c); }
  catch (e: any) {
    // The runtime gateway user (countersignGateway role) can't change schemas — by design. Admin runs setup via seed.
    if (e?.code === 13 || e?.codeName === "Unauthorized") return console.error("setup skipped: runtime user lacks DDL rights (expected)");
    throw e;
  }
}

async function setupUnsafe(c: Ctx) {
  const existing = new Set((await c.cs.listCollections().toArray()).map((x) => x.name));
  const ensure = async (name: string, validator?: Document) => {
    if (!existing.has(name)) await c.cs.createCollection(name, validator ? { validator } : {});
    else if (validator) await c.cs.command({ collMod: name, validator });
  };

  // Ledger entries can't be written half-formed.
  await ensure("ledger", {
    $jsonSchema: {
      bsonType: "object",
      required: ["seq", "at", "event", "actor", "prevHash", "hash"],
      properties: {
        seq: { bsonType: ["int", "long"] },
        at: { bsonType: "date" },
        event: { bsonType: "string" },
        actor: { bsonType: "string" },
        prevHash: { bsonType: "string" },
        hash: { bsonType: "string", minLength: 64, maxLength: 64 },
      },
    },
  });
  // Every identity must have an owner tenant and a key.
  await ensure("identities", {
    $jsonSchema: {
      bsonType: "object",
      required: ["_id", "kind", "tenantId", "keyHash"],
      properties: { kind: { enum: ["agent", "human"] } },
    },
  });
  for (const n of ["policies", "proposals", "before_images", "grants", "settings"]) await ensure(n);

  await col.ledger(c).createIndex({ seq: 1 }, { unique: true });
  await col.ledger(c).createIndex({ proposalId: 1 });
  await col.proposals(c).createIndex({ tenantId: 1, status: 1, createdAt: -1 });
  await col.identities(c).createIndex({ keyHash: 1 }, { unique: true });
  await col.beforeImages(c).createIndex({ proposalId: 1 });
  await col.grants(c).createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // TTL: grants vanish on their own
}
