// Local sentence embeddings (MiniLM, 384 dims). No API key; model is cached after first load.
import { pipeline } from "@huggingface/transformers";
import type { Document } from "mongodb";
import { col, type Ctx } from "./db.js";
import type { ChangeRequest } from "./types.js";

let model: Promise<any> | null = null;
export async function embed(text: string): Promise<number[]> {
  model ??= pipeline("feature-extraction", "Xenova/all-MiniLM-L6-v2");
  const out = await (await model)(text, { pooling: "mean", normalize: true });
  return Array.from(out.data as Float32Array);
}

// What a change *means*, in words: op, target, fields, filter shape, reason.
export const describe = (r: ChangeRequest) =>
  `${r.op} on ${r.collection}; fields ${Object.values(r.update ?? {}).flatMap((f: any) => Object.keys(f ?? {})).concat(Object.keys(r.document ?? {})).join(", ") || "none"}; ` +
  `filter on ${Object.keys(r.filter ?? {}).join(", ") || "none"}; ${r.expectedCount} record(s); reason: ${r.reason}`;

export const VECTOR_INDEX = "proposals_vector";

export async function ensureVectorIndex(c: Ctx) {
  try {
    const have = await col.proposals(c).listSearchIndexes(VECTOR_INDEX).toArray();
    if (have.length) return;
    await col.proposals(c).createSearchIndex({
      name: VECTOR_INDEX, type: "vectorSearch",
      definition: { fields: [
        { type: "vector", path: "embedding", numDimensions: 384, similarity: "cosine" },
        { type: "filter", path: "tenantId" },
        { type: "filter", path: "status" },
      ] },
    });
  } catch (e: any) {
    if (e?.code === 13) return; // runtime user can't manage indexes; seed (admin) creates it
    console.error("vector index unavailable (local test DB?):", e.message);
  }
}

// Nearest past proposals in this tenant. Returns [] where $vectorSearch isn't supported (local tests).
export async function similar(c: Ctx, tenantId: string, vector: number[], statuses: string[], limit = 5): Promise<Document[]> {
  try {
    return await col.proposals(c).aggregate([
      { $vectorSearch: { index: VECTOR_INDEX, path: "embedding", queryVector: vector, numCandidates: 100, limit, filter: { tenantId, status: { $in: statuses } } } },
      { $project: { embedding: 0, score: { $meta: "vectorSearchScore" } } },
    ]).toArray();
  } catch {
    return [];
  }
}
