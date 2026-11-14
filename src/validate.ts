// Query validator. Owner: Fares. Pure functions: throw Denied with a reason, never touch the DB.
import type { Document } from "mongodb";
import type { ChangeRequest, Rule } from "./types.js";

export class Denied extends Error {}
const deny = (msg: string): never => { throw new Denied(msg); };

// Server-side JS and writes-hidden-in-reads, anywhere in the tree.
const BANNED = new Set(["$where", "$function", "$accumulator", "$out", "$merge"]);
const READ_STAGES = new Set(["$match", "$project", "$sort", "$limit", "$skip", "$group", "$count", "$unwind", "$lookup", "$addFields", "$set"]);
const UPDATE_OPS = new Set(["$set", "$inc", "$unset"]);
const RESERVED = new Set(["_id", "tenantId", "_v", "_cs"]); // gateway-owned fields

export function scanBanned(v: unknown, path = "") {
  if (Array.isArray(v)) return v.forEach((x, i) => scanBanned(x, `${path}[${i}]`));
  if (v && typeof v === "object" && v.constructor === Object) {
    for (const [k, x] of Object.entries(v)) {
      if (BANNED.has(k)) deny(`operator ${k} is not allowed (${path || "root"})`);
      scanBanned(x, path ? `${path}.${k}` : k);
    }
  }
}

const top = (field: string) => field.split(".")[0];

export function validateChange(req: ChangeRequest, rule: Rule | undefined) {
  if (!rule) deny(`no write access to collection "${req.collection}"`);
  if (!rule!.ops.includes(req.op)) deny(`${req.op} not allowed on ${req.collection}`);
  if (!Number.isInteger(req.expectedCount) || req.expectedCount < 1) deny("expectedCount must be a positive integer");
  if (!req.reason?.trim()) deny("reason is required");

  if (req.op === "insertOne") {
    if (!req.document || typeof req.document !== "object") deny("insertOne needs a document");
    if (req.expectedCount !== 1) deny("insertOne expectedCount must be 1");
    scanBanned(req.document);
    for (const k of Object.keys(req.document!)) {
      if (k.startsWith("$") || RESERVED.has(k)) deny(`field ${k} is reserved`);
      if (!rule!.writableFields.includes(top(k))) deny(`field ${k} is not writable`);
    }
    return;
  }

  // update/delete: a filter that matches everything is the #1 way agents wipe tables.
  if (!req.filter || Object.keys(req.filter).length === 0) deny("empty filter: refusing to touch every record");
  scanBanned(req.filter);
  if (req.op.startsWith("delete")) return;

  if (!req.update || Object.keys(req.update).length === 0) deny("update is required");
  for (const [op, fields] of Object.entries(req.update!)) {
    if (!UPDATE_OPS.has(op)) deny(`update operator ${op} not allowed (use $set/$inc/$unset)`);
    if (!fields || typeof fields !== "object") deny(`${op} needs an object`);
    scanBanned(fields);
    for (const f of Object.keys(fields)) {
      if (RESERVED.has(top(f))) deny(`field ${f} is reserved`);
      if (!rule!.writableFields.includes(top(f))) deny(`field ${f} is not writable`);
    }
  }
}

// Reads: find filter or a restricted aggregation pipeline. Returns the pipeline with tenant
// isolation injected into the root AND every $lookup, so a join can't reach another tenant.
export function buildReadPipeline(tenantId: string, collection: string, readable: (c: string) => boolean, filter: Document = {}, pipeline: Document[] = [], limit = 50): Document[] {
  if (!readable(collection)) deny(`no read access to "${collection}"`);
  scanBanned(filter);
  scanBanned(pipeline);
  const out: Document[] = [{ $match: { $and: [{ tenantId }, filter] } }];
  for (const stage of pipeline) {
    const keys = Object.keys(stage);
    if (keys.length !== 1) deny("each pipeline stage must have exactly one operator");
    const k = keys[0];
    if (!READ_STAGES.has(k)) deny(`stage ${k} is not allowed`);
    if (k === "$lookup") {
      const l = stage.$lookup;
      if (!readable(l.from)) deny(`$lookup into "${l.from}" is not allowed`);
      const inner = l.pipeline ?? [];
      // Recurse so nested lookups get validated and tenant-scoped too.
      const scoped = buildReadPipeline(tenantId, l.from, readable, {}, inner, 1000);
      const { localField, foreignField, ...rest } = l;
      const lookup: Document = { ...rest, pipeline: scoped.slice(0, -1) };
      if (localField) Object.assign(lookup, { localField, foreignField });
      out.push({ $lookup: lookup });
    } else out.push(stage);
  }
  out.push({ $limit: Math.min(Math.max(1, limit), 200) });
  return out;
}
