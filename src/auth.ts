// GitHub sign-in, signed session cookies, and key requests.
// Issuing a credential is itself a reviewed change: someone requests, a different approver approves,
// the key is shown once, and everything lands in the ledger. Identities are insert-only; revocation is a list.
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { ObjectId, type Document } from "mongodb";
import { col, type Ctx } from "./db.js";
import { append, sha256 } from "./ledger.js";
import { authenticate, type Who } from "./policy.js";
import type { Identity } from "./types.js";
import { Denied } from "./validate.js";

const SECRET = process.env.SESSION_SECRET ?? randomBytes(32).toString("hex"); // ponytail: random fallback logs everyone out on restart; set SESSION_SECRET in prod
const ADMINS = (process.env.GITHUB_ADMINS ?? "").toLowerCase().split(",").map((s) => s.trim()).filter(Boolean);
const DEFAULT_TENANT = process.env.GITHUB_ADMIN_TENANT ?? "maple";

// ---------- sessions ----------
export interface SessionCookie { gh: string; id?: string; exp: number }
const sign = (s: string) => createHmac("sha256", SECRET).update(s).digest("base64url");

export function makeCookie(s: Omit<SessionCookie, "exp">, hours = 12) {
  const body = Buffer.from(JSON.stringify({ ...s, exp: Date.now() + hours * 3600_000 })).toString("base64url");
  return `cs_session=${body}.${sign(body)}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=${hours * 3600}`;
}

export function readCookie(header: string | undefined): SessionCookie | null {
  const raw = header?.split(/;\s*/).find((p) => p.startsWith("cs_session="))?.slice(11);
  if (!raw) return null;
  const [body, mac] = raw.split(".");
  if (!body || !mac) return null;
  const want = Buffer.from(sign(body)), got = Buffer.from(mac);
  if (want.length !== got.length || !timingSafeEqual(want, got)) return null;
  const s = JSON.parse(Buffer.from(body, "base64url").toString()) as SessionCookie;
  return s.exp > Date.now() ? s : null;
}

// ---------- GitHub OAuth ----------
export const githubConfigured = () => !!(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET);

export function githubAuthorizeUrl(state: string) {
  const u = new URL("https://github.com/login/oauth/authorize");
  u.searchParams.set("client_id", process.env.GITHUB_CLIENT_ID!);
  u.searchParams.set("redirect_uri", `${process.env.PUBLIC_URL}/auth/github/callback`);
  u.searchParams.set("scope", "read:user");
  u.searchParams.set("state", state);
  return u.toString();
}

export async function githubLogin(c: Ctx, code: string): Promise<SessionCookie> {
  const tok = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST", headers: { accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify({ client_id: process.env.GITHUB_CLIENT_ID, client_secret: process.env.GITHUB_CLIENT_SECRET, code }),
  }).then((r) => r.json());
  if (!tok.access_token) throw new Denied(`GitHub sign-in failed: ${tok.error_description ?? tok.error ?? "no token"}`);
  const user = await fetch("https://api.github.com/user", { headers: { authorization: `Bearer ${tok.access_token}`, "user-agent": "countersign" } }).then((r) => r.json());
  const gh = String(user.login ?? "").toLowerCase();
  if (!gh) throw new Denied("GitHub sign-in failed: no login");

  let id = await col.identities(c).findOne({ kind: "human", github: gh } as any);
  // Bootstrap: configured admins become approvers on first sign-in. Everyone else must request access.
  if (!id && ADMINS.includes(gh)) {
    id = { _id: `human:gh:${gh}`, kind: "human", tenantId: DEFAULT_TENANT, role: "approver", keyHash: sha256(randomBytes(32).toString("hex")), github: gh } as Identity;
    await col.identities(c).insertOne(id);
    await append(c, "identity.bootstrapped", "system", { github: gh, role: "approver", tenant: DEFAULT_TENANT });
  }
  await append(c, "auth.github_login", id?._id ?? `gh:${gh}`, { github: gh, member: !!id });
  return { gh, id: id?._id, exp: 0 };
}

// ---------- key requests ----------
const requests = (c: Ctx) => c.cs.collection<Document>("key_requests");
const newKey = (kind: "agent" | "human") => `cs_${kind}_${randomBytes(24).toString("base64url")}`;

export async function requestMembership(c: Ctx, gh: string, tenantId: string, role: string, reason: string) {
  if (!["support", "approver"].includes(role)) throw new Denied("role must be support or approver");
  if (!(await col.policies(c).findOne({ _id: `${tenantId}:${role}` }))) throw new Denied("unknown tenant/role");
  if (!reason?.trim()) throw new Denied("reason is required");
  if (await col.identities(c).findOne({ kind: "human", github: gh } as any)) throw new Denied("you already have access");
  const r = { kind: "membership", github: gh, requester: `gh:${gh}`, tenantId, role, reason, status: "pending", createdAt: new Date() };
  const { insertedId } = await requests(c).insertOne(r);
  await append(c, "key.requested", `gh:${gh}`, { kind: "membership", tenantId, role, reason });
  return { _id: insertedId, ...r };
}

// An agent key = an agent identity scoped to a subset of what the requesting human may touch.
export async function requestAgentKey(c: Ctx, who: Who, name: string, scopes: string[], reason: string) {
  const human = await authenticate(c, who, "human");
  const policy = await col.policies(c).findOne({ _id: `${human.tenantId}:${human.role}` });
  const allowed = new Set(policy?.rules.map((r) => r.collection));
  if (!/^[a-z0-9-]{3,30}$/.test(name ?? "")) throw new Denied("name: 3-30 chars, a-z 0-9 -");
  if (!scopes?.length || scopes.some((s) => !allowed.has(s))) throw new Denied(`scopes must be a subset of ${[...allowed].join(", ")}`);
  if (!reason?.trim()) throw new Denied("reason is required");
  const r = { kind: "agent", requester: human._id, tenantId: human.tenantId, name, scopes, reason, status: "pending", createdAt: new Date() };
  const { insertedId } = await requests(c).insertOne(r);
  await append(c, "key.requested", human._id, { kind: "agent", name, scopes, reason });
  return { _id: insertedId, ...r };
}

export async function decide(c: Ctx, who: Who, id: string, approveIt: boolean) {
  const approver = await authenticate(c, who, "human");
  if (!["approver", "admin"].includes(approver.role ?? "")) throw new Denied(`role ${approver.role} cannot approve keys`);
  const r = await requests(c).findOne({ _id: new ObjectId(id), tenantId: approver.tenantId, status: "pending" });
  if (!r) throw new Denied("no pending request in your tenant");
  if (r.requester === approver._id || (r.github && r.github === (approver as any).github)) throw new Denied("no self-approval");
  if (!approveIt) {
    await requests(c).updateOne({ _id: r._id, status: "pending" }, { $set: { status: "rejected", decidedBy: approver._id } });
    await append(c, "key.rejected", approver._id, { request: String(r._id) });
    return { status: "rejected" };
  }
  const kind = r.kind === "agent" ? "agent" : "human";
  const key = newKey(kind);
  const identity: Document = kind === "agent"
    ? { _id: `agent:${r.tenantId}:${r.name}-${randomBytes(2).toString("hex")}`, kind, tenantId: r.tenantId, scopes: r.scopes, owner: r.requester, keyHash: sha256(key), createdBy: approver._id }
    : { _id: `human:gh:${r.github}`, kind, tenantId: r.tenantId, role: r.role, github: r.github, keyHash: sha256(key), createdBy: approver._id };
  // Claim the request first so two approvers can't both issue.
  const claimed = await requests(c).updateOne({ _id: r._id, status: "pending" }, { $set: { status: "approved", decidedBy: approver._id, identity: identity._id, issuedKey: key } });
  if (!claimed.modifiedCount) throw new Denied("request already decided");
  await col.identities(c).insertOne(identity as Identity);
  await append(c, "key.issued", approver._id, { request: String(r._id), identity: identity._id, kind, scopes: r.scopes ?? null, role: r.role ?? null });
  return { status: "approved", identity: identity._id };
}

// Show-once: the plaintext key is removed the moment the requester reads it.
export async function claim(c: Ctx, requester: string, id: string) {
  const r = await requests(c).findOneAndUpdate(
    { _id: new ObjectId(id), requester, status: "approved", issuedKey: { $exists: true } },
    { $unset: { issuedKey: "" }, $set: { status: "claimed", claimedAt: new Date() } });
  if (!r) throw new Denied("nothing to claim (already shown once, or not approved yet)");
  await append(c, "key.claimed", requester, { identity: r.identity });
  return { identity: r.identity, key: r.issuedKey, kind: r.kind };
}

export const listRequests = (c: Ctx, filter: Document) =>
  requests(c).find(filter, { projection: { issuedKey: 0 } }).sort({ createdAt: -1 }).limit(50).toArray();

export async function revoke(c: Ctx, who: Who, identityId: string) {
  const approver = await authenticate(c, who, "human");
  if (!["approver", "admin"].includes(approver.role ?? "")) throw new Denied("only approvers can revoke");
  const target = await col.identities(c).findOne({ _id: identityId, tenantId: approver.tenantId });
  if (!target) throw new Denied("no such identity in your tenant");
  if (target._id === approver._id) throw new Denied("you can't revoke yourself");
  await col.settings(c).updateOne({ _id: "revoked" as any }, { $addToSet: { ids: identityId } }, { upsert: true });
  await append(c, "key.revoked", approver._id, { identity: identityId });
  return { revoked: identityId };
}
