// HTTP: approval inbox + API, remote MCP endpoint, and the change-stream watchdog.
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { ObjectId, type Document } from "mongodb";
import { col, connect, setup, type Ctx } from "./db.js";
import { approve, grantUnmask, reject, rollback } from "./gateway.js";
import { embed, ensureVectorIndex, similar } from "./embed.js";
import { append, verifyChain } from "./ledger.js";
import { buildServer } from "./mcp.js";
import { authenticate, type Who } from "./policy.js";
import { claim, decide, githubAuthorizeUrl, githubConfigured, githubLogin, listRequests, makeCookie, readCookie, requestAgentKey, requestMembership, revoke } from "./auth.js";
import { Denied } from "./validate.js";

const c = await connect();
await setup(c);
await ensureVectorIndex(c);

// ---- live events to the inbox (Server-Sent Events fed by change streams) ----
const clients = new Set<ServerResponse>();
const broadcast = (type: string, data: unknown) => {
  const msg = `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const r of clients) r.write(msg);
};
col.ledger(c).watch([{ $match: { operationType: "insert" } }]).on("change", (e: any) => broadcast("ledger", e.fullDocument)).on("error", console.error);

// ---- watchdog: any write to business data that didn't come through Countersign is an alarm ----
c.data.watch([], { fullDocument: "updateLookup" }).on("change", async (e: any) => {
  try {
    if (!["insert", "update", "replace", "delete"].includes(e.operationType)) return;
    const coll = e.ns.coll;
    let governed: boolean;
    if (e.operationType === "delete") governed = !!(await col.beforeImages(c).findOne({ docId: e.documentKey._id }));
    else if (e.operationType === "update") governed = "_cs" in (e.updateDescription?.updatedFields ?? {});
    // ponytail: _cs tag is forgeable by someone holding raw creds; least-privilege DB roles are the real wall, this is the tripwire.
    else governed = !!e.fullDocument?._cs;
    if (!governed && !(await isSeeding())) {
      await append(c, "alarm.ungoverned_write", "watchdog", { collection: coll, op: e.operationType, docId: String(e.documentKey._id) });
    }
  } catch (err) { console.error("watchdog", err); }
}).on("error", console.error);
const isSeeding = async () => !!(await col.settings(c).findOne({ _id: "seeding" as any, until: { $gt: new Date() } }));

// ---- helpers ----
const send = (res: ServerResponse, code: number, body: unknown) => {
  res.writeHead(code, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
};
const body = async (req: IncomingMessage): Promise<any> => {
  let s = "";
  for await (const chunk of req) s += chunk;
  return s ? JSON.parse(s) : {};
};
// Header key (API/demo) wins; otherwise a signed GitHub session cookie.
const session = (req: IncomingMessage) => readCookie(req.headers.cookie);
const key = (req: IncomingMessage): Who => {
  const h = req.headers["x-human-key"] as string | undefined;
  if (h) return h;
  const s = session(req);
  return s?.id ? { id: s.id } : undefined;
};
const redirect = (res: ServerResponse, to: string, cookie?: string) => {
  res.writeHead(302, { location: to, ...(cookie ? { "set-cookie": cookie } : {}) });
  res.end();
};

// Show the approver what will change: before/after for the records the dry run found.
function applyLocally(doc: Document, u: Document = {}) {
  const out = { ...doc };
  for (const [k, v] of Object.entries(u.$set ?? {})) out[k] = v;
  for (const [k, v] of Object.entries(u.$inc ?? {})) out[k] = (out[k] ?? 0) + (v as number);
  for (const k of Object.keys(u.$unset ?? {})) delete out[k];
  return out;
}

async function detail(id: string, tenantId: string) {
  const p = await col.proposals(c).findOne({ _id: new ObjectId(id), tenantId });
  if (!p) throw new Denied("no such proposal");
  const ids = (p.dryRun?.ids ?? []).slice(0, 25);
  const docs = await c.data.collection(p.collection).find({ _id: { $in: ids } }).toArray();
  const strip = ({ _cs, _v, tenantId: _t, sin, dob, ...rest }: Document) => rest;
  const diff = p.op === "insertOne" ? [{ before: null, after: p.document }]
    : docs.map((d) => ({ before: strip(d), after: p.op.startsWith("delete") ? null : strip(applyLocally(d, p.update)) }));
  const ledger = await col.ledger(c).find({ proposalId: p._id }).sort({ seq: 1 }).toArray();
  const { embedding: _e, ...pub } = p;
  return { proposal: { ...pub, dryRun: { matched: p.dryRun?.ids.length ?? 0, idsHash: p.dryRun?.idsHash } }, diff, ledger };
}

// ---- routes ----
createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", "http://x");
  const [, a, b, id, action] = url.pathname.split("/");
  try {
    if (url.pathname === "/" || url.pathname === "/index.html") {
      res.writeHead(200, { "content-type": "text/html" });
      return res.end(await readFile(new URL("../public/index.html", import.meta.url)));
    }
    if (url.pathname === "/health") return send(res, 200, { ok: true });

    // Remote MCP: point any MCP client here with x-agent-key / x-human-key headers.
    if (url.pathname === "/mcp") {
      const server = buildServer(c, req.headers["x-agent-key"] as string, req.headers["x-human-key"] as string);
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      res.on("close", () => { transport.close(); server.close(); });
      await server.connect(transport);
      return transport.handleRequest(req, res, req.method === "POST" ? await body(req) : undefined);
    }

    // ---- GitHub sign-in ----
    if (url.pathname === "/auth/github") {
      if (!githubConfigured()) return send(res, 503, { error: "GitHub sign-in is not configured" });
      const state = randomBytes(16).toString("hex");
      return redirect(res, githubAuthorizeUrl(state), `cs_oauth_state=${state}; Path=/auth; HttpOnly; SameSite=Lax; Secure; Max-Age=600`);
    }
    if (url.pathname === "/auth/github/callback") {
      const want = req.headers.cookie?.match(/cs_oauth_state=([a-f0-9]+)/)?.[1];
      if (!want || want !== url.searchParams.get("state")) throw new Denied("sign-in state mismatch; try again");
      const s = await githubLogin(c, url.searchParams.get("code") ?? "");
      return redirect(res, "/", makeCookie({ gh: s.gh, id: s.id }));
    }
    if (url.pathname === "/auth/logout") return redirect(res, "/", "cs_session=; Path=/; Max-Age=0");
    if (url.pathname === "/auth/me") {
      const s = session(req);
      let idn = s?.id ? await col.identities(c).findOne({ _id: s.id }) : null;
      // Membership approved since you signed in: upgrade the session in place.
      if (s && !idn) idn = await col.identities(c).findOne({ kind: "human", github: s.gh } as any);
      if (s && idn && !s.id) res.setHeader("set-cookie", makeCookie({ gh: s.gh, id: idn._id }));
      return send(res, 200, { github: githubConfigured(), signedIn: !!s, gh: s?.gh ?? null, id: idn?._id ?? null, role: idn?.role ?? null, tenantId: idn?.tenantId ?? null });
    }
    // Signed in with GitHub but not a member yet: the only thing you can do is ask.
    if (url.pathname === "/api/requests/membership" && req.method === "POST") {
      const s = session(req);
      if (!s) throw new Denied("sign in with GitHub first");
      const { tenantId, role, reason } = await body(req);
      return send(res, 200, await requestMembership(c, s.gh, tenantId, role, reason));
    }
    if (url.pathname === "/api/requests/mine") {
      const s = session(req);
      const k = key(req);
      const me = k ? (await authenticate(c, k, "human"))._id : s ? `gh:${s.gh}` : null;
      if (!me) throw new Denied("sign in first");
      const ghReq = s ? `gh:${s.gh}` : "__none__";
      return send(res, 200, await listRequests(c, { requester: { $in: [me, ghReq] } }));
    }
    if (url.pathname.startsWith("/api/requests/") && url.pathname.endsWith("/claim") && req.method === "POST") {
      const s = session(req);
      const k = key(req);
      const me = k ? (await authenticate(c, k, "human"))._id : s ? `gh:${s.gh}` : null;
      if (!me) throw new Denied("sign in first");
      const rid = url.pathname.split("/")[3];
      try { return send(res, 200, await claim(c, me, rid)); }
      catch (e) { if (s && me !== `gh:${s.gh}`) return send(res, 200, await claim(c, `gh:${s.gh}`, rid)); throw e; }
    }

    if (url.pathname === "/api/events") {
      const qk = url.searchParams.get("key");
      await authenticate(c, qk || key(req), "human");
      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" });
      res.write(": hello\n\n");
      clients.add(res);
      return req.on("close", () => clients.delete(res));
    }

    if (a !== "api") return send(res, 404, { error: "not found" });
    const human = await authenticate(c, key(req), "human");

    if (b === "me") return send(res, 200, { id: human._id, role: human.role, tenantId: human.tenantId });

    // ---- keys: request, approve, revoke ----
    if (b === "requests" && !id && req.method === "GET") return send(res, 200, await listRequests(c, { tenantId: human.tenantId }));
    if (b === "requests" && id === "agent" && req.method === "POST") {
      const { name, scopes, reason } = await body(req);
      return send(res, 200, await requestAgentKey(c, key(req), name, scopes, reason));
    }
    if (b === "requests" && id && req.method === "POST" && (action === "approve" || action === "reject"))
      return send(res, 200, await decide(c, key(req), id, action === "approve"));
    if (b === "identities" && !id) {
      const revoked = new Set(((await col.settings(c).findOne({ _id: "revoked" as any }))?.ids ?? []) as string[]);
      const ids = await col.identities(c).find({ tenantId: human.tenantId }, { projection: { keyHash: 0 } }).toArray();
      return send(res, 200, ids.map((i) => ({ ...i, revoked: revoked.has(i._id) })));
    }
    if (b === "identities" && id && action === "revoke" && req.method === "POST") return send(res, 200, await revoke(c, key(req), decodeURIComponent(id)));
    if (b === "proposals" && !id) {
      const list = await col.proposals(c).find({ tenantId: human.tenantId }).sort({ createdAt: -1 }).limit(100).toArray();
      return send(res, 200, list.map((p) => ({ _id: p._id, status: p.status, op: p.op, collection: p.collection, risk: p.risk, reason: p.reason, agentId: p.agentId, onBehalfOf: p.onBehalfOf, matched: p.dryRun?.ids.length ?? 0, expectedCount: p.expectedCount, createdAt: p.createdAt, approvedBy: p.approvedBy, result: p.result })));
    }
    if (b === "proposals" && id && !action) return send(res, 200, await detail(id, human.tenantId));
    if (b === "proposals" && req.method === "POST") {
      if (action === "approve") return send(res, 200, await approve(c, id, key(req)));
      if (action === "reject") return send(res, 200, await reject(c, id, key(req), (await body(req)).why));
      if (action === "rollback") return send(res, 200, await rollback(c, id, key(req)));
    }
    if (b === "search") {
      // Plain-English audit search over every proposal in this tenant (Atlas Vector Search).
      const q = url.searchParams.get("q") ?? "";
      const hits = await similar(c, human.tenantId, await embed(q), ["applied", "pending", "blocked", "failed", "rejected", "rolled_back", "expired"], 10);
      return send(res, 200, hits.map((h) => ({ _id: h._id, score: h.score, status: h.status, op: h.op, collection: h.collection, reason: h.reason, agentId: h.agentId, onBehalfOf: h.onBehalfOf, approvedBy: h.approvedBy, createdAt: h.createdAt })));
    }
    if (b === "ledger" && id === "verify") return send(res, 200, await verifyChain(c));
    if (b === "ledger") return send(res, 200, await col.ledger(c).find().sort({ seq: -1 }).limit(Number(url.searchParams.get("limit") ?? 100)).toArray());
    if (b === "grants" && req.method === "POST") {
      const { field, reason, minutes } = await body(req);
      return send(res, 200, await grantUnmask(c, key(req), field, reason, minutes));
    }
    if (b === "killswitch") {
      if (req.method === "GET") return send(res, 200, await col.settings(c).findOne({ _id: "killswitch" as any }));
      if (!["approver", "admin"].includes(human.role ?? "")) throw new Denied("only approvers can use the kill switch");
      const { on, agent } = await body(req);
      const upd = agent ? { [on ? "$addToSet" : "$pull"]: { agents: agent } } : { [on ? "$addToSet" : "$pull"]: { tenants: human.tenantId } };
      await col.settings(c).updateOne({ _id: "killswitch" as any }, upd as any, { upsert: true });
      await append(c, on ? "killswitch.on" : "killswitch.off", human._id, { agent: agent ?? null, tenant: human.tenantId });
      return send(res, 200, await col.settings(c).findOne({ _id: "killswitch" as any }));
    }
    return send(res, 404, { error: "not found" });
  } catch (e: any) {
    if (e instanceof Denied) return send(res, 403, { denied: e.message });
    if (e instanceof SyntaxError) return send(res, 400, { error: "bad json" });
    console.error(e);
    return send(res, 500, { error: e.message });
  }
}).listen(Number(process.env.PORT ?? 8080), () => console.log(`countersign on :${process.env.PORT ?? 8080}`));
