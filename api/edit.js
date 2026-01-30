import OpenAI, { toFile } from "openai";

export const config = {
  api: { bodyParser: false }
};

// Lock to your domains (prevents other sites using your backend)
const ALLOWED = new Set([
  "https://freshpainters.co.nz",
  "https://www.freshpainters.co.nz",
]);

function setCors(req, res) {
  const origin = req.headers.origin;
  if (!origin) return; // allow server-to-server
  if (ALLOWED.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  }
}

import crypto from "crypto";

function verifyToken(token, secret, maxAgeMs = 1000 * 60 * 60 * 24 * 30) { // 30 days
  try {
    const raw = Buffer.from(token, "base64url").toString("utf8");
    const [email, ts, h] = raw.split("|");
    if (!email || !ts || !h) return null;

    const age = Date.now() - Number(ts);
    if (!Number.isFinite(age) || age < 0 || age > maxAgeMs) return null;

    const msg = `${email}|${ts}`;
    const expected = crypto.createHmac("sha256", secret).update(msg).digest("hex");
    if (expected !== h) return null;

    return email;
  } catch {
    return null;
  }
}

// Tiny multipart parser for 1 file + fields (no extra libraries)
async function parseMultipart(req) {
  const ct = req.headers["content-type"] || "";
  const m = ct.match(/boundary=(.+)$/);
  if (!m) throw new Error("Missing multipart boundary");
  const boundary = "--" + m[1];

  const chunks = [];
  for await (const c of req) chunks.push(c);
  const buffer = Buffer.concat(chunks);

  const parts = buffer.toString("binary").split(boundary).slice(1, -1);
  const fields = {};
  let file = null;

  for (const p of parts) {
    const part = p.trimStart();
    if (!part) continue;

    const [rawHeaders, rawBody] = part.split("\r\n\r\n");
    if (!rawBody) continue;

    const headers = rawHeaders.split("\r\n");
    const disp = headers.find(h => h.toLowerCase().startsWith("content-disposition"));
    if (!disp) continue;

    const nameMatch = disp.match(/name="([^"]+)"/);
    const filenameMatch = disp.match(/filename="([^"]*)"/);

    const bodyBinary = rawBody.slice(0, -2); // drop trailing \r\n
    const bodyBuf = Buffer.from(bodyBinary, "binary");

    const name = nameMatch ? nameMatch[1] : null;

    if (filenameMatch && filenameMatch[1]) {
      const typeHeader = headers.find(h => h.toLowerCase().startsWith("content-type"));
      const mime = typeHeader ? typeHeader.split(":")[1].trim() : "application/octet-stream";
      file = { filename: filenameMatch[1], mime, buffer: bodyBuf, field: name };
    } else if (name) {
      fields[name] = bodyBuf.toString("utf8");
    }
  }

  return { fields, file };
}

// Simple in-memory rate limit (per region instance) — good for MVP
const WINDOW_MS = 60 * 60 * 1000; // 1 hour
const MAX = 8; // per IP per hour
const buckets = new Map();

function rateLimit(req, res) {
  const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket.remoteAddress || "unknown";
  const now = Date.now();
  const b = buckets.get(ip) || { start: now, count: 0 };
  if (now - b.start > WINDOW_MS) { b.start = now; b.count = 0; }
  b.count += 1;
  buckets.set(ip, b);
  res.setHeader("X-RateLimit-Limit", String(MAX));
  res.setHeader("X-RateLimit-Remaining", String(Math.max(0, MAX - b.count)));
  return b.count <= MAX;
}

export default async function handler(req, res) {
  try {
    setCors(req, res);

    if (req.method === "OPTIONS") return res.status(200).end();
    if (req.method !== "POST") return res.status(405).json({ error: "Use POST" });

    const secret = process.env.SESSION_SECRET;
if (!secret) return res.status(500).json({ error: "Missing SESSION_SECRET" });

const token = req.headers["x-fp-token"];
const email = verifyToken(token, secret);
if (!email) return res.status(401).json({ error: "Please enter your email to use the generator." });


    if (!rateLimit(req, res)) {
      return res.status(429).json({ error: "Rate limit exceeded. Please try again later." });
    }

    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) return res.status(500).json({ error: "Missing OPENAI_API_KEY on server" });

    const { fields, file } = await parseMultipart(req);

    if (!file?.buffer) return res.status(400).json({ error: "Missing image file" });

    const prompt = (fields.prompt || "").trim();
    if (prompt.length < 3) return res.status(400).json({ error: "Missing prompt" });

    const n = Math.min(3, Math.max(1, Number(fields.n || 1)));
    const size = fields.size || "auto";
    const layout = fields.layout || "high";

    const okMime = ["image/jpeg", "image/png", "image/webp"].includes(file.mime);
    if (!okMime) return res.status(400).json({ error: "Unsupported image type. Use JPG, PNG, or WEBP." });

    const client = new OpenAI({ apiKey });

    // Preserve photo strongly when layout=high
    const preserve = layout === "high";
    const model = preserve ? "gpt-image-1" : "gpt-image-1.5";

    const imageFile = await toFile(file.buffer, file.filename || "upload", { type: file.mime });

    const rsp = await client.images.edit({
      model,
      image: [imageFile],
      prompt,
      n,
      size,
      ...(model === "gpt-image-1" ? { input_fidelity: "high" } : {})
    });

    const images = (rsp.data || []).map(d => `data:image/png;base64,${d.b64_json}`);
    return res.status(200).json({ images, model });
  } catch (err) {
    return res.status(500).json({ error: err?.message || "Server error" });
  }
}
