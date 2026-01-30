import OpenAI, { toFile } from "openai";
import crypto from "crypto";

export const config = {
  api: { bodyParser: false },
};

// ---- CORS: allow only your site(s) ----
const ALLOWED_ORIGINS = new Set([
  "https://freshpainters.co.nz",
  "https://www.freshpainters.co.nz",
  // If you test on a GoDaddy preview URL, add it temporarily, e.g.:
  // "https://YOUR-PREVIEW.godaddysites.com",
]);

function setCors(req, res) {
  const origin = req.headers.origin;
  if (!origin) return;

  if (ALLOWED_ORIGINS.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-FP-Token");
  }
}

// ---- Unlock token verify (email gate) ----
// token = base64url(email|timestamp|hmac_sha256(email|timestamp, secret))
function verifyToken(token, secret, maxAgeMs = 1000 * 60 * 60 * 24 * 30) {
  try {
    if (!token) return null;
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

// ---- Basic rate limit (per-instance memory) ----
const WINDOW_MS = 60 * 60 * 1000; // 1 hour
const MAX_REQ_PER_WINDOW = 8;     // per IP per hour
const buckets = new Map();

function getClientIp(req) {
  const xf = req.headers["x-forwarded-for"];
  if (typeof xf === "string" && xf.length) return xf.split(",")[0].trim();
  return req.socket?.remoteAddress || "unknown";
}

function rateLimit(req, res) {
  const ip = getClientIp(req);
  const now = Date.now();

  const b = buckets.get(ip) || { start: now, count: 0 };
  if (now - b.start > WINDOW_MS) {
    b.start = now;
    b.count = 0;
  }
  b.count += 1;
  buckets.set(ip, b);

  res.setHeader("X-RateLimit-Limit", String(MAX_REQ_PER_WINDOW));
  res.setHeader("X-RateLimit-Remaining", String(Math.max(0, MAX_REQ_PER_WINDOW - b.count)));

  return b.count <= MAX_REQ_PER_WINDOW;
}

// ---- Minimal multipart parser (1 image + text fields) ----
async function parseMultipart(req) {
  const contentType = req.headers["content-type"] || "";
  const match = contentType.match(/boundary=(.+)$/);
  if (!match) throw new Error("Missing multipart boundary");

  const boundary = "--" + match[1];

  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
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
    const disp = headers.find((h) => h.toLowerCase().startsWith("content-disposition"));
    if (!disp) continue;

    const nameMatch = disp.match(/name="([^"]+)"/);
    const filenameMatch = disp.match(/filename="([^"]*)"/);

    const bodyBinary = rawBody.slice(0, -2); // remove trailing \r\n
    const bodyBuf = Buffer.from(bodyBinary, "binary");

    const name = nameMatch ? nameMatch[1] : null;

    if (filenameMatch && filenameMatch[1]) {
      const typeHeader = headers.find((h) => h.toLowerCase().startsWith("content-type"));
      const mime = typeHeader ? typeHeader.split(":")[1].trim() : "application/octet-stream";
      file = { filename: filenameMatch[1], mime, buffer: bodyBuf, field: name };
    } else if (name) {
      fields[name] = bodyBuf.toString("utf8");
    }
  }

  return { fields, file };
}

// ---- Step 1: Turn ANY user prompt into a precise edit plan (Structured Outputs) ----
async function buildEditPlan(openai, userPrompt) {
  // JSON Schema (inner schema object)
  const innerSchema = {
    type: "object",
    additionalProperties: false,
    properties: {
      intent_summary: { type: "string" },
      must_keep: { type: "array", items: { type: "string" } },
      changes: { type: "array", items: { type: "string" } },
      materials_palette: { type: "array", items: { type: "string" } },
      lighting_notes: { type: "string" },
      negative_constraints: { type: "array", items: { type: "string" } },
      final_image_prompt: { type: "string" },
    },
    required: [
      "intent_summary",
      "must_keep",
      "changes",
      "materials_palette",
      "lighting_notes",
      "negative_constraints",
      "final_image_prompt",
    ],
  };

  const instructions = `
You are an expert architectural visualiser and interior/exterior designer.
Convert the user's request into a precise, photorealistic image-edit plan.

Rules:
- Do NOT apply a global filter/color grade. Changes must be localized and tangible (paint, materials, finishes, lighting).
- Preserve camera angle, perspective, and geometry unless the user explicitly asks otherwise.
- Keep it realistic for a real renovation/paint job (no impossible structures).
- Avoid text, logos, watermarks, signage.
- Produce a final_image_prompt that is ready to use in an image-edit model.
Return ONLY JSON matching the schema.
`.trim();

  const model = process.env.TEXT_MODEL || "gpt-5";

  // IMPORTANT: Responses API now uses text.format (not response_format)
  const resp = await openai.responses.create({
    model,
    reasoning: { effort: "low" },
    instructions,
    input: `User request:\n${userPrompt}`,
    text: {
      format: {
        type: "json_schema",
        name: "design_edit_plan",
        strict: true,
        schema: innerSchema,
      },
    },
  });

  const raw = resp.output_text?.trim();
  if (!raw) throw new Error("Failed to generate edit plan.");
  return JSON.parse(raw);
}

// ---- Step 2: Run the image edit with high fidelity ----
async function runImageEdit(openai, file, finalPrompt, n, size) {
  const imageFile = await toFile(file.buffer, file.filename || "upload", { type: file.mime });

  const rsp = await openai.images.edit({
    model: "gpt-image-1",
    image: [imageFile],
    prompt: finalPrompt,
    n,
    size,
    input_fidelity: "high",
    quality: "high",
  });

  return (rsp.data || []).map((d) => `data:image/png;base64,${d.b64_json}`);
}

export default async function handler(req, res) {
  try {
    setCors(req, res);

    if (req.method === "OPTIONS") return res.status(200).end();
    if (req.method !== "POST") return res.status(405).json({ error: "Use POST" });

    if (!rateLimit(req, res)) {
      return res.status(429).json({ error: "Rate limit exceeded. Please try again later." });
    }

    const secret = process.env.SESSION_SECRET;
    if (!secret) return res.status(500).json({ error: "Missing SESSION_SECRET" });

    const token = req.headers["x-fp-token"];
    const email = verifyToken(token, secret);
    if (!email) {
      return res.status(401).json({ error: "Please enter your email to unlock the generator." });
    }

    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) return res.status(500).json({ error: "Missing OPENAI_API_KEY on server" });

    const openai = new OpenAI({ apiKey });

    const { fields, file } = await parseMultipart(req);
    if (!file?.buffer) return res.status(400).json({ error: "Missing image file" });

    const okMime = ["image/jpeg", "image/png", "image/webp"].includes(file.mime);
    if (!okMime) return res.status(400).json({ error: "Unsupported image type. Use JPG, PNG, or WEBP." });

    const userPrompt = (fields.prompt || "").trim();
    if (userPrompt.length < 3) {
      return res.status(400).json({ error: "Please describe what you want to change." });
    }

    const n = Math.min(3, Math.max(1, Number(fields.n || 2)));
    const size = (fields.size || "auto").trim();

    // Step 1: structured plan from any prompt
    const plan = await buildEditPlan(openai, userPrompt);

    // Step 2: image edit prompt generated by the plan
    const images = await runImageEdit(openai, file, plan.final_image_prompt, n, size);

    return res.status(200).json({
      ok: true,
      images,
      plan_summary: plan.intent_summary,
      // plan, // uncomment if you want to inspect the full plan in the browser
    });
  } catch (err) {
    return res.status(500).json({ error: err?.message || "Server error" });
  }
}
