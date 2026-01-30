import crypto from "crypto";

const ALLOWED_ORIGINS = new Set([
  "https://freshpainters.co.nz",
  "https://www.freshpainters.co.nz",
  // If you're testing on a GoDaddy preview URL, add it here, e.g.:
  // "https://YOUR-PREVIEW-NAME.godaddysites.com"
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

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function sign(email, secret) {
  const ts = Date.now().toString();
  const msg = `${email}|${ts}`;
  const h = crypto.createHmac("sha256", secret).update(msg).digest("hex");
  const raw = `${email}|${ts}|${h}`;
  return Buffer.from(raw, "utf8").toString("base64url");
}

async function postToWebhook(url, payload) {
  try {
    const rsp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    return rsp.ok;
  } catch {
    return false;
  }
}

export default async function handler(req, res) {
  try {
    setCors(req, res);

    if (req.method === "OPTIONS") return res.status(200).end();
    if (req.method !== "POST") return res.status(405).json({ error: "Use POST" });

    const { email, marketing_opt_in, privacy_accepted, page } = req.body || {};
    const cleanEmail = (email || "").toString().trim().toLowerCase();

    if (!isValidEmail(cleanEmail)) {
      return res.status(400).json({ error: "Please enter a valid email address." });
    }
    if (!privacy_accepted) {
      return res.status(400).json({ error: "Please accept the Privacy Policy to continue." });
    }

    const secret = process.env.SESSION_SECRET;
    if (!secret) return res.status(500).json({ error: "Missing SESSION_SECRET" });

    const token = sign(cleanEmail, secret);

    const webhook = process.env.LEADS_WEBHOOK_URL;
    if (webhook) {
      const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket.remoteAddress || "";
      const ua = req.headers["user-agent"] || "";
      await postToWebhook(webhook, {
        email: cleanEmail,
        marketing_opt_in: !!marketing_opt_in,
        privacy_accepted: !!privacy_accepted,
        page: page || "",
        ip,
        user_agent: ua,
      });
    }

    return res.status(200).json({ ok: true, token });
  } catch (err) {
    return res.status(500).json({ error: err?.message || "Server error" });
  }
}
