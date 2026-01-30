import crypto from "crypto";

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function sign(email, secret) {
  // token = base64(email|timestamp|hmac)
  const ts = Date.now().toString();
  const msg = `${email}|${ts}`;
  const h = crypto.createHmac("sha256", secret).update(msg).digest("hex");
  const raw = `${email}|${ts}|${h}`;
  return Buffer.from(raw, "utf8").toString("base64url");
}

async function postToLeadsWebhook(url, payload) {
  const rsp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  // We won’t hard-fail if Sheets hiccups; we’ll still allow token issuance.
  return rsp.ok;
}

export default async function handler(req, res) {
  try {
    if (req.method === "OPTIONS") return res.status(200).end();
    if (req.method !== "POST") return res.status(405).json({ error: "Use POST" });

    const { email, page } = req.body || {};
    const cleanEmail = (email || "").toString().trim().toLowerCase();

    if (!isValidEmail(cleanEmail)) {
      return res.status(400).json({ error: "Please enter a valid email address." });
    }

    const secret = process.env.SESSION_SECRET;
    if (!secret) return res.status(500).json({ error: "Missing SESSION_SECRET" });

    const token = sign(cleanEmail, secret);

    const webhook = process.env.LEADS_WEBHOOK_URL;
    if (webhook) {
      const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket.remoteAddress || "";
      const ua = req.headers["user-agent"] || "";
      await postToLeadsWebhook(webhook, { email: cleanEmail, ip, user_agent: ua, page: page || "" });
    }

    return res.status(200).json({ ok: true, token });
  } catch (err) {
    return res.status(500).json({ error: err?.message || "Server error" });
  }
}
