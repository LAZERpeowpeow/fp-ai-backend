import OpenAI, { toFile } from "openai";

export const config = {
  api: {
    bodyParser: false, // we will parse multipart ourselves
  },
};

function cors(res, origin) {
  const allowed = [
    "https://freshpainters.co.nz",
    "https://www.freshpainters.co.nz",
  ];

  // If request has no Origin (server-to-server), allow
  if (!origin) return;

  if (allowed.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  }
}

// Very small multipart parser (enough for 1 file + fields).
// This avoids installing extra libs.
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
    const disp = headers.find(h => h.toLowerCase().startsWith("content-disposition"));
    if (!disp) continue;

    const nameMatch = disp.match(/name="([^"]+)"/);
    const filenameMatch = disp.match(/filename="([^"]*)"/);

    const bodyBinary = rawBody.slice(0, -2); // remove trailing \r\n
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

export default async function handler(req, res) {
  try {
    cors(res, req.headers.origin);

    if (req.method === "OPTIONS") {
      res.status(200).end();
      return;
    }

    if (req.method !== "POST") {
      res.status(405).json({ error: "Use POST" });
      return;
    }

    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) {
      res.status(500).json({ error: "Missing OPENAI_API_KEY on server" });
      return;
    }

    const { fields, file } = await parseMultipart(req);

    if (!file || !file.buffer) {
      res.status(400).json({ error: "Missing image file" });
      return;
    }

    const prompt = (fields.prompt || "").trim();
    if (prompt.length < 3) {
      res.status(400).json({ error: "Missing prompt" });
      return;
    }

    const n = Math.min(3, Math.max(1, Number(fields.n || 1)));
    const size = fields.size || "auto";
    const layout = fields.layout || "high";

    const okMime = ["image/jpeg", "image/png", "image/webp"].includes(file.mime);
    if (!okMime) {
      res.status(400).json({ error: "Unsupported image type. Use JPG, PNG, or WEBP." });
      return;
    }

    const client = new OpenAI({ apiKey });

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
    res.status(200).json({ images, model });
  } catch (err) {
    res.status(500).json({ error: err?.message || "Server error" });
  }
}
