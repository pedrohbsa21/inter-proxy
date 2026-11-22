const http = require("http");
const https = require("https");
const { URL } = require("url");

const PORT = process.env.PORT || 3000;
const PROXY_TOKEN = process.env.PROXY_TOKEN || "";
const INTER_CLIENT_ID = process.env.INTER_CLIENT_ID || "";
const INTER_CLIENT_SECRET = process.env.INTER_CLIENT_SECRET || "";
const INTER_CERT_CRT = process.env.INTER_CERT_CRT || "";
const INTER_CERT_KEY = process.env.INTER_CERT_KEY || "";

const INTER_BASE = "https://cdpj.partners.bancointer.com.br";

let cachedToken = null;
let tokenExpiresAt = 0;

function getHttpsAgent() {
  const cert = INTER_CERT_CRT.replace(/\\n/g, "\n");
  const key = INTER_CERT_KEY.replace(/\\n/g, "\n");
  return new https.Agent({ cert, key, keepAlive: true });
}

async function getAccessToken() {
  const now = Date.now();
  if (cachedToken && tokenExpiresAt > now + 60000) {
    return cachedToken;
  }

  const agent = getHttpsAgent();
  const body = new URLSearchParams({
    client_id: INTER_CLIENT_ID,
    client_secret: INTER_CLIENT_SECRET,
    grant_type: "client_credentials",
    scope: "pix.read pix.write",
  }).toString();

  const res = await fetch(`${INTER_BASE}/oauth/v2/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body,
    // @ts-ignore
    agent,
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Falha OAuth Inter (${res.status}): ${errText}`);
  }

  const data = await res.json();
  cachedToken = data.access_token;
  tokenExpiresAt = now + (data.expires_in || 3600) * 1000;
  return cachedToken;
}

const server = http.createServer(async (req, res) => {
  // CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, PUT, POST, OPTIONS");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    return res.end();
  }

  const url = new URL(req.url, `http://${req.headers.host}`);

  // Healthcheck
  if (url.pathname === "/" || url.pathname === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ status: "ok", service: "inter-pix-proxy" }));
  }

  // Token de proteção do proxy
  if (PROXY_TOKEN) {
    const incomingToken = req.headers["x-proxy-token"];
    if (incomingToken !== PROXY_TOKEN) {
      res.writeHead(401, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ error: "Token do proxy inválido" }));
    }
  }

  try {
    const token = await getAccessToken();
    const agent = getHttpsAgent();

    // Ler corpo da requisição (se houver)
    let bodyBuffers = [];
    for await (const chunk of req) {
      bodyBuffers.push(chunk);
    }
    const reqBody = bodyBuffers.length > 0 ? Buffer.concat(bodyBuffers).toString("utf-8") : undefined;

    const targetUrl = `${INTER_BASE}${url.pathname}${url.search}`;
    const interRes = await fetch(targetUrl, {
      method: req.method,
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: reqBody,
      // @ts-ignore
      agent,
    });

    const respText = await interRes.text();
    res.writeHead(interRes.status, { "Content-Type": "application/json" });
    res.end(respText);
  } catch (err) {
    console.error("Erro no proxy:", err);
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: err.message || "Erro interno no proxy" }));
  }
});

server.listen(PORT, () => {
  console.log(`Proxy Inter Pix ativo na porta ${PORT}`);
});
