const http = require("http");
const https = require("https");
const { URL } = require("url");

const PORT = process.env.PORT || 3000;
const PROXY_TOKEN = process.env.PROXY_TOKEN || "";
const INTER_CLIENT_ID = process.env.INTER_CLIENT_ID || "";
const INTER_CLIENT_SECRET = process.env.INTER_CLIENT_SECRET || "";
const INTER_CERT_CRT = process.env.INTER_CERT_CRT || "";
const INTER_CERT_KEY = process.env.INTER_CERT_KEY || "";

const INTER_HOST = "cdpj.partners.bancointer.com.br";

let cachedToken = null;
let tokenExpiresAt = 0;

function cleanPem(str) {
  if (!str) return "";
  // Se veio com \n literais, converter para quebras de linha reais
  let cleaned = str.replace(/\\n/g, "\n").trim();
  return cleaned;
}

function makeHttpsRequest(options, data) {
  return new Promise((resolve, reject) => {
    const cert = cleanPem(INTER_CERT_CRT);
    const key = cleanPem(INTER_CERT_KEY);

    const reqOptions = {
      ...options,
      cert,
      key,
      rejectUnauthorized: true,
    };

    const req = https.request(reqOptions, (res) => {
      let chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf-8");
        resolve({
          statusCode: res.statusCode || 500,
          headers: res.headers,
          body,
        });
      });
    });

    req.on("error", (err) => {
      reject(err);
    });

    if (data) {
      req.write(data);
    }
    req.end();
  });
}

async function getAccessToken() {
  const now = Date.now();
  if (cachedToken && tokenExpiresAt > now + 60000) {
    return cachedToken;
  }

  const postData = new URLSearchParams({
    client_id: INTER_CLIENT_ID.trim(),
    client_secret: INTER_CLIENT_SECRET.trim(),
    grant_type: "client_credentials",
    scope: "pix.read pix.write cob.read cob.write webhook.read webhook.write",
  }).toString();

  const response = await makeHttpsRequest(
    {
      hostname: INTER_HOST,
      port: 443,
      path: "/oauth/v2/token",
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": Buffer.byteLength(postData),
      },
    },
    postData
  );

  if (response.statusCode < 200 || response.statusCode >= 300) {
    throw new Error(`Falha OAuth Inter (${response.statusCode}): ${response.body}`);
  }

  const data = JSON.parse(response.body);
  cachedToken = data.access_token;
  tokenExpiresAt = now + (data.expires_in || 3600) * 1000;
  return cachedToken;
}

const server = http.createServer(async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, PUT, POST, OPTIONS");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    return res.end();
  }

  const url = new URL(req.url, `http://${req.headers.host}`);

  if (url.pathname === "/" || url.pathname === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ status: "ok", service: "inter-pix-proxy" }));
  }

  if (PROXY_TOKEN) {
    const incomingToken = req.headers["x-proxy-token"];
    if (incomingToken !== PROXY_TOKEN.trim()) {
      res.writeHead(401, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ error: "Token do proxy inválido" }));
    }
  }

  try {
    const token = await getAccessToken();

    let bodyBuffers = [];
    for await (const chunk of req) {
      bodyBuffers.push(chunk);
    }
    const reqBody = bodyBuffers.length > 0 ? Buffer.concat(bodyBuffers).toString("utf-8") : undefined;

    const interResponse = await makeHttpsRequest(
      {
        hostname: INTER_HOST,
        port: 443,
        path: `${url.pathname}${url.search}`,
        method: req.method,
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          Authorization: `Bearer ${token}`,
          ...(reqBody ? { "Content-Length": Buffer.byteLength(reqBody) } : {}),
        },
      },
      reqBody
    );

    res.writeHead(interResponse.statusCode, { "Content-Type": "application/json" });
    res.end(interResponse.body);
  } catch (err) {
    console.error("Erro no proxy:", err);
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: err.message || "Erro interno no proxy" }));
  }
});

server.listen(PORT, () => {
  console.log(`Proxy Inter Pix ativo na porta ${PORT}`);
});
