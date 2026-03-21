// server.js (ESM)

import express from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import rateLimit from "express-rate-limit";
import { v4 as uuidv4 } from "uuid";
import FormData from "form-data";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load environment variables - prefer .env.local over .env
const envLocalPath = path.join(__dirname, ".env.local");
const envPath = path.join(__dirname, ".env");

if (fs.existsSync(envLocalPath)) {
  dotenv.config({ path: envLocalPath });
  console.log("Loaded configuration from .env.local");
} else if (fs.existsSync(envPath)) {
  dotenv.config({ path: envPath });
  console.log("Loaded configuration from .env");
} else {
  dotenv.config();
  console.log("Using default environment variables");
}

const app = express();
const PORT = process.env.PORT || 3001;

// Trust proxy - configure based on deployment environment
// For Railway/Render/Heroku, use 1 to trust the first proxy
// For development, don't trust any proxy
const trustProxyConfig = process.env.NODE_ENV === "production" ? 1 : false;
app.set("trust proxy", trustProxyConfig);

// Security middleware
app.use(helmet());

// ===============================
// ✅ FIX: parse comma-separated FRONTEND_URL into multiple origins
// Example env:
// FRONTEND_URL="https://multi-ais-chat.netlify.app,https://aifiestaa.netlify.app,https://pintukr.in"
// ===============================
const envOrigins = (process.env.FRONTEND_URL || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

function normalizeOrigin(value) {
  try {
    const parsed = new URL(value);
    return `${parsed.protocol}//${parsed.host}`;
  } catch {
    return null;
  }
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const normalizedEnvOrigins = envOrigins
  .map((origin) => normalizeOrigin(origin))
  .filter(Boolean);

const vercelPreviewMatchers = normalizedEnvOrigins
  .map((origin) => {
    const parsed = new URL(origin);
    if (!parsed.hostname.endsWith(".vercel.app")) {
      return null;
    }

    const projectSlug = parsed.hostname.replace(/\.vercel\.app$/i, "");
    return {
      protocol: parsed.protocol,
      hostnamePattern: new RegExp(
        `^${escapeRegex(projectSlug)}(?:-[a-z0-9-]+)?\\.vercel\\.app$`,
        "i",
      ),
    };
  })
  .filter(Boolean);

function isAllowedOrigin(origin) {
  const normalizedOrigin = normalizeOrigin(origin);
  if (!normalizedOrigin) {
    return false;
  }

  if (allowedOrigins.has(normalizedOrigin)) {
    return true;
  }

  const parsedOrigin = new URL(normalizedOrigin);
  return vercelPreviewMatchers.some(
    (matcher) =>
      matcher.protocol === parsedOrigin.protocol &&
      matcher.hostnamePattern.test(parsedOrigin.hostname),
  );
}

// Use the first origin as a "primary" URL for headers like HTTP-Referer
const primaryFrontendUrl =
  normalizedEnvOrigins[0] || "http://localhost:5173";

// Define allowed origins for CORS
const allowedOrigins = new Set([
  ...normalizedEnvOrigins,
  "http://localhost:5173",
  "http://localhost:3000",
]);

app.use(
  cors({
    origin(origin, callback) {
      // Allow requests with no origin (curl, mobile apps, server-to-server)
      if (!origin) return callback(null, true);

      if (isAllowedOrigin(origin)) return callback(null, true);

      return callback(new Error(`Not allowed by CORS: ${origin}`), false);
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "X-Session-Token", "x-session-token"],
  }),
);

// Base64-encoded images can exceed the raw upload size; align with 10MB frontend cap.
app.use(express.json({ limit: "20mb" }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  // Skip rate limiting in development
  skip: () => process.env.NODE_ENV === "development",
  message: "Too many requests from this IP, please try again later.",
  // Explicitly validate the trust proxy setting
  validate: {
    trustProxy: false, // Disable the built-in validation since we're handling it manually
    xForwardedForHeader: false, // Disable this validation too
  },
});
app.use("/api/", limiter);

// Session storage (in production, use Redis or a database)
const sessions = new Map();
const SESSION_DURATION = 60 * 60 * 1000; // 1 hour

// Cleanup expired sessions
setInterval(
  () => {
    const now = Date.now();
    for (const [token, session] of sessions.entries()) {
      if (now > session.expiresAt) sessions.delete(token);
    }
  },
  5 * 60 * 1000,
); // Clean every 5 minutes

// Cache for extracted keys - computed once at startup
const keyCache = new Map();

// Helper to extract API keys from environment (with caching)
function extractKeys(baseKeyName) {
  // Return cached result if available
  if (keyCache.has(baseKeyName)) return keyCache.get(baseKeyName);

  const keys = new Set();
  const envVarMap = {
    GOOGLE_API_KEY: "GOOGLE_API_KEY",
    GROQ_API_KEY: "GROQ_API_KEY",
    SAMBANOVAAI_API_KEY: "SAMBANOVAAI_API_KEY",
    OPENROUTER_API_KEY: "OPENROUTER_API_KEY",
    GITHUB_TOKEN: "GITHUB_TOKEN",
    COHERE_API_KEY: "COHERE_API_KEY",
    XAI_API_KEY: "XAI_API_KEY",
    FASTROUTER_API_KEY: "FASTROUTER_API_KEY",
  };

  const base = envVarMap[baseKeyName] || baseKeyName;

  // Direct key
  if (process.env[base]) keys.add(process.env[base]);

  // Numbered variants - check up to 20 keys per service
  for (let i = 1; i <= 20; i++) {
    // Try both KEY1 and KEY_1 formats
    const key1 = process.env[`${base}${i}`];
    const key2 = process.env[`${base}_${i}`];

    if (key1 && key1.trim()) keys.add(key1.trim());
    if (key2 && key2.trim()) keys.add(key2.trim());
  }

  // Debug logging for troubleshooting
  if (keys.size === 0) {
    console.log(
      `No keys found for ${baseKeyName}. Checked: ${base}, ${base}1-20, ${base}_1-20`,
    );
  }

  const result = Array.from(keys);
  keyCache.set(baseKeyName, result);
  return result;
}

function getOpenAICompatibleKeys() {
  return Array.from(
    new Set([
      ...extractKeys("FASTROUTER_API_KEY"),
      ...extractKeys("SAMBANOVAAI_API_KEY"),
    ]),
  );
}

// Pre-warm the key cache at startup
function initializeKeyCache() {
  const services = [
    "GROQ_API_KEY",
    "GOOGLE_API_KEY",
    "SAMBANOVAAI_API_KEY",
    "OPENROUTER_API_KEY",
    "GITHUB_TOKEN",
    "COHERE_API_KEY",
    "XAI_API_KEY",
    "FASTROUTER_API_KEY",
  ];
  services.forEach(extractKeys);
}

// Middleware to verify session token
function authenticateSession(req, res, next) {
  const token = req.headers["x-session-token"];

  if (!token)
    return res.status(401).json({ error: "No session token provided" });

  const session = sessions.get(token);

  if (!session || Date.now() > session.expiresAt) {
    sessions.delete(token);
    return res.status(401).json({ error: "Session expired or invalid" });
  }

  // Refresh session
  session.expiresAt = Date.now() + SESSION_DURATION;
  req.session = session;
  next();
}

// Middleware to prevent caching of sensitive data
function preventCache(req, res, next) {
  res.set({
    "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
    Pragma: "no-cache",
    Expires: "0",
    "Surrogate-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
  });
  next();
}

// Initialize session - client calls this first
app.post("/api/session/init", (req, res) => {
  const token = uuidv4();
  const session = {
    id: token,
    createdAt: Date.now(),
    expiresAt: Date.now() + SESSION_DURATION,
    keyIndices: {
      gemini: 0,
      groq: 0,
      openai: 0,
      openrouter: 0,
      github: 0,
      cohere: 0,
      xai: 0,
      fastrouter: 0,
    },
  };

  sessions.set(token, session);

  // Get actual key counts for each service
  const groqKeys = extractKeys("GROQ_API_KEY");
  const geminiKeys = extractKeys("GOOGLE_API_KEY");
  const openaiKeys = getOpenAICompatibleKeys();
  const openrouterKeys = extractKeys("OPENROUTER_API_KEY");
  const githubKeys = extractKeys("GITHUB_TOKEN");
  const cohereKeys = extractKeys("COHERE_API_KEY");
  const xaiKeys = extractKeys("XAI_API_KEY");
  const fastrouterKeys = extractKeys("FASTROUTER_API_KEY");

  // Return session info with actual key counts
  res.json({
    token,
    expiresAt: session.expiresAt,
    services: {
      gemini: geminiKeys.length,
      groq: groqKeys.length,
      openai: openaiKeys.length,
      openrouter: openrouterKeys.length,
      github: githubKeys.length,
      cohere: cohereKeys.length,
      xai: xaiKeys.length,
      fastrouter: fastrouterKeys.length,
    },
  });
});

// Get API key for a specific service
app.post("/api/keys/get", authenticateSession, preventCache, (req, res) => {
  const { service } = req.body;

  if (!service) return res.status(400).json({ error: "Service not specified" });

  if (service === "openai") {
    const keys = getOpenAICompatibleKeys();
    if (keys.length === 0) {
      return res.status(404).json({ error: "No keys configured for openai" });
    }

    const currentIndex = req.session.keyIndices.openai || 0;
    const key = keys[currentIndex % keys.length];

    res.type("application/octet-stream");
    const responseData = { key, index: currentIndex, total: keys.length };
    const buffer = Buffer.from(JSON.stringify(responseData));
    return res.send(buffer);
  }

  const keyMap = {
    gemini: "GOOGLE_API_KEY",
    groq: "GROQ_API_KEY",
    openrouter: "OPENROUTER_API_KEY",
    github: "GITHUB_TOKEN",
    cohere: "COHERE_API_KEY",
    xai: "XAI_API_KEY",
    fastrouter: "FASTROUTER_API_KEY",
  };

  const baseKey = keyMap[service];
  if (!baseKey) return res.status(400).json({ error: "Invalid service" });

  const keys = extractKeys(baseKey);
  if (keys.length === 0)
    return res.status(404).json({ error: `No keys configured for ${service}` });

  // Get current index for this service
  const currentIndex = req.session.keyIndices[service] || 0;
  const key = keys[currentIndex % keys.length];

  // Set response type to prevent browser preview/caching
  res.type("application/octet-stream");

  // Send the response as a buffer to prevent text preview
  const responseData = { key, index: currentIndex, total: keys.length };
  const buffer = Buffer.from(JSON.stringify(responseData));
  res.send(buffer);
});

// Rotate to next key for a service
app.post("/api/keys/rotate", authenticateSession, (req, res) => {
  const { service } = req.body;

  if (
    !service ||
    !Object.prototype.hasOwnProperty.call(req.session.keyIndices, service)
  ) {
    return res.status(400).json({ error: "Invalid service" });
  }

  // Increment the index
  req.session.keyIndices[service] =
    (req.session.keyIndices[service] + 1) % 1000;

  res.json({ success: true, newIndex: req.session.keyIndices[service] });
});

// Get service status (which services have keys configured)
app.get("/api/services/status", authenticateSession, (req, res) => {
  res.json({
    groq: extractKeys("GROQ_API_KEY").length > 0,
    gemini: extractKeys("GOOGLE_API_KEY").length > 0,
    openai: getOpenAICompatibleKeys().length > 0,
    openrouter: extractKeys("OPENROUTER_API_KEY").length > 0,
    github: extractKeys("GITHUB_TOKEN").length > 0,
    cohere: extractKeys("COHERE_API_KEY").length > 0,
    xai: extractKeys("XAI_API_KEY").length > 0,
    fastrouter: extractKeys("FASTROUTER_API_KEY").length > 0,
  });
});

// Add a new endpoint to get key counts
app.get("/api/keys/count", authenticateSession, (req, res) => {
  res.json({
    groq: extractKeys("GROQ_API_KEY").length,
    gemini: extractKeys("GOOGLE_API_KEY").length,
    openai: getOpenAICompatibleKeys().length,
    openrouter: extractKeys("OPENROUTER_API_KEY").length,
    github: extractKeys("GITHUB_TOKEN").length,
    cohere: extractKeys("COHERE_API_KEY").length,
    xai: extractKeys("XAI_API_KEY").length,
    fastrouter: extractKeys("FASTROUTER_API_KEY").length,
  });
});

// Health check
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// List all available SambaNova models for UI dropdown selection
app.get("/api/models/openai", authenticateSession, async (req, res) => {
  const keys = extractKeys("SAMBANOVAAI_API_KEY");
  if (keys.length === 0) {
    return res.status(503).json({ error: "No SambaNova API keys available" });
  }

  try {
    const models = await getSambaNovaModels(keys[0]);
    return res.json({
      models: sanitizeModelIds(models),
      source: "sambanova",
      success: true,
    });
  } catch (error) {
    const details = error instanceof Error ? error.message : String(error);
    return res.status(500).json({
      error: "Failed to fetch SambaNova models",
      details: compactText(details),
      success: false,
    });
  }
});

// List FastRouter chat models for UI dropdown selection
app.get("/api/models/fastrouter", authenticateSession, (req, res) => {
  const keys = extractKeys("FASTROUTER_API_KEY");
  if (keys.length === 0) {
    return res.status(503).json({ error: "No FastRouter API keys available" });
  }

  getFastRouterModels(keys[0])
    .then((models) =>
      res.json({
        models: sanitizeModelIds(models).slice(0, FASTROUTER_MODEL_TARGET_COUNT),
        source: "fastrouter",
        success: true,
      }),
    )
    .catch((error) => {
      const details = error instanceof Error ? error.message : String(error);
      res.status(500).json({
        error: "Failed to fetch FastRouter models",
        details: compactText(details),
        success: false,
      });
    });
});

// =============================================================================
// SECURE PROXY ENDPOINTS - AI API calls made server-side (keys never sent to client)
// =============================================================================

// Helper to get next key with rotation
function getNextKey(session, service, baseKeyName) {
  const keys = extractKeys(baseKeyName);
  if (keys.length === 0) return null;
  const currentIndex = session.keyIndices[service] || 0;
  return {
    key: keys[currentIndex % keys.length],
    index: currentIndex,
    total: keys.length,
  };
}

// Helper to rotate key on failure
function rotateKeyOnFailure(session, service) {
  session.keyIndices[service] = ((session.keyIndices[service] || 0) + 1) % 1000;
}

const OPENROUTER_MODEL_CACHE_TTL_MS = 5 * 60 * 1000;
const OPENROUTER_DEFAULT_MODELS = [
  "qwen/qwen3-coder:free",
  "upstage/solar-pro-3:free",
  "openrouter/free",
];
const OPENROUTER_PREFERRED_MODELS = [
  "qwen/qwen3-coder:free",
  "openai/gpt-oss-20b:free",
  "openai/gpt-oss-120b:free",
  "upstage/solar-pro-3:free",
  "stepfun/step-3.5-flash:free",
];
let openRouterModelCache = { expiresAt: 0, models: OPENROUTER_DEFAULT_MODELS };

const SAMBANOVA_MODEL_CACHE_TTL_MS = 5 * 60 * 1000;
const SAMBANOVA_DEFAULT_MODELS = ["Meta-Llama-3.1-8B-Instruct"];
let sambaNovaModelCache = { expiresAt: 0, models: SAMBANOVA_DEFAULT_MODELS };
const SAMBANOVA_MODEL_PROBE_TIMEOUT_MS = 12 * 1000;
const SAMBANOVA_MODEL_PROBE_MAX_ATTEMPTS = 2;
const FASTROUTER_MODEL_CACHE_TTL_MS = 5 * 60 * 1000;
const FASTROUTER_DEFAULT_MODELS = [
  "anthropic/claude-sonnet-4-20250514",
  "anthropic/claude-opus-4.5",
  "anthropic/claude-3-5-sonnet-20241022",
  "anthropic/claude-3-7-sonnet-20250219",
];
const FASTROUTER_MODEL_PREFERRED = [
  "anthropic/claude-sonnet-4-20250514",
  "anthropic/claude-opus-4.5",
  "anthropic/claude-3-7-sonnet-20250219",
  "anthropic/claude-3-5-sonnet-20241022",
  "anthropic/claude-3-5-haiku-20241022",
  "anthropic/claude-haiku-4.5",
  "anthropic/claude-4.5-sonnet",
  "anthropic/claude-opus-4-20250514",
];
const FASTROUTER_MODEL_TARGET_COUNT = 4;
const FASTROUTER_MODEL_PROBE_TIMEOUT_MS = 10 * 1000;
let fastRouterModelCache = { expiresAt: 0, models: FASTROUTER_DEFAULT_MODELS };

function compactText(value, max = 200) {
  if (!value) return "";
  return String(value).replace(/\s+/g, " ").trim().slice(0, max);
}

function parseErrorMessage(rawText, fallback) {
  if (!rawText) return fallback;
  try {
    const parsed = JSON.parse(rawText);
    const message =
      parsed?.error?.message ||
      parsed?.message ||
      parsed?.detail ||
      parsed?.error_description;
    return compactText(message, 260) || fallback;
  } catch {
    return compactText(rawText, 260) || fallback;
  }
}

function isPreferredOpenRouterModel(modelId) {
  if (typeof modelId !== "string" || !modelId.endsWith(":free")) return false;

  const lower = modelId.toLowerCase();
  if (lower.includes("vl") || lower.includes("vision")) return false;
  if (lower.includes("image") || lower.includes("audio")) return false;
  if (lower.includes("transcribe") || lower.includes("embedding")) return false;
  if (lower.includes("thinking")) return false;
  return true;
}

async function fetchOpenRouterModels(apiKey) {
  const response = await fetch("https://openrouter.ai/api/v1/models/user", {
    method: "GET",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "HTTP-Referer": primaryFrontendUrl,
      "X-Title": "AI Chat Fusion",
    },
  });

  if (!response.ok) {
    const raw = await response.text();
    const details = parseErrorMessage(
      raw,
      `OpenRouter model list failed (${response.status})`,
    );
    throw new Error(details);
  }

  const data = await response.json();
  const available = Array.isArray(data?.data)
    ? data.data.map((item) => item?.id).filter(isPreferredOpenRouterModel)
    : [];

  const ordered = [];
  for (const preferred of OPENROUTER_PREFERRED_MODELS) {
    if (available.includes(preferred)) ordered.push(preferred);
  }
  for (const model of available) {
    if (!ordered.includes(model)) ordered.push(model);
  }

  const limited = ordered.slice(0, 10);
  if (!limited.includes("openrouter/free")) limited.push("openrouter/free");
  if (limited.length === 0) return OPENROUTER_DEFAULT_MODELS;

  return limited;
}

async function getOpenRouterModels(apiKey) {
  if (
    openRouterModelCache.expiresAt > Date.now() &&
    openRouterModelCache.models.length > 0
  ) {
    return openRouterModelCache.models;
  }

  try {
    const models = await fetchOpenRouterModels(apiKey);
    openRouterModelCache = {
      expiresAt: Date.now() + OPENROUTER_MODEL_CACHE_TTL_MS,
      models,
    };
    return models;
  } catch (error) {
    const details =
      error instanceof Error ? error.message : "Unknown model-list error";
    console.warn(`[OpenRouter] using fallback model list: ${details}`);
    openRouterModelCache = {
      expiresAt: Date.now() + OPENROUTER_MODEL_CACHE_TTL_MS,
      models: OPENROUTER_DEFAULT_MODELS,
    };
    return OPENROUTER_DEFAULT_MODELS;
  }
}

function invalidateOpenRouterModelCache() {
  openRouterModelCache.expiresAt = 0;
}

function buildOpenRouterRequestModels(modelCandidates) {
  const unique = Array.from(
    new Set(
      (Array.isArray(modelCandidates) ? modelCandidates : []).filter(
        (model) => typeof model === "string" && model.trim().length > 0,
      ),
    ),
  );

  const selected = unique.slice(0, 3);

  if (!selected.includes("openrouter/free")) {
    if (selected.length < 3) selected.push("openrouter/free");
    else selected[selected.length - 1] = "openrouter/free";
  }

  return Array.from(new Set(selected)).slice(0, 3);
}

function extractOpenRouterContent(data) {
  const firstMessage = data?.choices?.[0]?.message;
  const content = firstMessage?.content;

  if (typeof content === "string" && content.trim()) return content.trim();

  if (Array.isArray(content)) {
    const text = content
      .map((part) =>
        typeof part === "string"
          ? part
          : typeof part?.text === "string"
            ? part.text
            : "",
      )
      .join("")
      .trim();
    if (text) return text;
  }

  if (
    typeof firstMessage?.reasoning === "string" &&
    firstMessage.reasoning.trim()
  ) {
    return firstMessage.reasoning.trim();
  }

  return "";
}

function isPreferredFastRouterModel(modelId) {
  if (typeof modelId !== "string" || !modelId.startsWith("anthropic/")) return false;

  const lower = modelId.toLowerCase();
  if (lower.includes(":thinking")) return false;
  if (lower.includes("image")) return false;
  if (lower.includes("audio")) return false;
  if (lower.includes("embedding")) return false;
  return true;
}

async function fetchFastRouterModelCandidates(apiKey) {
  const response = await fetch("https://go.fastrouter.ai/api/v1/models", {
    method: "GET",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
  });

  if (!response.ok) {
    const raw = await response.text();
    const details = parseErrorMessage(
      raw,
      `FastRouter model list failed (${response.status})`,
    );
    throw new Error(details);
  }

  const data = await response.json();
  const available = sanitizeModelIds(
    Array.isArray(data?.data) ? data.data.map((item) => item?.id) : [],
  ).filter(isPreferredFastRouterModel);

  const ordered = [];
  for (const preferred of FASTROUTER_MODEL_PREFERRED) {
    if (available.includes(preferred)) ordered.push(preferred);
  }
  for (const modelId of available) {
    if (!ordered.includes(modelId)) ordered.push(modelId);
  }

  return ordered;
}

async function isWorkingFastRouterModel(apiKey, modelId) {
  const controller = new AbortController();
  const timeoutId = setTimeout(
    () => controller.abort(),
    FASTROUTER_MODEL_PROBE_TIMEOUT_MS,
  );

  try {
    const response = await fetch(
      "https://go.fastrouter.ai/api/v1/chat/completions",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: modelId,
          messages: [{ role: "user", content: "Reply with exactly: OK" }],
          max_tokens: 16,
          temperature: 0,
        }),
        signal: controller.signal,
      },
    );

    if (response.ok) return true;

    const raw = await response.text();
    const details = parseErrorMessage(
      raw,
      `FastRouter API error (${response.status})`,
    );
    console.warn(
      `[FastRouter] excluding non-working model ${modelId}: ${response.status}: ${compactText(details, 320)}`,
    );
    return false;
  } catch (error) {
    const details =
      error instanceof Error ? error.message : "Unknown FastRouter probe error";
    console.warn(
      `[FastRouter] excluding non-working model ${modelId}: ${compactText(details, 320)}`,
    );
    return false;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function getFastRouterModels(apiKey) {
  if (
    fastRouterModelCache.expiresAt > Date.now() &&
    fastRouterModelCache.models.length > 0
  ) {
    return fastRouterModelCache.models;
  }

  try {
    const candidates = await fetchFastRouterModelCandidates(apiKey);
    const working = [];

    for (const modelId of candidates) {
      if (working.length >= FASTROUTER_MODEL_TARGET_COUNT) break;
      const isWorking = await isWorkingFastRouterModel(apiKey, modelId);
      if (isWorking) working.push(modelId);
    }

    const models =
      working.length > 0
        ? working
        : FASTROUTER_DEFAULT_MODELS.slice(0, FASTROUTER_MODEL_TARGET_COUNT);

    fastRouterModelCache = {
      expiresAt: Date.now() + FASTROUTER_MODEL_CACHE_TTL_MS,
      models,
    };

    return models;
  } catch (error) {
    const details =
      error instanceof Error ? error.message : "Unknown FastRouter model-list error";
    console.warn(`[FastRouter] using fallback model list: ${details}`);
    fastRouterModelCache = {
      expiresAt: Date.now() + FASTROUTER_MODEL_CACHE_TTL_MS,
      models: FASTROUTER_DEFAULT_MODELS,
    };
    return FASTROUTER_DEFAULT_MODELS;
  }
}

function isSambaNovaChatModel(modelId) {
  if (typeof modelId !== "string" || !modelId.trim()) return false;

  const lower = modelId.toLowerCase();
  if (lower.includes("embedding")) return false;
  if (lower.includes("whisper")) return false;
  if (lower.includes("audio")) return false;
  if (lower.includes("transcribe")) return false;
  if (lower.includes("tts")) return false;

  return true;
}

function sanitizeModelIds(models) {
  return Array.from(
    new Set(
      (Array.isArray(models) ? models : []).filter(
        (modelId) => typeof modelId === "string" && modelId.trim().length > 0,
      ),
    ),
  );
}

async function fetchSambaNovaModels(apiKey) {
  const response = await fetch("https://api.sambanova.ai/v1/models", {
    method: "GET",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
  });

  if (!response.ok) {
    const raw = await response.text();
    const details = parseErrorMessage(
      raw,
      `SambaNova model list failed (${response.status})`,
    );
    throw new Error(details);
  }

  const data = await response.json();
  const available = sanitizeModelIds(
    Array.isArray(data?.data) ? data.data.map((item) => item?.id) : [],
  );

  const chatCandidates = available.filter((modelId) =>
    isSambaNovaChatModel(modelId),
  );
  if (chatCandidates.length === 0) return SAMBANOVA_DEFAULT_MODELS;

  const workingModels = [];

  for (const modelId of chatCandidates) {
    const isWorking = await isWorkingSambaNovaChatModel(apiKey, modelId);
    if (isWorking) workingModels.push(modelId);
  }

  if (workingModels.length === 0) return SAMBANOVA_DEFAULT_MODELS;
  return workingModels;
}

async function isWorkingSambaNovaChatModel(apiKey, modelId) {
  let lastDetails = "";

  for (
    let attempt = 1;
    attempt <= SAMBANOVA_MODEL_PROBE_MAX_ATTEMPTS;
    attempt++
  ) {
    const controller = new AbortController();
    const timeoutId = setTimeout(
      () => controller.abort(),
      SAMBANOVA_MODEL_PROBE_TIMEOUT_MS,
    );

    try {
      const response = await fetch("https://api.sambanova.ai/v1/chat/completions", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: modelId,
          messages: [{ role: "user", content: "Reply with exactly: OK" }],
          max_tokens: 16,
          temperature: 0,
        }),
        signal: controller.signal,
      });

      const raw = await response.text();
      if (response.ok) return true;

      const details = parseErrorMessage(
        raw,
        `SambaNova API error (${response.status})`,
      );
      lastDetails = `${response.status}: ${details}`;

      if ([400, 401, 403, 404, 422].includes(response.status)) {
        break;
      }
    } catch (error) {
      lastDetails =
        error instanceof Error ? error.message : "Unknown SambaNova probe error";
    } finally {
      clearTimeout(timeoutId);
    }
  }

  console.warn(`[SambaNova] excluding non-working model ${modelId}: ${compactText(lastDetails, 320)}`);
  return false;
}

async function getSambaNovaModels(apiKey) {
  if (
    sambaNovaModelCache.expiresAt > Date.now() &&
    sambaNovaModelCache.models.length > 0
  ) {
    return sambaNovaModelCache.models;
  }

  try {
    const models = await fetchSambaNovaModels(apiKey);
    sambaNovaModelCache = {
      expiresAt: Date.now() + SAMBANOVA_MODEL_CACHE_TTL_MS,
      models,
    };
    return models;
  } catch (error) {
    const details =
      error instanceof Error ? error.message : "Unknown model-list error";
    console.warn(`[SambaNova] using fallback model list: ${details}`);
    sambaNovaModelCache = {
      expiresAt: Date.now() + SAMBANOVA_MODEL_CACHE_TTL_MS,
      models: SAMBANOVA_DEFAULT_MODELS,
    };
    return SAMBANOVA_DEFAULT_MODELS;
  }
}

function invalidateSambaNovaModelCache() {
  sambaNovaModelCache.expiresAt = 0;
}

function getPreferredSambaNovaModel(models) {
  const allModels = sanitizeModelIds(models);
  const chatModels = allModels.filter((modelId) => isSambaNovaChatModel(modelId));
  const candidates = chatModels.length > 0 ? chatModels : allModels;
  if (candidates.length === 0) return SAMBANOVA_DEFAULT_MODELS[0];
  return candidates[Math.floor(Date.now() / 1000) % candidates.length];
}

function parseBase64Image(image) {
  if (typeof image !== "string") {
    return { error: "Invalid image data" };
  }

  const match = image.match(/^data:([^;]+);base64,([\s\S]+)$/);
  const mimeType = match?.[1] || "image/png";
  let base64Data = match?.[2] || image;

  base64Data = base64Data.replace(/\s/g, "");

  if (!base64Data) {
    return { error: "Invalid image data" };
  }

  return { mimeType, base64Data };
}

// Proxy endpoint for Groq API (with retry on rate limit)
app.post("/api/proxy/groq", authenticateSession, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: "Message required" });

  const keys = extractKeys("GROQ_API_KEY");
  const maxRetries = Math.min(keys.length, 5);

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const keyData = getNextKey(req.session, "groq", "GROQ_API_KEY");
    if (!keyData)
      return res.status(503).json({ error: "No Groq API keys available" });

    try {
      const response = await fetch(
        "https://api.groq.com/openai/v1/chat/completions",
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${keyData.key}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model: "llama-3.1-8b-instant",
            messages: [
              {
                role: "system",
                content:
                  "You are Groq AI, an ultra-fast AI assistant. Provide concise, helpful responses.",
              },
              { role: "user", content: message },
            ],
            max_tokens: 1000,
            temperature: 0.7,
          }),
        },
      );

      if (response.ok) {
        const data = await response.json();
        return res.json({
          content: data.choices?.[0]?.message?.content || "",
          model: "llama-3.1-8b-instant",
          source: "groq",
          success: true,
        });
      }

      if (response.status === 429 || response.status === 401) {
        rotateKeyOnFailure(req.session, "groq");
        continue;
      }

      return res.status(response.status).json({
        error: "Groq API error",
        status: response.status,
      });
    } catch {
      rotateKeyOnFailure(req.session, "groq");
      continue;
    }
  }

  res
    .status(429)
    .json({ error: "All Groq API keys rate limited", success: false });
});

// Proxy endpoint for Gemini API via FastRouter (with retry on rate limit)
app.post("/api/proxy/gemini", authenticateSession, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: "Message required" });

  const keys = extractKeys("FASTROUTER_API_KEY");
  const maxRetries = Math.min(keys.length, 5);

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const keyData = getNextKey(req.session, "fastrouter", "FASTROUTER_API_KEY");
    if (!keyData)
      return res
        .status(503)
        .json({ error: "No FastRouter API keys available for Gemini" });

    try {
      const response = await fetch(
        "https://go.fastrouter.ai/api/v1/chat/completions",
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${keyData.key}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model: "google/gemini-2.5-flash",
            messages: [
              {
                role: "system",
                content: "You are Gemini, a helpful AI assistant by Google.",
              },
              { role: "user", content: message },
            ],
            max_tokens: 4096,
            temperature: 0.7,
          }),
        },
      );

      if (response.ok) {
        const data = await response.json();
        return res.json({
          content: data.choices?.[0]?.message?.content || "",
          model: "google/gemini-2.5-flash",
          source: "gemini",
          success: true,
        });
      }

      if ([429, 401, 403].includes(response.status)) {
        rotateKeyOnFailure(req.session, "fastrouter");
        continue;
      }

      return res
        .status(response.status)
        .json({ error: "Gemini API error", status: response.status });
    } catch {
      rotateKeyOnFailure(req.session, "fastrouter");
      continue;
    }
  }

  res
    .status(429)
    .json({ error: "All FastRouter API keys rate limited", success: false });
});

// Proxy endpoint for Cohere API
app.post("/api/proxy/cohere", authenticateSession, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: "Message required" });

  const keys = extractKeys("COHERE_API_KEY");
  const maxRetries = Math.min(keys.length, 5);
  const modelCandidates = [
    "command-a-03-2025",
    "command-r-plus-08-2024",
    "command-r7b-12-2024",
  ];
  const attemptErrors = [];

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const keyData = getNextKey(req.session, "cohere", "COHERE_API_KEY");
    if (!keyData) {
      return res.status(503).json({ error: "No Cohere API keys available" });
    }

    let shouldRotateKey = false;

    for (const model of modelCandidates) {
      try {
        const response = await fetch("https://api.cohere.com/v2/chat", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${keyData.key}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model,
            messages: [{ role: "user", content: message }],
            temperature: 0.7,
          }),
        });

        const raw = await response.text();

        if (response.ok) {
          const data = JSON.parse(raw);
          const content = data?.message?.content?.[0]?.text || "";

          if (!content.trim()) {
            attemptErrors.push(`${model}: empty response`);
            continue;
          }

          return res.json({
            content,
            model,
            source: "cohere",
            success: true,
          });
        }

        const details = parseErrorMessage(
          raw,
          `Cohere API error (${response.status})`,
        );
        attemptErrors.push(`${model} (${response.status}): ${details}`);

        if (response.status === 401 || response.status === 429) {
          shouldRotateKey = true;
          break;
        }

        if (
          response.status === 404 ||
          (response.status === 400 &&
            /model|removed|not found|deprecated/i.test(details))
        ) {
          continue;
        }
      } catch (error) {
        const details =
          error instanceof Error ? error.message : "Unknown Cohere error";
        attemptErrors.push(`${model}: ${compactText(details)}`);
      }
    }

    if (shouldRotateKey) {
      rotateKeyOnFailure(req.session, "cohere");
    }
  }

  return res.status(503).json({
    error: "All Cohere models failed",
    details: compactText(attemptErrors.join(" | "), 500),
    success: false,
  });
});

// Proxy endpoint for GitHub Models API
app.post("/api/proxy/github", authenticateSession, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: "Message required" });

  const keyData = getNextKey(req.session, "github", "GITHUB_TOKEN");
  if (!keyData)
    return res.status(503).json({ error: "No GitHub API tokens available" });

  const models = [
    "xai/grok-3-mini",
    "deepseek/DeepSeek-V3-0324",
    "openai/gpt-4.1",
  ];
  const selectedModel = models[Math.floor(Date.now() / 1000) % models.length];

  try {
    const response = await fetch(
      "https://models.github.ai/inference/chat/completions",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${keyData.key}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: selectedModel,
          messages: [
            {
              role: "system",
              content: "You are GitHub AI, an advanced AI assistant.",
            },
            { role: "user", content: message },
          ],
          max_tokens: 1000,
          temperature: 0.7,
        }),
      },
    );

    if (!response.ok) {
      if (response.status === 429 || response.status === 401)
        rotateKeyOnFailure(req.session, "github");
      return res
        .status(response.status)
        .json({ error: "GitHub API error", status: response.status });
    }

    const data = await response.json();
    res.json({
      content: data.choices?.[0]?.message?.content || "",
      model: selectedModel,
      source: "github",
      success: true,
    });
  } catch {
    res
      .status(500)
      .json({ error: "Failed to call GitHub API", success: false });
  }
});

// Proxy endpoint for OpenRouter API
app.post("/api/proxy/openrouter", authenticateSession, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: "Message required" });

  const keys = extractKeys("OPENROUTER_API_KEY");
  const maxRetries = Math.min(keys.length, 5);
  const attemptErrors = [];

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const keyData = getNextKey(req.session, "openrouter", "OPENROUTER_API_KEY");
    if (!keyData) {
      return res.status(503).json({ error: "No OpenRouter API keys available" });
    }

    const modelCandidates = await getOpenRouterModels(keyData.key);
    const requestModels = buildOpenRouterRequestModels(modelCandidates);

    try {
      const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${keyData.key}`,
          "Content-Type": "application/json",
          "HTTP-Referer": primaryFrontendUrl,
          "X-Title": "AI Chat Fusion",
        },
        body: JSON.stringify({
          models: requestModels,
          provider: {
            allow_fallbacks: true,
            sort: "throughput",
          },
          messages: [
            {
              role: "system",
              content: "You are OpenRouter AI, a flexible AI assistant.",
            },
            { role: "user", content: message },
          ],
          max_tokens: 1000,
          temperature: 0.5,
        }),
      });

      const raw = await response.text();

      if (response.ok) {
        const data = JSON.parse(raw);
        const content = extractOpenRouterContent(data);
        if (!content) {
          attemptErrors.push("OpenRouter: empty content");
          continue;
        }

        return res.json({
          content,
          model: data?.model || "openrouter/free",
          source: "openrouter",
          success: true,
        });
      }

      const details = parseErrorMessage(
        raw,
        `OpenRouter API error (${response.status})`,
      );
      attemptErrors.push(`${response.status}: ${details}`);

      if (response.status === 401 || response.status === 429) {
        rotateKeyOnFailure(req.session, "openrouter");
        continue;
      }

      if (response.status === 400 || response.status === 404) {
        invalidateOpenRouterModelCache();
      }
    } catch (error) {
      const details =
        error instanceof Error ? error.message : "Unknown OpenRouter error";
      attemptErrors.push(`network: ${compactText(details)}`);
    }
  }

  return res.status(503).json({
    error: "All OpenRouter attempts failed",
    details: compactText(attemptErrors.join(" | "), 500),
    success: false,
  });
});

// Proxy endpoint for xAI (Grok) via FastRouter API
app.post("/api/proxy/xai", authenticateSession, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: "Message required" });

  const keyData = getNextKey(req.session, "fastrouter", "FASTROUTER_API_KEY");
  if (!keyData)
    return res
      .status(503)
      .json({ error: "No FastRouter API keys available for xAI" });

  try {
    const response = await fetch(
      "https://go.fastrouter.ai/api/v1/chat/completions",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${keyData.key}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: "x-ai/grok-3-beta",
          messages: [
            {
              role: "system",
              content:
                "You are Grok, an AI assistant by xAI. Be helpful, witty, and insightful.",
            },
            { role: "user", content: message },
          ],
          max_tokens: 2048,
          temperature: 0.7,
        }),
      },
    );

    if (!response.ok) {
      if (response.status === 429 || response.status === 401)
        rotateKeyOnFailure(req.session, "fastrouter");
      return res
        .status(response.status)
        .json({ error: "xAI API error", status: response.status });
    }

    const data = await response.json();
    res.json({
      content: data.choices?.[0]?.message?.content || "",
      model: "x-ai/grok-3-beta",
      source: "xai",
      success: true,
    });
  } catch {
    res.status(500).json({ error: "Failed to call xAI API", success: false });
  }
});

// Proxy endpoint for OpenAI-compatible API via SambaNova
app.post("/api/proxy/openai", authenticateSession, async (req, res) => {
  const { message, model } = req.body;
  if (!message) return res.status(400).json({ error: "Message required" });
  const requestedModel =
    typeof model === "string" && model.trim().length > 0 ? model.trim() : null;

  if (!requestedModel) {
    const fastRouterKeyData = getNextKey(
      req.session,
      "fastrouter",
      "FASTROUTER_API_KEY",
    );
    if (!fastRouterKeyData) {
      return res.status(503).json({
        error: "No FastRouter API keys available for OpenAI",
        success: false,
      });
    }

    try {
      const fastRouterResponse = await fetch(
        "https://go.fastrouter.ai/api/v1/chat/completions",
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${fastRouterKeyData.key}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model: "openai/gpt-4o",
            messages: [
              { role: "system", content: "You are a helpful AI assistant." },
              { role: "user", content: message },
            ],
            max_tokens: 1000,
            temperature: 0.7,
          }),
        },
      );

      if (!fastRouterResponse.ok) {
        if (
          fastRouterResponse.status === 429 ||
          fastRouterResponse.status === 401
        ) {
          rotateKeyOnFailure(req.session, "fastrouter");
        }

        return res.status(fastRouterResponse.status).json({
          error: "OpenAI API error",
          status: fastRouterResponse.status,
          success: false,
        });
      }

      const fastRouterData = await fastRouterResponse.json();
      return res.json({
        content: fastRouterData.choices?.[0]?.message?.content || "",
        model: fastRouterData?.model || "openai/gpt-4o",
        source: "openai",
        success: true,
      });
    } catch {
      return res.status(500).json({
        error: "Failed to call OpenAI API",
        success: false,
      });
    }
  }

  const keys = extractKeys("SAMBANOVAAI_API_KEY");
  const maxRetries = Math.min(keys.length, 5);
  const attemptErrors = [];

  if (maxRetries === 0) {
    return res.status(503).json({
      error: "No SambaNova API keys available",
      success: false,
    });
  }

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const keyData = getNextKey(req.session, "openai", "SAMBANOVAAI_API_KEY");
    if (!keyData) {
      return res.status(503).json({
        error: "No SambaNova API keys available",
        success: false,
      });
    }

    const selectedModel = requestedModel;

    try {
      const response = await fetch(
        "https://api.sambanova.ai/v1/chat/completions",
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${keyData.key}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model: selectedModel,
            messages: [
              { role: "system", content: "You are a helpful AI assistant." },
              { role: "user", content: message },
            ],
            max_tokens: 1000,
            temperature: 0.7,
          }),
        },
      );

      const raw = await response.text();

      if (response.ok) {
        const data = JSON.parse(raw);
        const content = data?.choices?.[0]?.message?.content;
        if (!content || !content.trim()) {
          attemptErrors.push(`${selectedModel}: empty response`);
          continue;
        }

        return res.json({
          content,
          model: data?.model || selectedModel,
          source: "openai",
          success: true,
        });
      }

      const details = parseErrorMessage(
        raw,
        `SambaNova API error (${response.status})`,
      );
      attemptErrors.push(`${selectedModel} (${response.status}): ${details}`);

      if (response.status === 400 || response.status === 404) {
        invalidateSambaNovaModelCache();
      }

      if (response.status === 401 || response.status === 429) {
        rotateKeyOnFailure(req.session, "openai");
      }
    } catch (error) {
      const details =
        error instanceof Error ? error.message : "Unknown SambaNova error";
      attemptErrors.push(`${selectedModel}: ${compactText(details)}`);
      rotateKeyOnFailure(req.session, "openai");
    }
  }

  return res.status(503).json({
    error: "SambaNova request failed for selected model",
    details: compactText(attemptErrors.join(" | "), 500),
    success: false,
  });
});

// Proxy endpoint for FastRouter (Anthropic Claude) API
app.post("/api/proxy/fastrouter", authenticateSession, async (req, res) => {
  const { message, model } = req.body;
  if (!message) return res.status(400).json({ error: "Message required" });

  const keyData = getNextKey(req.session, "fastrouter", "FASTROUTER_API_KEY");
  if (!keyData)
    return res.status(503).json({ error: "No FastRouter API keys available" });

  const requestedModel =
    typeof model === "string" && model.trim().length > 0 ? model.trim() : null;
  const availableModels = await getFastRouterModels(keyData.key);

  if (requestedModel && !availableModels.includes(requestedModel)) {
    return res.status(400).json({
      error: "Unsupported FastRouter model",
      success: false,
    });
  }

  const selectedModel =
    requestedModel ||
    availableModels[Math.floor(Date.now() / 1000) % availableModels.length];

  try {
    const response = await fetch(
      "https://go.fastrouter.ai/api/v1/chat/completions",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${keyData.key}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: selectedModel,
          messages: [
            {
              role: "system",
              content:
                "You are Claude, an AI assistant by Anthropic. Be helpful and honest.",
            },
            { role: "user", content: message },
          ],
          max_tokens: 2048,
          temperature: 0.7,
        }),
      },
    );

    if (!response.ok) {
      if (response.status === 429 || response.status === 401)
        rotateKeyOnFailure(req.session, "fastrouter");
      return res
        .status(response.status)
        .json({ error: "FastRouter API error", status: response.status });
    }

    const data = await response.json();
    res.json({
      content: data.choices?.[0]?.message?.content || "",
      model: selectedModel,
      source: "fastrouter",
      success: true,
    });
  } catch {
    res
      .status(500)
      .json({ error: "Failed to call FastRouter API", success: false });
  }
});

// Proxy endpoint for FastRouter Image Generation / Editing API
app.post("/api/proxy/image-generate", authenticateSession, async (req, res) => {
  const { prompt, model, image } = req.body;
  if (!prompt) return res.status(400).json({ error: "Prompt required" });

  const keyData = getNextKey(req.session, "fastrouter", "FASTROUTER_API_KEY");
  if (!keyData)
    return res.status(503).json({ error: "No FastRouter API keys available" });

  const isEditRequest = !!image;
  const imageModel = model || (isEditRequest ? "openai/dall-e-2" : "openai/dall-e-3");

  try {
    let response;

    if (isEditRequest) {
      const imageData = parseBase64Image(image);
      if (imageData.error) {
        return res.status(400).json({ error: imageData.error });
      }

      const imageBuffer = Buffer.from(imageData.base64Data, "base64");
      if (!imageBuffer.length) {
        return res.status(400).json({ error: "Invalid image data" });
      }
      const formData = new FormData();
      formData.append("model", imageModel);
      formData.append("prompt", prompt);
      formData.append("n", "1");
      formData.append("size", "1024x1024");
      formData.append(
        "image",
        imageBuffer,
        {
          filename: "image.png",
          contentType: imageData.mimeType,
          knownLength: imageBuffer.length,
        },
      );

      let contentLength;
      try {
        contentLength = await new Promise((resolve, reject) => {
          formData.getLength((err, length) => {
            if (err) reject(err);
            else resolve(Number(length));
          });
        });
      } catch (error) {
        return res.status(500).json({
          error: "Failed to calculate image size",
          details: error instanceof Error ? error.message : String(error),
          success: false,
        });
      }

      const formHeaders = formData.getHeaders();
      if (!Number.isFinite(contentLength)) {
        return res.status(500).json({
          error: "Failed to calculate image size",
          details: "Invalid content length for image payload",
          success: false,
        });
      }

      const requestHeaders = {
        Authorization: `Bearer ${keyData.key}`,
        ...formHeaders,
        "Content-Length": String(contentLength),
      };

      let primaryError = null;
      try {
        response = await fetch(
          "https://go.fastrouter.ai/api/v1/images/edits",
          {
            method: "POST",
            headers: requestHeaders,
            body: formData,
            duplex: "half",
          },
        );
      } catch (error) {
        primaryError = error;
      }

      if (!response) {
        const fallbackBody = formData.getBuffer();
        try {
          response = await fetch(
            "https://go.fastrouter.ai/api/v1/images/edits",
            {
              method: "POST",
              headers: {
                Authorization: `Bearer ${keyData.key}`,
                ...formHeaders,
                "Content-Length": String(fallbackBody.length),
              },
              body: fallbackBody,
            },
          );
        } catch (fallbackError) {
          if (fallbackError instanceof Error) {
            fallbackError.cause = primaryError;
          }
          throw fallbackError;
        }
      }
    } else {
      response = await fetch(
        "https://go.fastrouter.ai/api/v1/images/generations",
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${keyData.key}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model: imageModel,
            prompt,
            n: 1,
            size: "1024x1024",
          }),
        },
      );
    }

    if (!response.ok) {
      if (response.status === 429 || response.status === 401)
        rotateKeyOnFailure(req.session, "fastrouter");
      const errorText = await response.text();
      return res.status(response.status).json({
        error: "Image generation failed",
        status: response.status,
        details: errorText,
        success: false,
      });
    }

    const data = await response.json();
    let imageUrl = data.data?.[0]?.url;
    const b64Json = data.data?.[0]?.b64_json;

    if (b64Json && !imageUrl) imageUrl = `data:image/png;base64,${b64Json}`;

    res.json({
      success: true,
      imageUrl,
      model: imageModel,
      source: "fastrouter",
    });
  } catch (error) {
    const details = error instanceof Error ? error.message : String(error);
    const cause =
      error instanceof Error && error.cause
        ? error.cause instanceof Error
          ? error.cause.message
          : String(error.cause)
        : undefined;
    console.error("Image generation error:", error);
    res.status(500).json({
      error: "Failed to generate image",
      details,
      cause,
      success: false,
    });
  }
});

function getPrimaryKey(baseKeyName) {
  const keys = extractKeys(baseKeyName);
  return keys.length > 0 ? keys[0] : null;
}

function normalizeExternalUrl(rawUrl) {
  if (typeof rawUrl !== "string" || !rawUrl.trim()) {
    throw new Error("URL is required");
  }

  const trimmed = rawUrl.trim();
  const normalized = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  return new URL(normalized).toString();
}

function createFounderSource({
  type,
  title,
  summary,
  content,
  url,
  provider,
  tags = [],
  metadata = {},
}) {
  const timestamp = Date.now();
  return {
    id: `source_${timestamp}_${Math.random().toString(36).slice(2, 10)}`,
    type,
    title,
    summary,
    content,
    url,
    provider,
    tags,
    metadata,
    status: "ready",
    createdAt: timestamp,
    updatedAt: timestamp,
  };
}

function dataUrlToBuffer(dataUrl) {
  if (typeof dataUrl !== "string") {
    throw new Error("Audio payload is required");
  }

  const match = dataUrl.match(/^data:(.+?);base64,(.+)$/);
  if (!match) {
    throw new Error("Audio payload must be a base64 data URL");
  }

  return {
    mimeType: match[1],
    buffer: Buffer.from(match[2], "base64"),
  };
}

function buildFounderExportMarkdown(workspace) {
  const lines = [];
  const brief = workspace?.brief || {};
  const artifacts = Array.isArray(workspace?.artifacts) ? workspace.artifacts : [];
  const sources = Array.isArray(workspace?.sources) ? workspace.sources : [];
  const rehearsalSessions = Array.isArray(workspace?.rehearsalSessions)
    ? workspace.rehearsalSessions
    : [];

  lines.push(`# ${brief.startupName || workspace?.name || "Founder War Room Export"}`);
  lines.push("");
  lines.push(`Generated: ${new Date().toLocaleString()}`);
  lines.push("");
  lines.push("## Brief");
  lines.push("");
  lines.push(`- Tagline: ${brief.tagline || "Not set"}`);
  lines.push(`- Market: ${brief.market || "Not set"}`);
  lines.push(`- Target Customer: ${brief.targetCustomer || "Not set"}`);
  lines.push(`- Stage: ${brief.stage || "Not set"}`);
  lines.push(`- Business Model: ${brief.businessModel || "Not set"}`);
  lines.push("");
  lines.push("### Problem");
  lines.push(brief.problem || "Not set");
  lines.push("");
  lines.push("### Solution");
  lines.push(brief.solution || "Not set");
  lines.push("");
  lines.push("### Goals");
  lines.push(brief.goals || "Not set");
  lines.push("");
  lines.push("### Differentiation");
  lines.push(brief.differentiation || "Not set");
  lines.push("");
  lines.push("## Evidence");
  lines.push("");

  if (sources.length === 0) {
    lines.push("No sources captured.");
    lines.push("");
  } else {
    sources.forEach((source) => {
      lines.push(`### ${source.title || "Untitled source"}`);
      lines.push(`- Type: ${source.type || "unknown"}`);
      if (source.url) lines.push(`- URL: ${source.url}`);
      if (source.provider) lines.push(`- Provider: ${source.provider}`);
      lines.push("");
      lines.push(source.summary || source.content || "No summary available.");
      lines.push("");
    });
  }

  lines.push("## Startup Pack");
  lines.push("");

  artifacts.forEach((artifact) => {
    lines.push(`### ${artifact.title || artifact.type || "Artifact"}`);
    lines.push("");
    if (artifact.imageUrl) {
      lines.push(`Image: ${artifact.imageUrl}`);
      lines.push("");
    }

    const currentVersion = Array.isArray(artifact.versions)
      ? artifact.versions.find((version) => version.id === artifact.currentVersionId)
      : null;
    lines.push(currentVersion?.content || "Not generated yet.");
    lines.push("");
  });

  if (rehearsalSessions.length > 0) {
    const latest = rehearsalSessions[0];
    lines.push("## Latest Rehearsal");
    lines.push("");
    lines.push("### Transcript");
    lines.push(latest.transcript || "Not available");
    lines.push("");
    lines.push("### Critique");
    lines.push(latest.critique || "Not available");
    lines.push("");
    lines.push("### Improved Script");
    lines.push(latest.improvedScript || "Not available");
    lines.push("");
  }

  return lines.join("\n");
}

async function runTavilySearch(queryText) {
  const apiKey = getPrimaryKey("TAVILY_API_KEY");
  if (!apiKey) {
    throw new Error("No Tavily API key configured");
  }

  const response = await fetch("https://api.tavily.com/search", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      query: queryText,
      search_depth: "advanced",
      max_results: 6,
      include_answer: true,
      include_raw_content: false,
    }),
  });

  if (!response.ok) {
    const raw = await response.text();
    throw new Error(parseErrorMessage(raw, `Tavily search failed (${response.status})`));
  }

  return response.json();
}

async function scrapeWithFirecrawl(url) {
  const apiKey = getPrimaryKey("FIRECRAWL_API_KEY");
  if (!apiKey) {
    throw new Error("No Firecrawl API key configured");
  }

  const response = await fetch("https://api.firecrawl.dev/v2/scrape", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      url,
      formats: ["markdown", "links", { type: "summary" }],
      onlyMainContent: true,
    }),
  });

  if (!response.ok) {
    const raw = await response.text();
    throw new Error(parseErrorMessage(raw, `Firecrawl scrape failed (${response.status})`));
  }

  return response.json();
}

async function fetchWithJinaReader(url) {
  const apiKey = getPrimaryKey("JINA_API_KEY");
  const readerUrl = `https://r.jina.ai/http://${url.replace(/^https?:\/\//i, "")}`;
  const response = await fetch(readerUrl, {
    headers: apiKey
      ? {
          Authorization: `Bearer ${apiKey}`,
        }
      : undefined,
  });

  if (!response.ok) {
    const raw = await response.text();
    throw new Error(parseErrorMessage(raw, `Jina reader failed (${response.status})`));
  }

  return response.text();
}

async function transcribeWithDeepgram(audioBuffer, mimeType) {
  const apiKey = getPrimaryKey("DEEPGRAM_API_KEY");
  if (!apiKey) {
    throw new Error("No Deepgram API key configured");
  }

  const response = await fetch(
    "https://api.deepgram.com/v1/listen?model=nova-3&smart_format=true&filler_words=false",
    {
      method: "POST",
      headers: {
        Authorization: `Token ${apiKey}`,
        "Content-Type": mimeType || "audio/webm",
      },
      body: audioBuffer,
    },
  );

  if (!response.ok) {
    const raw = await response.text();
    throw new Error(parseErrorMessage(raw, `Deepgram transcription failed (${response.status})`));
  }

  return response.json();
}

async function synthesizeWithElevenLabs(text) {
  const apiKey = getPrimaryKey("ELEVENLABS_API_KEY");
  const voiceId = process.env.ELEVENLABS_VOICE_ID;
  if (!apiKey || !voiceId) {
    throw new Error("ElevenLabs voice synthesis is not configured");
  }

  const response = await fetch(
    `https://api.elevenlabs.io/v1/text-to-speech/${voiceId}?output_format=mp3_44100_128`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "xi-api-key": apiKey,
      },
      body: JSON.stringify({
        text,
        model_id: "eleven_flash_v2_5",
        voice_settings: {
          stability: 0.45,
          similarity_boost: 0.8,
          style: 0.15,
          use_speaker_boost: true,
        },
      }),
    },
  );

  if (!response.ok) {
    const raw = await response.text();
    throw new Error(parseErrorMessage(raw, `ElevenLabs synthesis failed (${response.status})`));
  }

  const audioBuffer = Buffer.from(await response.arrayBuffer());
  return `data:audio/mpeg;base64,${audioBuffer.toString("base64")}`;
}

app.post("/api/founder/research/search", authenticateSession, async (req, res) => {
  const { query: inputQuery, workspaceSummary } = req.body || {};
  if (!inputQuery || typeof inputQuery !== "string") {
    return res.status(400).json({ error: "Search query is required" });
  }

  try {
    const queryText = workspaceSummary
      ? `${inputQuery}\n\nContext:\n${compactText(workspaceSummary, 500)}`
      : inputQuery;
    const data = await runTavilySearch(queryText);
    const results = Array.isArray(data?.results)
      ? data.results.map((item, index) =>
          createFounderSource({
            type: "search",
            title: item?.title || `Search result ${index + 1}`,
            summary: compactText(item?.content || item?.answer || "", 600),
            content: compactText(item?.content || item?.raw_content || "", 4000),
            url: item?.url,
            provider: "tavily",
            tags: ["research"],
            metadata: {
              score: typeof item?.score === "number" ? item.score : null,
            },
          }),
        )
      : [];

    return res.json({
      answer: typeof data?.answer === "string" ? data.answer : "",
      results,
    });
  } catch (error) {
    return res.status(500).json({
      error: "Failed to run market research search",
      details: error instanceof Error ? error.message : String(error),
    });
  }
});

app.post("/api/founder/research/ingest-url", authenticateSession, async (req, res) => {
  const { url: rawUrl } = req.body || {};
  if (!rawUrl || typeof rawUrl !== "string") {
    return res.status(400).json({ error: "URL is required" });
  }

  try {
    const normalizedUrl = normalizeExternalUrl(rawUrl);
    let provider = "firecrawl";
    let title = new URL(normalizedUrl).hostname.replace(/^www\./, "");
    let summary = "";
    let content = "";

    try {
      const data = await scrapeWithFirecrawl(normalizedUrl);
      const scrapeData = data?.data || data;
      title =
        scrapeData?.metadata?.title ||
        scrapeData?.title ||
        title;
      summary = compactText(
        scrapeData?.summary ||
          scrapeData?.metadata?.description ||
          scrapeData?.markdown ||
          "",
        700,
      );
      content = compactText(scrapeData?.markdown || "", 6000);
    } catch (firecrawlError) {
      provider = "jina";
      const readerText = await fetchWithJinaReader(normalizedUrl);
      content = compactText(readerText, 6000);
      summary = compactText(readerText, 700);
      if (firecrawlError instanceof Error) {
        console.warn(`[Founder] Firecrawl failed, using Jina fallback: ${firecrawlError.message}`);
      }
    }

    const source = createFounderSource({
      type: "url",
      title,
      summary: summary || `Captured content from ${normalizedUrl}`,
      content,
      url: normalizedUrl,
      provider,
      tags: ["url-ingest"],
    });

    return res.json({ source });
  } catch (error) {
    return res.status(500).json({
      error: "Failed to ingest URL",
      details: error instanceof Error ? error.message : String(error),
    });
  }
});

app.post("/api/founder/rehearsal/transcribe", authenticateSession, async (req, res) => {
  const { audioDataUrl } = req.body || {};
  if (!audioDataUrl || typeof audioDataUrl !== "string") {
    return res.status(400).json({ error: "Audio payload is required" });
  }

  try {
    const { buffer, mimeType } = dataUrlToBuffer(audioDataUrl);
    const data = await transcribeWithDeepgram(buffer, mimeType);
    const transcript =
      data?.results?.channels?.[0]?.alternatives?.[0]?.transcript || "";

    if (!transcript.trim()) {
      return res.status(422).json({
        error: "Deepgram did not return a transcript",
      });
    }

    return res.json({ transcript: transcript.trim() });
  } catch (error) {
    return res.status(500).json({
      error: "Failed to transcribe pitch",
      details: error instanceof Error ? error.message : String(error),
    });
  }
});

app.post("/api/founder/rehearsal/synthesize", authenticateSession, async (req, res) => {
  const { text } = req.body || {};
  if (!text || typeof text !== "string") {
    return res.status(400).json({ error: "Text is required" });
  }

  try {
    const audioDataUrl = await synthesizeWithElevenLabs(text);
    return res.json({ audioDataUrl });
  } catch (error) {
    return res.status(500).json({
      error: "Failed to synthesize pitch audio",
      details: error instanceof Error ? error.message : String(error),
    });
  }
});

app.post("/api/founder/export/markdown", authenticateSession, (req, res) => {
  const { workspace } = req.body || {};
  if (!workspace || typeof workspace !== "object") {
    return res.status(400).json({ error: "Workspace payload is required" });
  }

  try {
    const markdown = buildFounderExportMarkdown(workspace);
    return res.json({ markdown });
  } catch (error) {
    return res.status(500).json({
      error: "Failed to export workspace",
      details: error instanceof Error ? error.message : String(error),
    });
  }
});

function slugify(value) {
  return String(value || "local-growth")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function createLocalGrowthSource({
  type,
  title,
  summary,
  content,
  url,
  provider,
  tags = [],
  metadata = {},
  locationId,
}) {
  const timestamp = Date.now();
  return {
    id: `local_source_${timestamp}_${Math.random().toString(36).slice(2, 10)}`,
    type,
    title,
    summary,
    content,
    url,
    provider,
    tags,
    metadata,
    locationId,
    status: "ready",
    createdAt: timestamp,
    updatedAt: timestamp,
  };
}

function createCompetitorProfile({
  name,
  url,
  summary,
  positioning = "",
  pricingSignal = "",
  reviewThemes = [],
  strengths = [],
  gaps = [],
  distanceKm,
  locationId,
  citations = [],
}) {
  return {
    id: `competitor_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`,
    name,
    url,
    summary,
    positioning,
    pricingSignal,
    reviewThemes,
    strengths,
    gaps,
    distanceKm,
    locationId,
    citations,
    updatedAt: Date.now(),
  };
}

function getLocalGrowthFeatureAvailability() {
  const posthogKey =
    process.env.POSTHOG_PROJECT_API_KEY ||
    process.env.POSTHOG_API_KEY ||
    process.env.POSTHOG_KEY;
  const appwriteReady =
    Boolean(process.env.APPWRITE_PROJECT_ID) &&
    Boolean(process.env.APPWRITE_ENDPOINT) &&
    Boolean(process.env.APPWRITE_API_KEY) &&
    Boolean(process.env.APPWRITE_BUCKET_ID);

  return {
    research:
      Boolean(getPrimaryKey("TAVILY_API_KEY")) ||
      Boolean(getPrimaryKey("FIRECRAWL_API_KEY")) ||
      Boolean(getPrimaryKey("JINA_API_KEY")),
    geo:
      Boolean(process.env.HERE_API_KEY) ||
      Boolean(process.env.OPENCAGE_API_KEY) ||
      Boolean(process.env.MAPBOX_ACCESS_TOKEN),
    voice:
      Boolean(getPrimaryKey("DEEPGRAM_API_KEY")) ||
      Boolean(getPrimaryKey("ELEVENLABS_API_KEY")),
    sharing: appwriteReady,
    approvals: false,
    analytics: Boolean(process.env.POSTHOG_HOST) && Boolean(posthogKey),
    leadAgent: false,
    creativeLab:
      Boolean(getPrimaryKey("FASTROUTER_API_KEY")) ||
      Boolean(process.env.REPLICATE_API_TOKEN) ||
      Boolean(process.env.HUGGINGFACE_API_KEY),
  };
}

function dedupeLocalGrowthSources(sources) {
  const merged = new Map();
  sources
    .filter(Boolean)
    .forEach((source) => {
      const key = source.url || `${source.type}:${source.title}`.toLowerCase();
      const current = merged.get(key);
      if (!current || (source.updatedAt || 0) >= (current.updatedAt || 0)) {
        merged.set(key, source);
      }
    });
  return Array.from(merged.values()).sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
}

function dedupeCompetitorProfiles(competitors) {
  const merged = new Map();
  competitors
    .filter(Boolean)
    .forEach((competitor) => {
      const key =
        competitor.url ||
        `${competitor.name}:${competitor.locationId || "global"}`.toLowerCase();
      const current = merged.get(key);
      if (!current || (competitor.updatedAt || 0) >= (current.updatedAt || 0)) {
        merged.set(key, competitor);
      }
    });
  return Array.from(merged.values()).sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
}

async function geocodeWithHere(queryText) {
  const apiKey = process.env.HERE_API_KEY;
  if (!apiKey) return null;

  const response = await fetch(
    `https://geocode.search.hereapi.com/v1/geocode?q=${encodeURIComponent(queryText)}&apiKey=${apiKey}`,
  );

  if (!response.ok) {
    const raw = await response.text();
    throw new Error(parseErrorMessage(raw, `HERE geocode failed (${response.status})`));
  }

  const data = await response.json();
  const item = data?.items?.[0];
  if (!item?.position) return null;

  return {
    provider: "here",
    lat: item.position.lat,
    lng: item.position.lng,
    city: item.address?.city || item.address?.district || "",
    region: item.address?.state || "",
    postalCode: item.address?.postalCode || "",
    country: item.address?.countryName || item.address?.countryCode || "",
    timezone: item.timeZone?.name || "",
    label: item.address?.label || "",
  };
}

async function geocodeWithOpenCage(queryText) {
  const apiKey = process.env.OPENCAGE_API_KEY;
  if (!apiKey) return null;

  const response = await fetch(
    `https://api.opencagedata.com/geocode/v1/json?q=${encodeURIComponent(queryText)}&key=${apiKey}&limit=1&no_annotations=0`,
  );

  if (!response.ok) {
    const raw = await response.text();
    throw new Error(parseErrorMessage(raw, `OpenCage geocode failed (${response.status})`));
  }

  const data = await response.json();
  const item = data?.results?.[0];
  if (!item?.geometry) return null;

  return {
    provider: "opencage",
    lat: item.geometry.lat,
    lng: item.geometry.lng,
    city:
      item.components?.city ||
      item.components?.town ||
      item.components?.village ||
      "",
    region: item.components?.state || "",
    postalCode: item.components?.postcode || "",
    country: item.components?.country || "",
    timezone: item.annotations?.timezone?.name || "",
    label: item.formatted || "",
  };
}

async function geocodeWithMapbox(queryText) {
  const apiKey = process.env.MAPBOX_ACCESS_TOKEN;
  if (!apiKey) return null;

  const response = await fetch(
    `https://api.mapbox.com/geocoding/v5/mapbox.places/${encodeURIComponent(queryText)}.json?limit=1&access_token=${apiKey}`,
  );

  if (!response.ok) {
    const raw = await response.text();
    throw new Error(parseErrorMessage(raw, `Mapbox geocode failed (${response.status})`));
  }

  const data = await response.json();
  const item = data?.features?.[0];
  if (!item?.center) return null;

  const context = Array.isArray(item.context) ? item.context : [];
  const city = context.find((entry) => entry.id?.startsWith("place"))?.text || "";
  const region = context.find((entry) => entry.id?.startsWith("region"))?.text || "";
  const country = context.find((entry) => entry.id?.startsWith("country"))?.text || "";
  const postalCode = context.find((entry) => entry.id?.startsWith("postcode"))?.text || "";

  return {
    provider: "mapbox",
    lat: item.center[1],
    lng: item.center[0],
    city,
    region,
    postalCode,
    country,
    timezone: "",
    label: item.place_name || "",
  };
}

async function enrichLocationPayload(payload) {
  const queryText = [
    payload.addressLine,
    payload.city,
    payload.region,
    payload.postalCode,
    payload.country,
  ]
    .filter(Boolean)
    .join(", ");

  let geo = null;
  try {
    geo = (await geocodeWithHere(queryText)) || geo;
  } catch (error) {
    console.warn(`[Local Growth] HERE geocode failed: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!geo) {
    try {
      geo = (await geocodeWithOpenCage(queryText)) || geo;
    } catch (error) {
      console.warn(`[Local Growth] OpenCage geocode failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  if (!geo) {
    try {
      geo = (await geocodeWithMapbox(queryText)) || geo;
    } catch (error) {
      console.warn(`[Local Growth] Mapbox geocode failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  return {
    id: `location_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`,
    name: payload.name || payload.city || payload.addressLine || "Location",
    addressLine: payload.addressLine || geo?.label || "",
    city: payload.city || geo?.city || "",
    region: payload.region || geo?.region || "",
    postalCode: payload.postalCode || geo?.postalCode || "",
    country: payload.country || geo?.country || "",
    coordinates: geo
      ? {
          lat: geo.lat,
          lng: geo.lng,
        }
      : undefined,
    serviceRadiusKm: Number(payload.serviceRadiusKm || 10),
    timezone: geo?.timezone || "",
    notes: payload.notes || "",
    provider: geo?.provider || "manual",
    updatedAt: Date.now(),
  };
}

function buildStaticMapUrl(locations) {
  const token = process.env.MAPBOX_ACCESS_TOKEN;
  if (!token) return null;

  const markers = locations
    .filter((location) => location.coordinates)
    .slice(0, 6)
    .map(
      (location, index) =>
        `pin-s-${index % 2 === 0 ? "1d4ed8" : "0f766e"}(${location.coordinates.lng},${location.coordinates.lat})`,
    );

  if (markers.length === 0) return null;

  return `https://api.mapbox.com/styles/v1/mapbox/light-v11/static/${markers.join(",")}/auto/1000x420?padding=60&access_token=${token}`;
}

function inferBrandSnapshot(websiteUrl, scrapedTitle, summary, brandNotes) {
  let hostname = "";
  try {
    hostname = new URL(websiteUrl).hostname.replace(/^www\./, "");
  } catch {
    hostname = websiteUrl;
  }

  const titleText = scrapedTitle || hostname;
  const clientName = titleText
    .split(/[-|]/)[0]
    .replace(/\.(com|co|io|ai|net|org)$/i, "")
    .trim();

  return {
    clientName,
    websiteUrl,
    differentiators: summary || brandNotes || "",
    proofPoints: brandNotes || "",
    brandNotes: brandNotes || "",
  };
}

function computeVisibilityAudit(workspace, sources, competitors, locationIds) {
  const websiteText = sources
    .filter((source) => source.type === "website")
    .map((source) => `${source.summary || ""}\n${source.content || ""}`)
    .join("\n")
    .toLowerCase();
  const brandText = [
    workspace?.brand?.coreOffer,
    workspace?.brand?.goals,
    workspace?.brand?.differentiators,
    websiteText,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  const locationTerms = Array.isArray(workspace?.locations)
    ? workspace.locations
        .filter((location) => locationIds.includes(location.id))
        .flatMap((location) => [location.city, location.region, location.country])
        .filter(Boolean)
    : [];

  const termMatches = locationTerms.filter((term) =>
    brandText.includes(String(term).toLowerCase()),
  ).length;
  const localIntentCoverage = locationTerms.length
    ? Math.min(100, Math.round((termMatches / locationTerms.length) * 100))
    : 45;

  const trustWords = ["review", "testimonial", "award", "trusted", "years", "guarantee"];
  const geoWords = ["location", "near", "service area", "city", "address", "map"];
  const conversionWords = ["book", "schedule", "contact", "call", "quote", "demo"];

  const trustSignals = Math.min(
    100,
    trustWords.filter((word) => brandText.includes(word)).length * 18 + 28,
  );
  const geoSignals = Math.min(
    100,
    geoWords.filter((word) => brandText.includes(word)).length * 18 + 22,
  );
  const offerClarity = workspace?.brand?.coreOffer ? 82 : 38;
  const conversionClarity = Math.min(
    100,
    conversionWords.filter((word) => brandText.includes(word)).length * 20 + 20,
  );

  const score = Math.round(
    (localIntentCoverage + trustSignals + geoSignals + offerClarity + conversionClarity) / 5,
  );

  const opportunities = [];
  const risks = [];
  if (localIntentCoverage < 70) opportunities.push("Add city and service-area language to core pages and offers.");
  if (trustSignals < 70) opportunities.push("Surface stronger proof such as reviews, guarantees, and named case studies.");
  if (conversionClarity < 70) opportunities.push("Tighten CTAs and conversion paths on local landing pages.");
  if (competitors.length > 0) opportunities.push("Build comparison pages against the strongest nearby competitors.");
  if (geoSignals < 60) risks.push("Geo relevance is weak, which can reduce local discoverability.");
  if (trustSignals < 60) risks.push("Trust signals are thin relative to the category.");
  if (!workspace?.brand?.coreOffer) risks.push("Core offer is not clearly defined in the workspace.");

  return {
    id: `audit_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`,
    title: `${workspace?.brand?.clientName || "Client"} readiness audit`,
    summary:
      score >= 75
        ? "The workspace has a strong base for localized campaigns, but still needs tighter proof and location-specific execution."
        : "The workspace needs stronger geo relevance, proof signals, and conversion clarity before it will perform like a local growth engine.",
    score,
    metrics: {
      localIntentCoverage,
      trustSignals,
      geoSignals,
      offerClarity,
      conversionClarity,
    },
    opportunities,
    risks,
    citations: sources
      .slice(0, 8)
      .map((source) => source.url || source.title)
      .filter(Boolean),
    competitorIds: competitors.slice(0, 8).map((competitor) => competitor.id),
    locationIds,
    staticMapUrl: buildStaticMapUrl(
      Array.isArray(workspace?.locations)
        ? workspace.locations.filter((location) => locationIds.includes(location.id))
        : [],
    ),
    updatedAt: Date.now(),
  };
}

function buildLocalGrowthExportMarkdown(workspace) {
  const lines = [];
  lines.push(`# ${workspace?.brand?.clientName || workspace?.name || "Local Growth OS Workspace"}`);
  lines.push("");
  lines.push(`Updated: ${new Date(workspace?.updatedAt || Date.now()).toLocaleString()}`);
  lines.push("");
  lines.push("## Brand");
  lines.push("");
  lines.push(`- Website: ${workspace?.brand?.websiteUrl || "Not set"}`);
  lines.push(`- Vertical: ${workspace?.brand?.vertical || "Not set"}`);
  lines.push(`- Audience: ${workspace?.brand?.targetAudience || "Not set"}`);
  lines.push(`- Core Offer: ${workspace?.brand?.coreOffer || "Not set"}`);
  lines.push(`- Goals: ${workspace?.brand?.goals || "Not set"}`);
  lines.push("");
  lines.push("## Locations");
  lines.push("");
  if (Array.isArray(workspace?.locations) && workspace.locations.length > 0) {
    workspace.locations.forEach((location) => {
      lines.push(`### ${location.name}`);
      lines.push(
        `- ${[
          location.addressLine,
          location.city,
          location.region,
          location.postalCode,
          location.country,
        ]
          .filter(Boolean)
          .join(", ")}`,
      );
      lines.push(`- Radius: ${location.serviceRadiusKm} km`);
      lines.push("");
    });
  } else {
    lines.push("No locations yet.");
    lines.push("");
  }
  lines.push("## Assets");
  lines.push("");
  if (Array.isArray(workspace?.assets)) {
    workspace.assets.forEach((asset) => {
      const content =
        asset?.versions?.find((version) => version.id === asset.currentVersionId)?.content || "";
      lines.push(`### ${asset.title}`);
      if (asset.imageUrl) lines.push(`Image: ${asset.imageUrl}`);
      if (asset.audioUrl) lines.push(`Audio: ${asset.audioUrl}`);
      lines.push("");
      lines.push(content || "Not generated yet.");
      lines.push("");
    });
  }
  return lines.join("\n");
}

app.get("/api/local-growth/features", authenticateSession, (req, res) => {
  return res.json(getLocalGrowthFeatureAvailability());
});

app.post("/api/brand/import", authenticateSession, async (req, res) => {
  const { websiteUrl: rawWebsiteUrl, brandNotes = "" } = req.body || {};
  if (!rawWebsiteUrl || typeof rawWebsiteUrl !== "string") {
    return res.status(400).json({ error: "Website URL is required" });
  }

  try {
    const websiteUrl = normalizeExternalUrl(rawWebsiteUrl);
    const brandHostname = new URL(websiteUrl).hostname.replace(/^www\./, "");

    let provider = "manual";
    let scrapedTitle = brandHostname;
    let summary = compactText(brandNotes || `Imported ${brandHostname}`, 700);
    let content = "";

    if (getPrimaryKey("FIRECRAWL_API_KEY") || getPrimaryKey("JINA_API_KEY")) {
      try {
        if (getPrimaryKey("FIRECRAWL_API_KEY")) {
          const data = await scrapeWithFirecrawl(websiteUrl);
          const scrapeData = data?.data || data;
          provider = "firecrawl";
          scrapedTitle =
            scrapeData?.metadata?.title ||
            scrapeData?.title ||
            scrapedTitle;
          summary = compactText(
            scrapeData?.summary ||
              scrapeData?.metadata?.description ||
              scrapeData?.markdown ||
              summary,
            700,
          );
          content = compactText(scrapeData?.markdown || "", 6000);
        } else if (getPrimaryKey("JINA_API_KEY")) {
          const readerText = await fetchWithJinaReader(websiteUrl);
          provider = "jina";
          summary = compactText(readerText || summary, 700);
          content = compactText(readerText || "", 6000);
        }
      } catch (primaryError) {
        if (getPrimaryKey("JINA_API_KEY") && provider !== "jina") {
          try {
            const readerText = await fetchWithJinaReader(websiteUrl);
            provider = "jina";
            summary = compactText(readerText || summary, 700);
            content = compactText(readerText || "", 6000);
          } catch (fallbackError) {
            console.warn(
              `[Local Growth] URL import fallback failed: ${fallbackError instanceof Error ? fallbackError.message : String(fallbackError)}`,
            );
          }
        }

        if (!content && primaryError instanceof Error) {
          console.warn(
            `[Local Growth] Website import degraded to manual mode: ${primaryError.message}`,
          );
        }
      }
    }

    const inferredSummary = compactText(summary || brandNotes, 220);
    const brandSnapshot = {
      ...inferBrandSnapshot(websiteUrl, scrapedTitle, summary, brandNotes),
      targetAudience: "",
      coreOffer: inferredSummary,
      goals: compactText(brandNotes, 180),
      voiceExamples: "",
      vertical: "",
    };

    const sources = [
      createLocalGrowthSource({
        type: "website",
        title: scrapedTitle || brandSnapshot.clientName || brandHostname,
        summary,
        content,
        url: websiteUrl,
        provider,
        tags: ["brand-import", "website"],
        metadata: {
          hostname: brandHostname,
          inferred: provider === "manual",
        },
      }),
    ];

    const competitors = [];
    const competitorSources = [];

    if (getPrimaryKey("TAVILY_API_KEY")) {
      try {
        const researchQuery = [
          brandSnapshot.clientName || brandHostname,
          brandSnapshot.coreOffer,
          brandNotes,
          "local competitors market positioning reviews",
        ]
          .filter(Boolean)
          .join(" ");
        const searchData = await runTavilySearch(researchQuery);
        const results = Array.isArray(searchData?.results) ? searchData.results : [];

        results
          .filter((item) => item?.url && !String(item.url).includes(brandHostname))
          .slice(0, 5)
          .forEach((item, index) => {
            const competitor = createCompetitorProfile({
              name: item?.title || `Competitor ${index + 1}`,
              url: item?.url,
              summary: compactText(item?.content || item?.answer || "", 500),
              positioning: compactText(item?.title || "", 140),
              pricingSignal: "Unknown",
              reviewThemes: [],
              strengths: ["Visible local presence", "Comparable offer coverage"],
              gaps: ["Positioning can be challenged with stronger proof and geo landing pages"],
              citations: item?.url ? [item.url] : [],
            });

            competitors.push(competitor);
            competitorSources.push(
              createLocalGrowthSource({
                type: "competitor",
                title: item?.title || competitor.name,
                summary: compactText(item?.content || item?.answer || "", 600),
                content: compactText(item?.content || item?.raw_content || "", 4000),
                url: item?.url,
                provider: "tavily",
                tags: ["competitor-discovery", "brand-import"],
                metadata: {
                  score: typeof item?.score === "number" ? item.score : null,
                },
              }),
            );
          });
      } catch (error) {
        console.warn(
          `[Local Growth] Competitor discovery failed during brand import: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }

    return res.json({
      brandSnapshot,
      sources: dedupeLocalGrowthSources([...sources, ...competitorSources]),
      competitors: dedupeCompetitorProfiles(competitors),
    });
  } catch (error) {
    return res.status(500).json({
      error: "Failed to import brand website",
      details: error instanceof Error ? error.message : String(error),
    });
  }
});

app.post("/api/locations/enrich", authenticateSession, async (req, res) => {
  const payload = req.body || {};
  if (!payload.addressLine || typeof payload.addressLine !== "string") {
    return res.status(400).json({ error: "Location address is required" });
  }

  try {
    const location = await enrichLocationPayload(payload);
    const queryLabel = [
      location.addressLine,
      location.city,
      location.region,
      location.country,
    ]
      .filter(Boolean)
      .join(", ");

    const sources = [
      createLocalGrowthSource({
        type: "location",
        title: `${location.name} geo profile`,
        summary: compactText(
          `${queryLabel || location.name} normalized via ${location.provider || "manual"} with a ${location.serviceRadiusKm} km service radius.`,
          320,
        ),
        content: compactText(
          [
            `Address: ${queryLabel || "Not available"}`,
            location.coordinates
              ? `Coordinates: ${location.coordinates.lat}, ${location.coordinates.lng}`
              : "Coordinates: unavailable",
            `Timezone: ${location.timezone || "Unknown"}`,
          ].join("\n"),
          1200,
        ),
        provider: location.provider || "manual",
        tags: ["location-enrichment"],
        locationId: location.id,
        metadata: location.coordinates
          ? {
              lat: location.coordinates.lat,
              lng: location.coordinates.lng,
            }
          : {},
      }),
    ];

    const competitors = [];

    if (getPrimaryKey("TAVILY_API_KEY")) {
      try {
        const searchQuery = [
          payload.brandName || "",
          payload.vertical || "",
          "competitors near",
          location.city || location.addressLine,
          location.region || "",
          location.country || "",
        ]
          .filter(Boolean)
          .join(" ");
        const searchData = await runTavilySearch(searchQuery);
        const results = Array.isArray(searchData?.results) ? searchData.results : [];

        results.slice(0, 4).forEach((item, index) => {
          const competitor = createCompetitorProfile({
            name: item?.title || `Nearby competitor ${index + 1}`,
            url: item?.url,
            summary: compactText(item?.content || item?.answer || "", 420),
            positioning: compactText(item?.title || "", 140),
            pricingSignal: "Unknown",
            reviewThemes: ["Local discoverability", "Service coverage"],
            strengths: ["Visible in local search"],
            gaps: ["Proof depth and geo page quality still need validation"],
            locationId: location.id,
            citations: item?.url ? [item.url] : [],
          });

          competitors.push(competitor);
          sources.push(
            createLocalGrowthSource({
              type: "search",
              title: item?.title || competitor.name,
              summary: compactText(item?.content || item?.answer || "", 540),
              content: compactText(item?.content || item?.raw_content || "", 3200),
              url: item?.url,
              provider: "tavily",
              tags: ["location-intel", slugify(location.name)],
              locationId: location.id,
              metadata: {
                score: typeof item?.score === "number" ? item.score : null,
              },
            }),
          );
        });
      } catch (error) {
        console.warn(
          `[Local Growth] Nearby competitor scan failed: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }

    return res.json({
      location,
      sources: dedupeLocalGrowthSources(sources),
      competitors: dedupeCompetitorProfiles(competitors),
    });
  } catch (error) {
    return res.status(500).json({
      error: "Failed to enrich location",
      details: error instanceof Error ? error.message : String(error),
    });
  }
});

app.post("/api/intel/audit", authenticateSession, async (req, res) => {
  const { workspace, focusLocationIds } = req.body || {};
  if (!workspace || typeof workspace !== "object") {
    return res.status(400).json({ error: "Workspace payload is required" });
  }

  try {
    const allLocations = Array.isArray(workspace.locations) ? workspace.locations : [];
    const activeLocationIds =
      Array.isArray(focusLocationIds) && focusLocationIds.length > 0
        ? focusLocationIds
        : allLocations.slice(0, 6).map((location) => location.id);
    const activeLocations = allLocations.filter((location) =>
      activeLocationIds.includes(location.id),
    );

    const freshSources = [];
    const freshCompetitors = [];
    const brandHostname = workspace?.brand?.websiteUrl
      ? new URL(normalizeExternalUrl(workspace.brand.websiteUrl)).hostname.replace(/^www\./, "")
      : null;

    if (getPrimaryKey("TAVILY_API_KEY")) {
      for (const location of activeLocations.slice(0, 3)) {
        const queryText = [
          workspace?.brand?.clientName || "",
          workspace?.brand?.vertical || "",
          workspace?.brand?.coreOffer || "",
          location.city || location.addressLine,
          location.region || "",
          location.country || "",
          "local competitors reviews trust signals citations",
        ]
          .filter(Boolean)
          .join(" ");

        try {
          const searchData = await runTavilySearch(queryText);
          const results = Array.isArray(searchData?.results) ? searchData.results : [];

          results.slice(0, 4).forEach((item, index) => {
            freshSources.push(
              createLocalGrowthSource({
                type: "search",
                title: item?.title || `${location.name} market signal ${index + 1}`,
                summary: compactText(item?.content || item?.answer || "", 620),
                content: compactText(item?.content || item?.raw_content || "", 3600),
                url: item?.url,
                provider: "tavily",
                tags: ["intel-audit", slugify(location.name)],
                locationId: location.id,
                metadata: {
                  score: typeof item?.score === "number" ? item.score : null,
                },
              }),
            );

            if (!item?.url || (brandHostname && String(item.url).includes(brandHostname))) {
              return;
            }

            freshCompetitors.push(
              createCompetitorProfile({
                name: item?.title || `Competitor ${index + 1}`,
                url: item?.url,
                summary: compactText(item?.content || item?.answer || "", 480),
                positioning: compactText(item?.title || "", 160),
                pricingSignal: "Unknown",
                reviewThemes: ["Local intent", "Category visibility"],
                strengths: ["Ranking presence", "Comparable service narrative"],
                gaps: [
                  "Differentiate with stronger proof, offer specificity, and geo landing pages",
                ],
                locationId: location.id,
                citations: item?.url ? [item.url] : [],
              }),
            );
          });
        } catch (error) {
          console.warn(
            `[Local Growth] Tavily intel query failed for ${location.name}: ${error instanceof Error ? error.message : String(error)}`,
          );
        }
      }
    }

    const mergedSources = dedupeLocalGrowthSources([
      ...(Array.isArray(workspace.sources) ? workspace.sources : []),
      ...freshSources,
    ]);
    const mergedCompetitors = dedupeCompetitorProfiles([
      ...(Array.isArray(workspace.competitors) ? workspace.competitors : []),
      ...freshCompetitors,
    ]);
    const audit = computeVisibilityAudit(
      workspace,
      mergedSources,
      mergedCompetitors,
      activeLocationIds,
    );

    return res.json({
      audit,
      sources: freshSources,
      competitors: freshCompetitors,
      mapUrl: audit.staticMapUrl || null,
    });
  } catch (error) {
    return res.status(500).json({
      error: "Failed to run local growth audit",
      details: error instanceof Error ? error.message : String(error),
    });
  }
});

app.post("/api/assets/share", authenticateSession, async (req, res) => {
  const { bundle, workspace } = req.body || {};
  if (!bundle || typeof bundle !== "object" || !workspace || typeof workspace !== "object") {
    return res.status(400).json({ error: "Bundle and workspace payloads are required" });
  }

  const appwriteReady =
    Boolean(process.env.APPWRITE_PROJECT_ID) &&
    Boolean(process.env.APPWRITE_ENDPOINT) &&
    Boolean(process.env.APPWRITE_API_KEY) &&
    Boolean(process.env.APPWRITE_BUCKET_ID);

  if (!appwriteReady) {
    return res.json({
      enabled: false,
      provider: "appwrite-disabled",
    });
  }

  return res.json({
    enabled: false,
    provider: "appwrite-pending",
  });
});

app.post("/api/assets/export-markdown", authenticateSession, (req, res) => {
  const { workspace } = req.body || {};
  if (!workspace || typeof workspace !== "object") {
    return res.status(400).json({ error: "Workspace payload is required" });
  }

  try {
    const markdown = buildLocalGrowthExportMarkdown(workspace);
    return res.json({ markdown });
  } catch (error) {
    return res.status(500).json({
      error: "Failed to export Local Growth workspace",
      details: error instanceof Error ? error.message : String(error),
    });
  }
});

app.post("/api/approvals/sync", authenticateSession, async (req, res) => {
  const { thread } = req.body || {};
  if (!thread || typeof thread !== "object") {
    return res.status(400).json({ error: "Approval thread payload is required" });
  }

  return res.json({
    synced: false,
    provider: "local",
  });
});

app.post("/api/analytics/capture", authenticateSession, async (req, res) => {
  const { event, payload = {} } = req.body || {};
  if (!event || typeof event !== "string") {
    return res.status(400).json({ error: "Event name is required" });
  }

  const posthogKey =
    process.env.POSTHOG_PROJECT_API_KEY ||
    process.env.POSTHOG_API_KEY ||
    process.env.POSTHOG_KEY;
  const posthogHost = process.env.POSTHOG_HOST;

  if (!posthogKey || !posthogHost) {
    return res.json({
      tracked: false,
      provider: "disabled",
    });
  }

  try {
    const response = await fetch(`${posthogHost.replace(/\/+$/g, "")}/capture/`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        api_key: posthogKey,
        event,
        properties: {
          ...(payload && typeof payload === "object" ? payload : {}),
          distinct_id: req.session.id,
          session_id: req.session.id,
        },
      }),
    });

    if (!response.ok) {
      const raw = await response.text();
      throw new Error(parseErrorMessage(raw, `PostHog capture failed (${response.status})`));
    }

    return res.json({
      tracked: true,
      provider: "posthog",
    });
  } catch (error) {
    return res.status(502).json({
      error: "Failed to capture analytics event",
      details: error instanceof Error ? error.message : String(error),
    });
  }
});

app.post("/api/voice/transcribe", authenticateSession, async (req, res) => {
  const { audioDataUrl } = req.body || {};
  if (!audioDataUrl || typeof audioDataUrl !== "string") {
    return res.status(400).json({ error: "Audio payload is required" });
  }

  try {
    const { buffer, mimeType } = dataUrlToBuffer(audioDataUrl);
    const data = await transcribeWithDeepgram(buffer, mimeType);
    const transcript =
      data?.results?.channels?.[0]?.alternatives?.[0]?.transcript || "";

    if (!transcript.trim()) {
      return res.status(422).json({
        error: "Deepgram did not return a transcript",
      });
    }

    return res.json({ transcript: transcript.trim() });
  } catch (error) {
    return res.status(500).json({
      error: "Failed to transcribe voice brief",
      details: error instanceof Error ? error.message : String(error),
    });
  }
});

app.post("/api/voice/synthesize", authenticateSession, async (req, res) => {
  const { text } = req.body || {};
  if (!text || typeof text !== "string") {
    return res.status(400).json({ error: "Text is required" });
  }

  try {
    const audioDataUrl = await synthesizeWithElevenLabs(text);
    return res.json({ audioDataUrl });
  } catch (error) {
    return res.status(500).json({
      error: "Failed to synthesize voice script",
      details: error instanceof Error ? error.message : String(error),
    });
  }
});

app.post("/api/voice/lead-agent", authenticateSession, async (req, res) => {
  const { workspace, locationId } = req.body || {};
  const location = Array.isArray(workspace?.locations)
    ? workspace.locations.find((item) => item.id === locationId) || workspace.locations[0]
    : null;

  return res.json({
    enabled: false,
    leadCapture: {
      id: `lead_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`,
      locationId: location?.id,
      status: "disabled",
      summary: location
        ? `Lead intake preview is disabled for ${location.name}. Add a production Vapi provisioning flow before enabling it.`
        : "Lead intake preview is disabled until a location is selected.",
      provider: process.env.VAPI_API_KEY ? "vapi-disabled" : "disabled",
      updatedAt: Date.now(),
    },
  });
});

// Initialize key cache before starting server
initializeKeyCache();

app.listen(PORT, () => {
  console.log(`Backend server running on port ${PORT}`);
  console.log("CORS allowed origins:", Array.from(allowedOrigins));
  console.log("Primary frontend URL:", primaryFrontendUrl);

  console.log("Configured services:");

  const groqKeys = extractKeys("GROQ_API_KEY");
  const geminiKeys = extractKeys("GOOGLE_API_KEY");
  const openaiKeys = getOpenAICompatibleKeys();
  const openrouterKeys = extractKeys("OPENROUTER_API_KEY");
  const githubKeys = extractKeys("GITHUB_TOKEN");
  const cohereKeys = extractKeys("COHERE_API_KEY");
  const xaiKeys = extractKeys("XAI_API_KEY");
  const fastrouterKeys = extractKeys("FASTROUTER_API_KEY");

  console.log("- Groq:", groqKeys.length, "keys");
  console.log("- Gemini:", geminiKeys.length, "keys");
  console.log("- OpenAI:", openaiKeys.length, "keys");
  console.log("- OpenRouter:", openrouterKeys.length, "keys");
  console.log("- GitHub:", githubKeys.length, "keys");
  console.log("- Cohere:", cohereKeys.length, "keys");
  console.log("- XAI:", xaiKeys.length, "keys");
  console.log("- FastRouter:", fastrouterKeys.length, "keys");

  const totalKeys =
    groqKeys.length +
    geminiKeys.length +
    openaiKeys.length +
    openrouterKeys.length +
    githubKeys.length +
    cohereKeys.length +
    xaiKeys.length +
    fastrouterKeys.length;

  console.log("Total API keys configured:", totalKeys);

  if (totalKeys === 0) {
    console.warn("\n⚠️  WARNING: No API keys found!");
    console.warn(
      "Please ensure your .env.local or .env file contains API keys.",
    );
    console.warn('Example: GROQ_API_KEY1="your-key-here"');
  }
});
