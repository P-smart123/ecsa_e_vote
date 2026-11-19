import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import express from 'express';
import worker from './worker/src/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT) || 3000;
const HOST = '0.0.0.0';

function normalizeArg(value) {
  if (value === undefined) return null;
  if (typeof value === 'boolean') return value ? 1 : 0;
  return value;
}

/**
 * In-memory Cloudflare D1 adapter backed by Node.js built-in node:sqlite.
 * Data is ephemeral in AI Studio (lost when the container restarts/sleeps).
 */
function createD1Adapter(schemaPath) {
  const db = new DatabaseSync(':memory:');
  const schemaSql = fs.readFileSync(schemaPath, 'utf8');
  db.exec(schemaSql);

  function createStatement(sql, params = []) {
    return {
      _sql: sql,
      _params: params,
      bind(...args) {
        return createStatement(sql, args.map(normalizeArg));
      },
      async first(colName) {
        const stmt = db.prepare(sql);
        const row = stmt.get(...params);
        if (!row) return null;
        if (colName !== undefined) return row[colName] ?? null;
        return { ...row };
      },
      async all() {
        const stmt = db.prepare(sql);
        const rows = stmt.all(...params).map((r) => ({ ...r }));
        return { success: true, results: rows, meta: {} };
      },
      async run() {
        const stmt = db.prepare(sql);
        const info = stmt.run(...params);
        return {
          success: true,
          meta: {
            changes: Number(info.changes ?? 0),
            last_row_id: Number(info.lastInsertRowid ?? 0),
          },
        };
      },
    };
  }

  return {
    prepare(sql) {
      return createStatement(sql);
    },
    async batch(statements) {
      db.exec('BEGIN');
      try {
        const results = [];
        for (const s of statements) {
          const stmt = db.prepare(s._sql);
          if (/^\s*SELECT\b/i.test(s._sql)) {
            const rows = stmt.all(...s._params).map((r) => ({ ...r }));
            results.push({ success: true, results: rows, meta: {} });
          } else {
            const info = stmt.run(...s._params);
            results.push({
              success: true,
              results: [],
              meta: {
                changes: Number(info.changes ?? 0),
                last_row_id: Number(info.lastInsertRowid ?? 0),
              },
            });
          }
        }
        db.exec('COMMIT');
        return results;
      } catch (err) {
        db.exec('ROLLBACK');
        throw err;
      }
    },
  };
}

/**
 * In-memory Cloudflare R2 bucket adapter for candidate photos and manifesto PDFs.
 * Files are ephemeral in AI Studio (lost when the container restarts/sleeps).
 */
function createR2Adapter() {
  const store = new Map();
  return {
    async put(key, value, options = {}) {
      let bytes;
      if (value instanceof Uint8Array) {
        bytes = value;
      } else if (value instanceof ArrayBuffer) {
        bytes = new Uint8Array(value);
      } else if (typeof value === 'string') {
        bytes = new TextEncoder().encode(value);
      } else {
        bytes = new Uint8Array(await new Response(value).arrayBuffer());
      }
      store.set(key, {
        bytes,
        httpMetadata: options?.httpMetadata || {},
      });
      return { key, size: bytes.byteLength };
    },
    async get(key) {
      const entry = store.get(key);
      if (!entry) return null;
      return {
        key,
        body: entry.bytes,
        httpMetadata: entry.httpMetadata,
        async arrayBuffer() {
          return entry.bytes.buffer.slice(
            entry.bytes.byteOffset,
            entry.bytes.byteOffset + entry.bytes.byteLength
          );
        },
      };
    },
    async delete(key) {
      store.delete(key);
    },
  };
}

const schemaPath = path.join(__dirname, 'worker', 'schema.sql');
const workerEnv = {
  DB: createD1Adapter(schemaPath),
  FILES: createR2Adapter(),
  ALLOWED_ORIGIN: process.env.ALLOWED_ORIGIN || '*',
  SESSION_DAYS: process.env.SESSION_DAYS || '2',
  ADMIN_SETUP_KEY: process.env.ADMIN_SETUP_KEY || '',
  ENVIRONMENT: process.env.ENVIRONMENT || 'development',
};

const app = express();
app.disable('x-powered-by');

// Bridge /api/* requests directly to the Cloudflare Worker fetch handler
app.use('/api', async (req, res, next) => {
  try {
    const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
    const host = req.headers.host || `localhost:${PORT}`;
    const fullUrl = `${protocol}://${host}${req.originalUrl}`;

    const headers = new Headers();
    for (const [key, value] of Object.entries(req.headers)) {
      if (value === undefined) continue;
      const lower = key.toLowerCase();
      if (lower === 'connection' || lower === 'transfer-encoding') continue;
      if (Array.isArray(value)) {
        for (const v of value) headers.append(key, v);
      } else {
        headers.set(key, value);
      }
    }

    const method = req.method.toUpperCase();
    const hasBody = method !== 'GET' && method !== 'HEAD';
    let rawBody;
    if (hasBody) {
      const chunks = [];
      for await (const chunk of req) {
        chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
      }
      rawBody = Buffer.concat(chunks);
    }

    const webReq = new Request(fullUrl, {
      method,
      headers,
      body: hasBody && rawBody && rawBody.length > 0 ? rawBody : undefined,
    });

    const webRes = await worker.fetch(webReq, workerEnv);

    res.status(webRes.status);
    webRes.headers.forEach((value, key) => {
      if (key.toLowerCase() === 'transfer-encoding') return;
      res.setHeader(key, value);
    });

    if (webRes.body) {
      const buf = Buffer.from(await webRes.arrayBuffer());
      res.send(buf);
    } else {
      res.end();
    }
  } catch (err) {
    next(err);
  }
});

// Serve only the static frontend assets (avoid exposing backend files or configs)
const PUBLIC_FILES = new Map([
  ['/', 'index.html'],
  ['/index.html', 'index.html'],
  ['/styles.css', 'styles.css'],
  ['/app.js', 'app.js'],
  ['/config.js', 'config.js'],
]);

app.get(['/', '/index.html', '/styles.css', '/app.js', '/config.js'], (req, res) => {
  const file = PUBLIC_FILES.get(req.path);
  if (!file) return res.status(404).end();
  return res.sendFile(path.join(__dirname, file));
});

app.use((err, _req, res, _next) => {
  console.error('[ECSA server error]', err);
  res.status(500).json({ error: 'Server error. Please try again.' });
});

app.listen(PORT, HOST, () => {
  console.log(`ECSA Online E-Voting server running at http://${HOST}:${PORT}`);
  console.log('[AI Studio] Using in-memory SQLite (D1 adapter) and in-memory file storage (R2 adapter).');
});
