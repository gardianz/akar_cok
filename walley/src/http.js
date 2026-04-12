const DEFAULT_HEADERS = {
  Accept: 'application/json',
  'Content-Type': 'application/json',
  'User-Agent': 'walley-transfer-bot/0.1.0',
};

function withTimeout(timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error(`Request timeout after ${timeoutMs}ms`)), timeoutMs);
  return {
    signal: controller.signal,
    clear: () => clearTimeout(timer),
  };
}

function buildUrl(baseUrl, path, query = {}) {
  const url = new URL(path, baseUrl);
  for (const [key, value] of Object.entries(query)) {
    if (value == null) continue;
    url.searchParams.set(key, String(value));
  }
  return url.toString();
}

async function parseJsonSafe(response) {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return { message: text };
  }
}

export class HttpError extends Error {
  constructor(message, status, requestId, traceId, payload) {
    super(message);
    this.status = status;
    this.requestId = requestId || '';
    this.traceId = traceId || '';
    this.payload = payload;
  }
}

export class WalleyHttpClient {
  constructor({ baseUrl, timeoutMs }) {
    this.baseUrl = baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`;
    this.timeoutMs = timeoutMs;
  }

  async request(path, { method = 'GET', query, headers = {}, body } = {}) {
    const timeout = withTimeout(this.timeoutMs);
    try {
      const requestHeaders = {
        ...DEFAULT_HEADERS,
        ...headers,
      };
      if (body == null) {
        delete requestHeaders['Content-Type'];
      }

      const response = await fetch(buildUrl(this.baseUrl, path, query), {
        method,
        headers: requestHeaders,
        body: body == null ? undefined : JSON.stringify(body),
        signal: timeout.signal,
      });
      const payload = await parseJsonSafe(response);

      if (!response.ok) {
        throw new HttpError(
          payload?.message || response.statusText || `HTTP ${response.status}`,
          response.status,
          payload?.request_id,
          payload?.trace_id,
          payload,
        );
      }

      return payload;
    } finally {
      timeout.clear();
    }
  }
}
