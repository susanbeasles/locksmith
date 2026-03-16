/**
 * Lambda adapter for Locksmith Express app behind API Gateway v2 (HTTP API).
 *
 * NOTE: src/index.ts (currently src/index.js) needs to be refactored to
 * export the Express `app` instance separately from the `start()` function.
 * For example:
 *
 *   export { app };          // <-- add this line
 *   export default app;      // <-- or this
 *
 * Then this file can import it as:
 *   import { app } from './src/index.js';
 *
 * Until that refactor is done, this import will not resolve.
 */

import type { IncomingMessage, ServerResponse } from 'http';
import { Readable } from 'stream';

// NOTE: index.ts must export `app` for this import to work.
// See comment block above for the required change.
import { app } from './src/index.js';

interface APIGatewayProxyEventV2 {
  version: string;
  routeKey: string;
  rawPath: string;
  rawQueryString: string;
  headers: Record<string, string>;
  queryStringParameters?: Record<string, string>;
  body?: string;
  isBase64Encoded: boolean;
  requestContext: {
    accountId: string;
    apiId: string;
    domainName: string;
    domainPrefix: string;
    http: {
      method: string;
      path: string;
      protocol: string;
      sourceIp: string;
      userAgent: string;
    };
    requestId: string;
    routeKey: string;
    stage: string;
    time: string;
    timeEpoch: number;
  };
}

interface APIGatewayProxyResultV2 {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
  isBase64Encoded: boolean;
}

/**
 * Convert an API Gateway v2 event into a Node.js-compatible IncomingMessage
 * and pipe it through the Express app.
 */
function eventToRequest(event: APIGatewayProxyEventV2): IncomingMessage {
  const {
    rawPath,
    rawQueryString,
    headers,
    body,
    isBase64Encoded,
    requestContext,
  } = event;

  const url = rawQueryString ? `${rawPath}?${rawQueryString}` : rawPath;
  const method = requestContext.http.method;

  // Build a readable stream from the body
  const bodyBuffer = body
    ? Buffer.from(body, isBase64Encoded ? 'base64' : 'utf-8')
    : Buffer.alloc(0);

  const stream = new Readable({
    read() {
      this.push(bodyBuffer);
      this.push(null);
    },
  });

  // Attach HTTP request properties that Express reads
  const req = stream as IncomingMessage;
  Object.assign(req, {
    url,
    method,
    headers: {
      ...headers,
      // Ensure content-length is accurate for body parsing
      ...(body ? { 'content-length': String(bodyBuffer.length) } : {}),
    },
    // Express trust proxy uses these
    connection: { remoteAddress: requestContext.http.sourceIp },
    socket: { remoteAddress: requestContext.http.sourceIp },
  });

  return req;
}

/**
 * Capture the Express response into an APIGatewayProxyResultV2.
 */
function captureResponse(res: ServerResponse): Promise<APIGatewayProxyResultV2> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    const originalWrite = res.write.bind(res) as (
      chunk: unknown,
      encodingOrCallback?: BufferEncoding | ((error: Error | null | undefined) => void),
      callback?: (error: Error | null | undefined) => void
    ) => boolean;

    const originalEnd = res.end.bind(res) as (
      chunk?: unknown,
      encodingOrCallback?: BufferEncoding | ((error: Error | null | undefined) => void),
      callback?: (error: Error | null | undefined) => void
    ) => ServerResponse;

    res.write = function (
      chunk: unknown,
      encodingOrCallback?: BufferEncoding | ((error: Error | null | undefined) => void),
      callback?: (error: Error | null | undefined) => void,
    ): boolean {
      if (chunk) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string));
      }
      if (typeof encodingOrCallback === 'function') {
        return originalWrite(chunk, encodingOrCallback);
      }
      return originalWrite(chunk, encodingOrCallback, callback);
    };

    res.end = function (
      chunk?: unknown,
      encodingOrCallback?: BufferEncoding | ((error: Error | null | undefined) => void),
      callback?: (error: Error | null | undefined) => void,
    ): ServerResponse {
      if (chunk && typeof chunk !== 'function') {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string));
      }

      const body = Buffer.concat(chunks);
      const isBase64Encoded = !isUtf8(body);

      // Collect response headers as flat string map
      const rawHeaders = res.getHeaders();
      const headers: Record<string, string> = {};
      for (const [key, value] of Object.entries(rawHeaders)) {
        if (value !== undefined) {
          headers[key] = Array.isArray(value) ? value.join(', ') : String(value);
        }
      }

      resolve({
        statusCode: res.statusCode,
        headers,
        body: isBase64Encoded ? body.toString('base64') : body.toString('utf-8'),
        isBase64Encoded,
      });

      if (typeof encodingOrCallback === 'function') {
        return originalEnd(chunk, encodingOrCallback);
      }
      return originalEnd(chunk, encodingOrCallback, callback);
    };
  });
}

/**
 * Heuristic: check if a buffer is valid UTF-8 text.
 */
function isUtf8(buf: Buffer): boolean {
  // If encoding and decoding round-trips cleanly, it is valid UTF-8
  const str = buf.toString('utf-8');
  return Buffer.byteLength(str, 'utf-8') === buf.length;
}

/**
 * AWS Lambda handler for API Gateway v2 (HTTP API) events.
 */
export async function handler(
  event: APIGatewayProxyEventV2,
): Promise<APIGatewayProxyResultV2> {
  const req = eventToRequest(event);
  const res = new (await import('http')).ServerResponse(req);

  const responsePromise = captureResponse(res);

  // Feed the request through Express
  app(req, res);

  return responsePromise;
}
