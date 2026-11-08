/**
 * Syntiox Intelligence - safe server-side diagnostics endpoint
 * Vercel Pages Function: /api/raw
 *
 * Accepts a user-initiated POST containing browser diagnostics, combines it
 * with a safe allow-list of request metadata, and returns JSON.
 * It deliberately never returns Cookie, Authorization, Vercel OIDC tokens,
 * proxy signatures, or other secret headers.
 */

export const config = {
  api: {
    bodyParser: { sizeLimit: '256kb' },
  },
};

const SAFE_HEADERS = [
  'accept',
  'accept-language',
  'accept-encoding',
  'user-agent',
  'referer',
  'origin',
  'host',
  'x-forwarded-host',
  'x-forwarded-proto',
  'sec-ch-ua',
  'sec-ch-ua-mobile',
  'sec-ch-ua-platform',
  'sec-ch-ua-arch',
  'sec-ch-ua-bitness',
  'sec-ch-ua-model',
  'sec-ch-ua-full-version-list',
  'sec-fetch-site',
  'sec-fetch-mode',
  'sec-fetch-dest',
  'sec-fetch-user',
  'upgrade-insecure-requests',
  'dnt',
  'save-data',
  'priority',
  'x-vercel-ip-continent',
  'x-vercel-ip-country',
  'x-vercel-ip-country-region',
  'x-vercel-ip-city',
  'x-vercel-ip-latitude',
  'x-vercel-ip-longitude',
  'x-vercel-ip-timezone',
  'x-vercel-ip-postal-code',
  'x-vercel-ip-as-number',
];

function cleanHeader(value, maxLength = 1000) {
  if (Array.isArray(value)) value = value.join(', ');
  if (typeof value !== 'string') return undefined;
  return value.replace(/[\r\n\0]/g, '').slice(0, maxLength);
}

function decodeGeo(value) {
  const cleaned = cleanHeader(value, 200);
  if (!cleaned) return null;
  try {
    return decodeURIComponent(cleaned);
  } catch {
    return cleaned;
  }
}

function firstIp(value) {
  const cleaned = cleanHeader(value, 300);
  if (!cleaned) return null;
  // Vercel documents x-forwarded-for as the visitor IP. If a list is present,
  // retain only the first address rather than returning the full proxy chain.
  return cleaned.split(',')[0].trim() || null;
}

function safePathAndQueryKeys(req) {
  try {
    const host = cleanHeader(req.headers.host, 255) || 'localhost';
    const parsed = new URL(req.url || '/', `https://${host}`);
    return {
      path: parsed.pathname,
      queryParameterNames: [...new Set([...parsed.searchParams.keys()])],
      // Query parameter VALUES are intentionally omitted: they can contain tokens.
    };
  } catch {
    return { path: '/', queryParameterNames: [] };
  }
}

export default function handler(req, res) {
  res.setHeader('Cache-Control', 'private, no-store, max-age=0');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({
      error: 'Method Not Allowed',
      allowedMethods: ['POST'],
    });
  }

  // Same-origin guard for browser requests. This is not authentication; it is
  // an additional CSRF/cross-site safeguard for this diagnostics endpoint.
  const origin = cleanHeader(req.headers.origin, 500);
  const host = cleanHeader(req.headers.host, 500);
  if (origin && host) {
    try {
      if (new URL(origin).host !== host) {
        return res.status(403).json({ error: 'Cross-origin request blocked' });
      }
    } catch {
      return res.status(403).json({ error: 'Invalid Origin header' });
    }
  }

  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const clientData = body.clientData;
  if (!clientData || typeof clientData !== 'object' || Array.isArray(clientData)) {
    return res.status(400).json({ error: 'clientData object is required' });
  }

  let payloadBytes = 0;
  try {
    payloadBytes = Buffer.byteLength(JSON.stringify(clientData), 'utf8');
  } catch {
    return res.status(400).json({ error: 'Invalid clientData payload' });
  }
  if (payloadBytes > 200 * 1024) {
    return res.status(413).json({ error: 'Diagnostics payload is too large' });
  }

  const headers = {};
  for (const name of SAFE_HEADERS) {
    const value = cleanHeader(req.headers[name]);
    if (value !== undefined) headers[name] = value;
  }

  const forwardedIp = firstIp(
    req.headers['x-forwarded-for'] ||
    req.headers['x-vercel-forwarded-for'] ||
    req.headers['x-real-ip']
  );

  const rawGeo = {
    continent: req.headers['x-vercel-ip-continent'],
    country: req.headers['x-vercel-ip-country'],
    region: req.headers['x-vercel-ip-country-region'],
    city: req.headers['x-vercel-ip-city'],
    latitude: req.headers['x-vercel-ip-latitude'],
    longitude: req.headers['x-vercel-ip-longitude'],
    timezone: req.headers['x-vercel-ip-timezone'],
    postalCode: req.headers['x-vercel-ip-postal-code'],
    asNumber: req.headers['x-vercel-ip-as-number'],
  };

  const geolocation = Object.fromEntries(
    Object.entries(rawGeo).map(([key, value]) => [
      key,
      key === 'city' ? decodeGeo(value) : cleanHeader(value, 200) || null,
    ])
  );

  const requestInfo = safePathAndQueryKeys(req);

  return res.status(200).json({
    product: 'Syntiox Intelligence',
    schemaVersion: '2.0.0',
    capturedAt: new Date().toISOString(),
    collection: {
      mode: 'user-initiated browser diagnostics',
      preciseLocationIncluded: Boolean(clientData?.location?.precise),
      persistedByThisEndpoint: false,
      note: 'This endpoint returns the capture; it does not write it to a database.',
    },
    serverSide: {
      request: {
        method: req.method,
        path: requestInfo.path,
        queryParameterNames: requestInfo.queryParameterNames,
        host: host || null,
        protocol: cleanHeader(req.headers['x-forwarded-proto'], 30) || null,
        contentType: cleanHeader(req.headers['content-type'], 200) || null,
        contentLength: Number(req.headers['content-length']) || payloadBytes,
      },
      ip: {
        address: forwardedIp,
        source: forwardedIp ? 'Vercel forwarded request header' : 'unavailable',
      },
      geolocation,
      headers,
      vercel: {
        regionAndRequestId: cleanHeader(req.headers['x-vercel-id'], 300) || null,
        deploymentUrl: cleanHeader(req.headers['x-vercel-deployment-url'], 255) || null,
      },
    },
    clientSide: clientData,
  });
}
