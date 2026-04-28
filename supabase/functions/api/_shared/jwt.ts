// ================================================================
// jwt.ts — JWT sign/verify (תואם לחלוטין ל-GAS הנוכחי)
// אותו JWT_SECRET → tokens מ-GAS עובדים גם כאן
// ================================================================

const SECRET = Deno.env.get('JWT_SECRET') ??
  'BagadHatzamKomando8219SecretKey2026XyZ_STATIC_2026';

const encoder = new TextEncoder();

async function hmacSign(data: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export interface JwtPayload {
  username:       string;
  role:           string;
  personalNumber: string;
  fullName:       string;
  email:          string;
  permissions:    string[];
  iat:            number;
  exp:            number;
}

export async function signJwt(payload: Omit<JwtPayload, 'iat' | 'exp'>): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const full: JwtPayload = { ...payload, iat: now, exp: now + 3600 };

  const header  = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  const body    = btoa(JSON.stringify(full))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  const sig     = await hmacSign(`${header}.${body}`);
  return `${header}.${body}.${sig}`;
}

export async function verifyJwt(token: string): Promise<JwtPayload | null> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [header, body, sig] = parts;
    const expected = await hmacSign(`${header}.${body}`);
    if (sig !== expected) return null;

    const payload: JwtPayload = JSON.parse(atob(body.replace(/-/g, '+').replace(/_/g, '/')));
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;

    return payload;
  } catch {
    return null;
  }
}
