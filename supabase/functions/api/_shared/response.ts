// ================================================================
// response.ts — פורמט תשובה אחיד (תואם לפורמט GAS הנוכחי)
// ================================================================

const CORS_HEADERS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

export function createResponse(statusCode: number, message: string, data: unknown): Response {
  return new Response(
    JSON.stringify({
      statusCode,
      message,
      data,
      timestamp: new Date().toISOString(),
    }),
    {
      status: 200, // HTTP status תמיד 200 — statusCode בגוף התשובה (כמו GAS)
      headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
    }
  );
}

export function corsOptions(): Response {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}
