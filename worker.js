/**
 * Sentry Safe Browsing proxy.
 *
 * Holds your Google Safe Browsing API key server-side and answers on
 * behalf of every visitor to your site, so nobody needs their own key.
 *
 * DEPLOY (Cloudflare dashboard, no CLI needed):
 *   1. dash.cloudflare.com -> Workers & Pages -> Create -> Create Worker
 *   2. Paste this whole file in, replacing the starter code. Deploy.
 *   3. Worker -> Settings -> Variables and Secrets -> Add:
 *        Name: SAFE_BROWSING_KEY   Type: Secret   Value: <your real key>
 *   4. Worker -> Settings -> Variables and Secrets -> Add:
 *        Name: ALLOWED_ORIGIN   Type: Text
 *        Value: https://your-site.com   (no trailing slash; your real domain)
 *   5. Copy the Worker's URL (top of its page, ends in .workers.dev) and
 *      paste it as SENTINEL_PROXY_URL in scan.html, qr.html, settings.html.
 *
 * Why ALLOWED_ORIGIN matters: without it, any other website could call
 * your Worker and burn through your Safe Browsing quota. Setting it
 * locks the proxy to requests that actually come from your own site.
 */

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const allowedOrigin = env.ALLOWED_ORIGIN || "*";
    const corsOk = allowedOrigin === "*" || origin === allowedOrigin;

    const corsHeaders = {
      "Access-Control-Allow-Origin": corsOk ? (allowedOrigin === "*" ? "*" : origin) : "null",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    if (!corsOk) {
      return new Response(JSON.stringify({ error: "Origin not allowed" }), {
        status: 403,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    if (request.method !== "POST") {
      return new Response(JSON.stringify({ error: "Method not allowed" }), {
        status: 405,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    if (!env.SAFE_BROWSING_KEY) {
      return new Response(JSON.stringify({ error: "Server not configured" }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    let body;
    try {
      body = await request.json();
    } catch (e) {
      return new Response(JSON.stringify({ error: "Invalid JSON body" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const url = body && body.url;
    if (!url || typeof url !== "string" || url.length > 2048) {
      return new Response(JSON.stringify({ error: "Missing or invalid url" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const sbRequest = {
      client: { clientId: "sentry-shared-proxy", clientVersion: "1.0.0" },
      threatInfo: {
        threatTypes: [
          "MALWARE",
          "SOCIAL_ENGINEERING",
          "UNWANTED_SOFTWARE",
          "POTENTIALLY_HARMFUL_APPLICATION",
        ],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }],
      },
    };

    try {
      const sbRes = await fetch(
        "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" +
          encodeURIComponent(env.SAFE_BROWSING_KEY),
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(sbRequest),
        }
      );

      if (!sbRes.ok) {
        return new Response(JSON.stringify({ error: "Upstream error", status: sbRes.status }), {
          status: 502,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      const data = await sbRes.json();
      const matches = data.matches || [];

      return new Response(
        JSON.stringify({ checked: true, unsafe: matches.length > 0, matches }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    } catch (e) {
      return new Response(JSON.stringify({ error: "Proxy request failed" }), {
        status: 502,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
  },
};
