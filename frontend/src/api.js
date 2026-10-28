// Leave VITE_API_URL empty in development (Vite proxies /api to FastAPI).
// Set it at build time if the API is hosted on a different origin.
const BASE = import.meta.env.VITE_API_URL ?? "";

async function request(path, options) {
  let res;
  try {
    res = await fetch(`${BASE}${path}`, options);
  } catch {
    throw new Error("Could not reach the ScamSleuth server. Is the backend running?");
  }
  if (!res.ok) {
    let message = `Request failed (${res.status}).`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") message = body.detail;
      else if (Array.isArray(body.detail) && body.detail[0]?.msg)
        message = body.detail[0].msg.replace(/^Value error, /, "");
    } catch {
      /* keep default message */
    }
    throw new Error(message);
  }
  return res.json();
}

export const analyze = ({ text, url }) =>
  request("/api/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text, url }),
  });

export const getSamples = () => request("/api/samples");
