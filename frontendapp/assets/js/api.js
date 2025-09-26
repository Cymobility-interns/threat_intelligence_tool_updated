export const API_BASE = "http://127.0.0.1:8000";

export async function fetchVulnerabilities({ from, to, search } = {}) {
  try {
    let url = `${API_BASE}/automotive_vulnerabilities`;
    const params = new URLSearchParams();

    if (from) params.append("from", from);
    if (to) params.append("to", to);
    if (search) params.append("search", search);

    if (params.toString()) {
      url += `?${params.toString()}`;
    }

    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }
    return await response.json();
  } catch (err) {
    console.error("Failed to fetch vulnerabilities:", err);
    return [];
  }
}

export async function postData(endpoint, data) {
  try {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
      credentials: "include", // ✅ important for session cookies
    });

    let result;
    try {
      result = await response.json();
    } catch {
      result = {};
    }

    if (!response.ok) {
      return { ok: false, result: { detail: result.detail || "Something went wrong. Please try again." } };
    }

    return { ok: true, result };
  } catch (error) {
    return { ok: false, result: { detail: "Cannot connect to server. Please check your network." } };
  }
}
