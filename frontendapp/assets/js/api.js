const API_BASE = "http://127.0.0.1:8000";

export async function postData(endpoint, data) {
  try {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
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
