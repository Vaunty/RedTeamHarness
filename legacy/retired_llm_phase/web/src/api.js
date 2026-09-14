/**
 * api.js - Fetch wrapper for the FastAPI backend.
 * All endpoints return JSON. Base URL points to the local dev server.
 */

const BASE = '';

async function fetchJSON(path) {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) {
    throw new Error(`API ${res.status}: ${res.statusText}`);
  }
  return res.json();
}

export const api = {
  getRuns:       (limit = 50) => fetchJSON(`/api/runs?limit=${limit}`),
  getRun:        (id)         => fetchJSON(`/api/runs/${id}`),
  getResults:    (id)         => fetchJSON(`/api/runs/${id}/results`),
  getMetrics:    (id)         => fetchJSON(`/api/runs/${id}/metrics`),
  compareRuns:   (base, def)  => fetchJSON(`/api/runs/compare?baseline=${base}&defended=${def}`),
  health:        ()           => fetchJSON(`/api/health`),
};
