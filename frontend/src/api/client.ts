import type { AnalysisResponse } from "../types/results";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8080/api";

export async function analyzeIndicator(ioc: string): Promise<AnalysisResponse> {
  const response = await fetch(`${API_BASE_URL}/analyze`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ ioc }),
  });

  if (!response.ok) {
    const payload = await safeJson(response);
    throw new Error(payload?.detail ?? `Request failed with status ${response.status}.`);
  }

  return response.json();
}

export async function analyzeFile(file: File): Promise<AnalysisResponse> {
  const body = new FormData();
  body.append("file", file);

  const response = await fetch(`${API_BASE_URL}/analyze/file`, {
    method: "POST",
    body,
  });

  if (!response.ok) {
    const payload = await safeJson(response);
    throw new Error(payload?.detail ?? `Request failed with status ${response.status}.`);
  }

  return response.json();
}

async function safeJson(response: Response): Promise<{ detail?: string } | null> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}
