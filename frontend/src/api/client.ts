import type { AnalysisResponse, NmapPreset, NmapScanResponse } from "../types/results";

const API_BASE_URL = resolveApiBaseUrl();

export async function analyzeIndicator(ioc: string): Promise<AnalysisResponse> {
  const url = `${API_BASE_URL}/analyze`;
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ ioc }),
  });

  return parseJsonResponse<AnalysisResponse>(response, url);
}

export async function analyzeFile(file: File): Promise<AnalysisResponse> {
  const body = new FormData();
  body.append("file", file);

  const url = `${API_BASE_URL}/analyze/file`;
  const response = await fetch(url, {
    method: "POST",
    body,
  });

  return parseJsonResponse<AnalysisResponse>(response, url);
}

export async function runNmapScan(payload: {
  target: string;
  preset: NmapPreset;
  confirmed_authorized: boolean;
  timeout_seconds: number;
}): Promise<NmapScanResponse> {
  const url = `${API_BASE_URL}/active-scan/nmap`;
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  return parseJsonResponse<NmapScanResponse>(response, url);
}

function resolveApiBaseUrl() {
  const configured = import.meta.env.VITE_API_BASE_URL?.trim();
  if (configured) {
    return stripTrailingSlashes(configured);
  }
  if (typeof window !== "undefined" && !isLocalHost(window.location.hostname)) {
    return `${window.location.origin}/api`;
  }
  return "http://localhost:8080/api";
}

function stripTrailingSlashes(value: string) {
  return value.replace(/\/+$/, "");
}

function isLocalHost(hostname: string) {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
}

async function parseJsonResponse<T>(response: Response, url: string): Promise<T> {
  const body = await response.text();
  const payload = body ? parseJsonBody(body, response, url) : null;

  if (!response.ok) {
    throw new Error(errorMessageFromPayload(payload, response, url));
  }
  if (!payload) {
    throw new Error(
      `Backend returned an empty response from ${url}. Check that VITE_API_BASE_URL points to the FastAPI backend URL ending in /api.`,
    );
  }
  return payload as T;
}

function parseJsonBody(body: string, response: Response, url: string): unknown {
  try {
    return JSON.parse(body);
  } catch {
    const preview = body.trim().slice(0, 120);
    throw new Error(
      `Backend returned a non-JSON response from ${url} with HTTP ${response.status}. ${preview || "The response body was empty."}`,
    );
  }
}

function errorMessageFromPayload(payload: unknown, response: Response, url: string) {
  const detail = readDetail(payload);
  return detail ? `${detail} (${response.status} from ${url})` : `Request failed with HTTP ${response.status} from ${url}.`;
}

function readDetail(payload: unknown): string | null {
  if (!payload || typeof payload !== "object") {
    return null;
  }
  const detail = (payload as { detail?: unknown }).detail;
  if (typeof detail === "string") {
    return detail;
  }
  if (Array.isArray(detail)) {
    return detail.map(formatValidationDetail).filter(Boolean).join(" ");
  }
  return null;
}

function formatValidationDetail(detail: unknown) {
  if (!detail || typeof detail !== "object") {
    return "";
  }
  const item = detail as { loc?: unknown; msg?: unknown };
  const path = Array.isArray(item.loc) ? item.loc.join(".") : "";
  const message = typeof item.msg === "string" ? item.msg : "";
  return [path, message].filter(Boolean).join(": ");
}
