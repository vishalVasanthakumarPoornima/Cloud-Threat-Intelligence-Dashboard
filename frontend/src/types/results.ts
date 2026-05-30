export type IOCType = "ip" | "domain" | "url" | "hash" | "file";
export type Severity = "Low" | "Medium" | "High" | "Critical";
export type SourceStatus =
  | "not_applicable"
  | "not_configured"
  | "pending"
  | "success"
  | "partial"
  | "restricted"
  | "failed"
  | "stubbed";

export type IOCDetails = {
  input_type: IOCType;
  submitted_value: string;
  normalized_value: string;
};

export type ScoreContribution = {
  source_name: string;
  points: number;
  reason: string;
};

export type SourceResult = {
  source_name: string;
  status: SourceStatus;
  normalized: Record<string, unknown>;
  error_message?: string | null;
};

export type RiskReport = {
  score: number;
  severity: Severity;
  summary: string;
  recommended_actions: string[];
  contributions: ScoreContribution[];
};

export type AnalysisResponse = {
  analysis_id: string;
  status: "completed" | "partial" | "pending";
  created_at: string;
  ioc: IOCDetails;
  risk_report: RiskReport;
  source_results: SourceResult[];
};

export type NmapPreset =
  | "quick_ports"
  | "open_ports"
  | "service_detection"
  | "os_detection"
  | "stealth_syn";

export type NmapPortResult = {
  port: number;
  protocol: string;
  state: string;
  reason?: string | null;
  service_name?: string | null;
  product?: string | null;
  version?: string | null;
  extra_info?: string | null;
  cpes: string[];
};

export type NmapOsMatch = {
  name: string;
  accuracy?: number | null;
};

export type NmapScanResponse = {
  status: "completed" | "failed" | "not_available" | "timeout";
  target: string;
  normalized_target: string;
  input_type: "ip" | "domain";
  preset: NmapPreset;
  command: string[];
  started_at: string;
  finished_at: string;
  duration_seconds: number;
  ports: NmapPortResult[];
  os_matches: NmapOsMatch[];
  warnings: string[];
  summary: string;
  error_message?: string | null;
};
