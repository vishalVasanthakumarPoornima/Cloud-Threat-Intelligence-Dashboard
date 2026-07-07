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

export type PortScanPreset =
  | "quick_ports"
  | "open_ports"
  | "service_detection"
  | "os_detection"
  | "stealth_syn";

export type PortScanPortResult = {
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

export type PortScanOsMatch = {
  name: string;
  accuracy?: number | null;
};

export type PortScanResponse = {
  status: "completed" | "failed" | "not_available" | "timeout";
  target: string;
  normalized_target: string;
  input_type: "ip" | "domain";
  preset: PortScanPreset;
  command: string[];
  started_at: string;
  finished_at: string;
  duration_seconds: number;
  ports: PortScanPortResult[];
  os_matches: PortScanOsMatch[];
  warnings: string[];
  summary: string;
  error_message?: string | null;
};

export type NmapPreset = PortScanPreset;
export type NmapPortResult = PortScanPortResult;
export type NmapOsMatch = PortScanOsMatch;
export type NmapScanResponse = PortScanResponse;
