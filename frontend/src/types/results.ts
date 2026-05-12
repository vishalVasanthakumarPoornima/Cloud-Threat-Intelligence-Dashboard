export type IOCType = "ip" | "domain" | "url" | "hash" | "file";
export type Severity = "Low" | "Medium" | "High" | "Critical";
export type SourceStatus =
  | "not_applicable"
  | "not_configured"
  | "pending"
  | "success"
  | "partial"
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
