import { AlertTriangle, CheckCircle2, CircleDashed, KeyRound, Loader2 } from "lucide-react";

import type { SourceResult } from "../types/results";

type Props = {
  sources: SourceResult[];
};

const statusStyles: Record<SourceResult["status"], string> = {
  success: "border-teal-200 bg-teal-50 text-teal-800 dark:border-teal-400/40 dark:bg-teal-500/15 dark:text-teal-100",
  partial: "border-cyan-200 bg-cyan-50 text-cyan-800 dark:border-cyan-400/40 dark:bg-cyan-500/15 dark:text-cyan-100",
  failed: "border-rose-200 bg-rose-50 text-rose-800 dark:border-rose-400/40 dark:bg-rose-500/15 dark:text-rose-100",
  not_configured: "border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-300/40 dark:bg-amber-400/15 dark:text-amber-100",
  not_applicable: "border-zinc-200 bg-zinc-50 text-zinc-700 dark:border-zinc-500/40 dark:bg-white/5 dark:text-zinc-200",
  pending: "border-sky-200 bg-sky-50 text-sky-800 dark:border-sky-400/40 dark:bg-sky-500/15 dark:text-sky-100",
  stubbed: "border-violet-200 bg-violet-50 text-violet-800 dark:border-violet-400/40 dark:bg-violet-500/15 dark:text-violet-100",
};

export function SourceStatusGrid({ sources }: Props) {
  return (
    <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
      {sources.length ? (
        sources.map((source) => (
          <div
            key={source.source_name}
            className="overflow-hidden rounded-md border border-white/70 bg-white/90 shadow-sm ring-1 ring-zinc-200/60 backdrop-blur dark:border-white/10 dark:bg-slate-950/85 dark:ring-white/10"
          >
            <div className="h-1 bg-gradient-to-r from-teal-500 via-cyan-500 to-amber-400" />
            <div className="p-4">
              <div className="mb-3 flex items-center justify-between gap-3">
                <h3 className="text-sm font-semibold text-zinc-950 dark:text-zinc-100">{source.source_name}</h3>
                <StatusIcon status={source.status} />
              </div>
              <span className={`inline-flex rounded-md border px-2 py-1 text-xs font-semibold ${statusStyles[source.status]}`}>
                {source.status.replace("_", " ")}
              </span>
              <SourceInsights source={source} />
              {source.error_message ? (
                <p className="mt-3 text-sm leading-5 text-zinc-600 dark:text-zinc-300">{source.error_message}</p>
              ) : null}
            </div>
          </div>
        ))
      ) : (
        <div className="rounded-md border border-white/70 bg-white/90 p-4 text-sm text-zinc-500 shadow-sm ring-1 ring-zinc-200/60 dark:border-white/10 dark:bg-slate-950/85 dark:text-zinc-400 dark:ring-white/10">
          Source status will appear after analysis.
        </div>
      )}
    </div>
  );
}

function SourceInsights({ source }: { source: SourceResult }) {
  const insights = buildInsights(source);
  if (!insights.length) {
    return null;
  }
  return (
    <div className="mt-3 flex flex-wrap gap-2">
      {insights.map((insight) => (
        <span key={insight} className="rounded-md bg-zinc-100 px-2 py-1 text-xs font-medium text-zinc-700 dark:bg-white/5 dark:text-zinc-200">
          {insight}
        </span>
      ))}
    </div>
  );
}

function buildInsights(source: SourceResult) {
  const normalized = source.normalized ?? {};
  const insights: string[] = [];
  pushNumber(insights, normalized.malicious_detections, "malicious");
  pushNumber(insights, normalized.suspicious_detections, "suspicious");
  pushNumber(insights, normalized.abuse_confidence_score, "abuse score");
  pushNumber(insights, normalized.pulse_count, "pulses");
  pushNumber(insights, normalized.service_count, "services");
  pushNumber(insights, normalized.risky_service_count, "risky services");
  pushNumber(insights, normalized.result_count, "urlscan hits");
  if (typeof normalized.submission_status === "string") {
    insights.push(normalized.submission_status.replace("_", " "));
  }
  if (typeof normalized.verdict === "string") {
    insights.push(`verdict ${normalized.verdict}`);
  }
  if (typeof normalized.type_description === "string") {
    insights.push(normalized.type_description);
  }
  if (Array.isArray(normalized.ports) && normalized.ports.length) {
    insights.push(`ports ${normalized.ports.slice(0, 4).join(", ")}`);
  }
  if (Array.isArray(normalized.privacy_flags) && normalized.privacy_flags.length) {
    insights.push(normalized.privacy_flags.slice(0, 2).join(", "));
  }
  return insights.slice(0, 4);
}

function pushNumber(insights: string[], value: unknown, label: string) {
  if (typeof value === "number" && value > 0) {
    insights.push(`${value} ${label}`);
  }
}

function StatusIcon({ status }: { status: SourceResult["status"] }) {
  if (status === "success") {
    return <CheckCircle2 className="text-teal-600" size={18} aria-hidden="true" />;
  }
  if (status === "not_configured") {
    return <KeyRound className="text-amber-600" size={18} aria-hidden="true" />;
  }
  if (status === "failed") {
    return <AlertTriangle className="text-rose-600" size={18} aria-hidden="true" />;
  }
  if (status === "pending") {
    return <Loader2 className="text-sky-600" size={18} aria-hidden="true" />;
  }
  return <CircleDashed className="text-zinc-500" size={18} aria-hidden="true" />;
}
