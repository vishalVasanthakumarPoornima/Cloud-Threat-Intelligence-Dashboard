import { AlertTriangle, CheckCircle2, CircleDashed, KeyRound, Loader2 } from "lucide-react";

import type { SourceResult } from "../types/results";

type Props = {
  sources: SourceResult[];
};

const statusStyles: Record<SourceResult["status"], string> = {
  success: "border-teal-200 bg-teal-50 text-teal-800 dark:border-teal-400/40 dark:bg-teal-500/15 dark:text-teal-100",
  partial: "border-cyan-200 bg-cyan-50 text-cyan-800 dark:border-cyan-400/40 dark:bg-cyan-500/15 dark:text-cyan-100",
  restricted: "border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-300/40 dark:bg-amber-400/15 dark:text-amber-100",
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
            className="effect-card overflow-hidden rounded-md border border-white/70 bg-white/90 shadow-sm ring-1 ring-zinc-200/60 backdrop-blur dark:border-white/10 dark:bg-slate-950/85 dark:ring-white/10"
          >
            <div className={`h-1 bg-gradient-to-r ${statusAccent(source.status)}`} />
            <div className="p-4">
              <div className="mb-3 flex items-center justify-between gap-3">
                <h3 className="text-sm font-semibold text-zinc-950 dark:text-zinc-100">{source.source_name}</h3>
                <span className={`flex h-8 w-8 items-center justify-center rounded-md border ${statusStyles[source.status]}`}>
                  <StatusIcon status={source.status} />
                </span>
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
        <div className="effect-card rounded-md border border-white/70 bg-gradient-to-br from-white via-cyan-50 to-amber-50 p-4 text-sm text-zinc-500 shadow-sm ring-1 ring-zinc-200/60 dark:border-white/10 dark:from-slate-950 dark:via-cyan-950/30 dark:to-amber-950/20 dark:text-zinc-400 dark:ring-white/10">
          Source status will appear after analysis.
        </div>
      )}
    </div>
  );
}

function SourceInsights({ source }: { source: SourceResult }) {
  const insights = buildInsights(source);
  const details = buildDetails(source);
  if (!insights.length) {
    return details.length ? <SourceDetails details={details} /> : null;
  }
  return (
    <>
      <div className="mt-3 flex flex-wrap gap-2">
        {insights.map((insight) => (
          <span key={insight} className="rounded-md bg-zinc-100 px-2 py-1 text-xs font-medium text-zinc-700 dark:bg-white/5 dark:text-zinc-200">
            {insight}
          </span>
        ))}
      </div>
      <SourceDetails details={details} />
    </>
  );
}

function SourceDetails({ details }: { details: Array<{ label: string; value: string }> }) {
  if (!details.length) {
    return null;
  }
  return (
    <dl className="mt-3 grid gap-2 text-xs">
      {details.map((detail) => (
        <div key={`${detail.label}-${detail.value}`} className="rounded-md border border-zinc-200/80 bg-zinc-50/80 px-2.5 py-2 dark:border-white/10 dark:bg-white/[0.04]">
          <dt className="mb-1 font-semibold uppercase tracking-normal text-zinc-500 dark:text-zinc-400">{detail.label}</dt>
          <dd className="break-words font-medium leading-5 text-zinc-800 dark:text-zinc-100">{detail.value}</dd>
        </div>
      ))}
    </dl>
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

function buildDetails(source: SourceResult) {
  const normalized = source.normalized ?? {};
  const name = source.source_name.toLowerCase();

  if (name.includes("shodan")) {
    return compactDetails([
      detail("Mode", normalized.api_mode === "internetdb" ? "Shodan InternetDB fallback" : "Shodan Host API"),
      detail(
        "Open ports",
        formatList(normalized.ports) || (normalized.data_available === false ? "None indexed by InternetDB" : null),
      ),
      detail("Hostnames", formatList(normalized.hostnames)),
      detail("Vulnerabilities", formatList(normalized.vulnerabilities) || formatCount(normalized.vulnerability_count)),
      detail("CPEs", formatList(normalized.cpes)),
      detail("Notes", asString(normalized.message)),
    ]);
  }

  if (name.includes("abuseipdb")) {
    return compactDetails([
      detail("Abuse score", `${asNumber(normalized.abuse_confidence_score, 0)}/100`),
      detail("Reports", formatCount(normalized.report_count, "reports")),
      detail("ISP", asString(normalized.isp)),
      detail("Usage", asString(normalized.usage_type)),
      detail("Country", joinValues([asString(normalized.country_name), asString(normalized.country_code)])),
      detail("Tor", asBoolean(normalized.is_tor)),
      detail("Last reported", asString(normalized.last_reported_at) || "No recent reports"),
    ]);
  }

  if (name.includes("ipinfo")) {
    const asn = asRecord(normalized.asn);
    return compactDetails([
      detail("Location", joinValues([asString(normalized.city), asString(normalized.region), asString(normalized.country)])),
      detail("ASN", joinValues([asString(asn?.asn), asString(asn?.name)])),
      detail("ASN type", asString(asn?.type)),
      detail("ASN domain", asString(asn?.domain)),
      detail("Timezone", asString(normalized.timezone)),
      detail("Privacy flags", formatList(normalized.privacy_flags) || "None returned"),
    ]);
  }

  if (name.includes("virustotal")) {
    return compactDetails([
      detail("Detections", `${asNumber(normalized.malicious_detections, 0)} malicious / ${asNumber(normalized.suspicious_detections, 0)} suspicious`),
      detail("Harmless", formatCount(normalized.harmless_detections, "engines")),
      detail("Undetected", formatCount(normalized.undetected, "engines")),
      detail("Reputation", formatCount(normalized.reputation)),
      detail("Categories", formatList(normalized.categories)),
      detail("Tags", formatList(normalized.tags)),
      detail("Threat label", asString(normalized.threat_label)),
      detail("Last analysis", formatUnixDate(normalized.last_analysis_date)),
    ]);
  }

  if (name.includes("alienvault") || name.includes("otx")) {
    return compactDetails([
      detail("Indicator type", asString(normalized.type)),
      detail("Pulses", formatCount(normalized.pulse_count, "pulses")),
      detail("Reputation", formatCount(normalized.reputation)),
      detail("Tags", formatList(normalized.tags) || "None returned"),
      detail("Malware families", formatList(normalized.malware_families) || "None returned"),
      detail("References", formatList(normalized.references)),
    ]);
  }

  if (name.includes("urlscan")) {
    return compactDetails([
      detail("Verdict", asString(normalized.verdict)),
      detail("Results", formatCount(normalized.result_count, "results")),
      detail("Submission", asString(normalized.submission_status)?.replace("_", " ")),
    ]);
  }

  return genericDetails(normalized);
}

function genericDetails(normalized: Record<string, unknown>) {
  return Object.entries(normalized)
    .map(([key, value]) => detail(formatLabel(key), formatValue(value)))
    .filter((item): item is { label: string; value: string } => Boolean(item?.value))
    .slice(0, 6);
}

function detail(label: string, value: string | null | undefined) {
  if (!value) {
    return null;
  }
  return { label, value };
}

function compactDetails(values: Array<{ label: string; value: string } | null>) {
  return values.filter((value): value is { label: string; value: string } => Boolean(value)).slice(0, 7);
}

function formatValue(value: unknown): string | null {
  if (Array.isArray(value)) {
    return formatList(value);
  }
  if (typeof value === "object" && value !== null) {
    return Object.entries(value as Record<string, unknown>)
      .map(([key, nested]) => `${formatLabel(key)} ${formatValue(nested) ?? ""}`.trim())
      .filter(Boolean)
      .slice(0, 4)
      .join(" · ");
  }
  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  }
  if (typeof value === "number") {
    return String(value);
  }
  return asString(value);
}

function formatList(value: unknown, limit = 6): string | null {
  if (!Array.isArray(value) || !value.length) {
    return null;
  }
  const formatted = value.map((item) => formatValue(item)).filter(Boolean).slice(0, limit);
  if (!formatted.length) {
    return null;
  }
  const suffix = value.length > limit ? ` +${value.length - limit} more` : "";
  return `${formatted.join(", ")}${suffix}`;
}

function formatCount(value: unknown, noun?: string): string | null {
  const number = asNumber(value);
  if (number === null) {
    return null;
  }
  return noun ? `${number} ${noun}` : String(number);
}

function formatUnixDate(value: unknown): string | null {
  const number = asNumber(value);
  if (!number) {
    return null;
  }
  return new Date(number * 1000).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

function joinValues(values: Array<string | null | undefined>) {
  const filtered = values.filter(Boolean);
  return filtered.length ? filtered.join(", ") : null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function asString(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  return trimmed || null;
}

function asNumber(value: unknown, fallback?: number): number | null {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  return fallback ?? null;
}

function asBoolean(value: unknown): string | null {
  if (typeof value !== "boolean") {
    return null;
  }
  return value ? "Yes" : "No";
}

function formatLabel(key: string) {
  return key.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
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
  if (status === "restricted") {
    return <KeyRound className="text-amber-600" size={18} aria-hidden="true" />;
  }
  if (status === "failed") {
    return <AlertTriangle className="text-rose-600" size={18} aria-hidden="true" />;
  }
  if (status === "pending") {
    return <Loader2 className="animate-spin text-sky-600" size={18} aria-hidden="true" />;
  }
  return <CircleDashed className="text-zinc-500" size={18} aria-hidden="true" />;
}

function statusAccent(status: SourceResult["status"]) {
  const accents: Record<SourceResult["status"], string> = {
    success: "from-teal-500 via-emerald-400 to-lime-300",
    partial: "from-cyan-500 via-sky-400 to-teal-300",
    restricted: "from-amber-400 via-yellow-300 to-orange-300",
    failed: "from-rose-500 via-pink-400 to-orange-300",
    not_configured: "from-amber-400 via-yellow-300 to-orange-300",
    not_applicable: "from-zinc-400 via-slate-300 to-zinc-200",
    pending: "from-sky-500 via-cyan-400 to-violet-300",
    stubbed: "from-violet-500 via-fuchsia-400 to-cyan-300",
  };

  return accents[status];
}
