import { ChevronDown, ShieldAlert } from "lucide-react";
import { RadialBar, RadialBarChart, ResponsiveContainer } from "recharts";

import { SeverityBadge } from "./SeverityBadge";
import type { RiskReport } from "../types/results";

type Props = {
  report: RiskReport | null;
  className?: string;
  sourceSummary?: string;
};

export function RiskScoreCard({ report, className = "", sourceSummary }: Props) {
  const score = report?.score ?? 0;
  const chartData = [{ name: "Risk", value: score, fill: colorForScore(score) }];
  const actions = report?.recommended_actions ?? ["Submit an indicator to calculate risk."];

  return (
    <section
      className={`effect-card min-w-0 overflow-hidden rounded-md border border-white/70 bg-white/[0.94] shadow-lg shadow-cyan-500/10 ring-1 ring-zinc-200/60 backdrop-blur dark:border-white/10 dark:bg-slate-950/90 dark:ring-white/10 ${className}`}
      aria-label="Risk score"
    >
      <div className="grid min-w-0 lg:grid-cols-[minmax(300px,440px)_1fr]">
        <div className="relative isolate overflow-hidden bg-gradient-to-br from-zinc-950 via-cyan-950 to-amber-700 p-5 text-white">
          <div className="absolute -right-8 -top-8 h-52 w-52 opacity-75" aria-hidden="true">
            <ResponsiveContainer width="100%" height="100%">
              <RadialBarChart
                innerRadius="72%"
                outerRadius="100%"
                data={chartData}
                startAngle={90}
                endAngle={-270}
              >
                <RadialBar dataKey="value" cornerRadius={4} background={{ fill: "rgba(255,255,255,0.16)" }} />
              </RadialBarChart>
            </ResponsiveContainer>
          </div>
          <div className="relative z-10 flex min-h-56 flex-col justify-between gap-6">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-sm font-semibold uppercase text-cyan-100">
                <ShieldAlert size={18} aria-hidden="true" />
                Risk Score
              </div>
              {report ? <SeverityBadge severity={report.severity} /> : null}
            </div>
            <div>
              <div className="flex items-end gap-2">
                <span className="text-7xl font-black leading-none tracking-normal text-white md:text-8xl">{score}</span>
                <span className="pb-2 text-2xl font-bold text-cyan-100 md:pb-3 md:text-3xl">/100</span>
              </div>
              <p className="mt-3 max-w-sm text-sm font-medium leading-6 text-cyan-50/90">
                {sourceSummary ?? "Run an analysis to produce a scored threat decision."}
              </p>
            </div>
          </div>
        </div>

        <div className="grid content-start gap-4 p-5">
          <div>
            <div className="mb-2 text-xs font-semibold uppercase text-zinc-500 dark:text-zinc-400">
              {report ? "Analyst summary" : "Ready"}
            </div>
            <p className="text-base font-medium leading-7 text-zinc-800 dark:text-zinc-100">
              {report?.summary ?? "Submit an IP, domain, URL, hash, or file to calculate the risk score."}
            </p>
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-md border border-zinc-200 bg-zinc-50 p-3 dark:border-white/10 dark:bg-white/[0.04]">
              <div className="text-xs font-semibold uppercase text-zinc-500 dark:text-zinc-400">Severity</div>
              <div className="mt-1 text-lg font-bold text-zinc-950 dark:text-zinc-50">{report?.severity ?? "Not scored"}</div>
            </div>
            <div className="rounded-md border border-zinc-200 bg-zinc-50 p-3 dark:border-white/10 dark:bg-white/[0.04]">
              <div className="text-xs font-semibold uppercase text-zinc-500 dark:text-zinc-400">Top action</div>
              <div className="mt-1 text-sm font-semibold leading-5 text-zinc-800 dark:text-zinc-100">{actions[0]}</div>
            </div>
          </div>

          <details className="group rounded-md border border-zinc-200 bg-white p-3 text-sm text-zinc-700 dark:border-white/10 dark:bg-slate-950 dark:text-zinc-200">
            <summary className="flex cursor-pointer list-none items-center justify-between gap-3 font-semibold text-zinc-950 dark:text-zinc-100">
              <span>Recommended actions</span>
              <ChevronDown className="shrink-0 transition group-open:rotate-180" size={16} aria-hidden="true" />
            </summary>
            <ul className="mt-3 space-y-2">
              {actions.map((action, index) => (
                <li key={action} className={`rounded-md border px-3 py-2 ${actionTone(index)}`}>
                  {action}
                </li>
              ))}
            </ul>
          </details>
        </div>
      </div>
    </section>
  );
}

function colorForScore(score: number) {
  if (score >= 75) return "#be123c";
  if (score >= 50) return "#ea580c";
  if (score >= 25) return "#ca8a04";
  return "#0f766e";
}

function actionTone(index: number) {
  const tones = [
    "border-teal-100 bg-teal-50/80 text-teal-900 dark:border-teal-400/20 dark:bg-teal-400/10 dark:text-teal-100",
    "border-cyan-100 bg-cyan-50/80 text-cyan-900 dark:border-cyan-400/20 dark:bg-cyan-400/10 dark:text-cyan-100",
    "border-amber-100 bg-amber-50/80 text-amber-900 dark:border-amber-300/20 dark:bg-amber-300/10 dark:text-amber-100",
    "border-rose-100 bg-rose-50/80 text-rose-900 dark:border-rose-400/20 dark:bg-rose-400/10 dark:text-rose-100",
  ];

  return tones[index % tones.length];
}
