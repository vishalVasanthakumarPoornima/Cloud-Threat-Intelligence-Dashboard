import { ShieldAlert } from "lucide-react";
import { RadialBar, RadialBarChart, ResponsiveContainer } from "recharts";

import { SeverityBadge } from "./SeverityBadge";
import type { RiskReport } from "../types/results";

type Props = {
  report: RiskReport | null;
};

export function RiskScoreCard({ report }: Props) {
  const score = report?.score ?? 0;
  const chartData = [{ name: "Risk", value: score, fill: colorForScore(score) }];

  return (
    <div className="overflow-hidden rounded-md border border-white/70 bg-white/85 shadow-sm ring-1 ring-zinc-200/60 backdrop-blur dark:border-white/10 dark:bg-slate-950/85 dark:ring-white/10">
      <div className="bg-gradient-to-r from-teal-600 via-cyan-600 to-amber-500 px-4 py-3 text-white">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-sm font-semibold">
            <ShieldAlert size={17} aria-hidden="true" />
            Risk Score
          </div>
          {report ? <SeverityBadge severity={report.severity} /> : null}
        </div>
      </div>
      <div className="p-4">
        <div className="relative h-52">
          <ResponsiveContainer width="100%" height="100%">
            <RadialBarChart
              innerRadius="72%"
              outerRadius="100%"
              data={chartData}
              startAngle={90}
              endAngle={-270}
            >
              <RadialBar dataKey="value" cornerRadius={4} background={{ fill: "var(--risk-ring-bg)" }} />
            </RadialBarChart>
          </ResponsiveContainer>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-5xl font-semibold tracking-normal text-zinc-950 dark:text-zinc-50">{score}</span>
            <span className="text-sm text-zinc-500 dark:text-zinc-400">out of 100</span>
          </div>
        </div>
        <ul className="space-y-2 text-sm text-zinc-700 dark:text-zinc-200">
          {(report?.recommended_actions ?? ["Submit an indicator to calculate risk."]).map((action) => (
            <li key={action} className="rounded-md bg-zinc-50 px-3 py-2 dark:bg-white/5">
              {action}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function colorForScore(score: number) {
  if (score >= 75) return "#be123c";
  if (score >= 50) return "#ea580c";
  if (score >= 25) return "#ca8a04";
  return "#0f766e";
}
