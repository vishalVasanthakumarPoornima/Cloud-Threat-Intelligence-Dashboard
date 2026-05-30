import type { RiskReport } from "../types/results";

type Props = {
  report: RiskReport | null;
};

export function EvidenceTable({ report }: Props) {
  return (
    <div className="effect-card overflow-hidden rounded-md border border-white/70 bg-white/90 shadow-sm ring-1 ring-zinc-200/60 backdrop-blur dark:border-white/10 dark:bg-slate-950/85 dark:ring-white/10">
      <div className="border-b border-zinc-200 bg-gradient-to-r from-zinc-50 via-cyan-50 to-amber-50 p-4 dark:border-white/10 dark:from-slate-900 dark:via-cyan-950/60 dark:to-amber-950/30">
        <h2 className="text-sm font-semibold text-zinc-950 dark:text-zinc-100">Score Evidence</h2>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[560px] text-left text-sm">
          <thead className="bg-white text-xs uppercase text-zinc-500 dark:bg-slate-950 dark:text-zinc-400">
            <tr>
              <th className="px-4 py-3 font-medium">Source</th>
              <th className="px-4 py-3 font-medium">Points</th>
              <th className="px-4 py-3 font-medium">Reason</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-100 dark:divide-white/10">
            {report?.contributions.length ? (
              report.contributions.map((item) => (
                <tr key={item.source_name} className="transition hover:bg-cyan-50/70 dark:hover:bg-cyan-400/10">
                  <td className="px-4 py-3 font-medium text-zinc-950 dark:text-zinc-100">{item.source_name}</td>
                  <td className="px-4 py-3">
                    <span className={`rounded-md px-2 py-1 text-xs font-semibold ${pointTone(item.points)}`}>{item.points}</span>
                  </td>
                  <td className="px-4 py-3 text-zinc-600 dark:text-zinc-300">{item.reason}</td>
                </tr>
              ))
            ) : (
              <tr>
                <td className="px-4 py-6 text-zinc-500 dark:text-zinc-400" colSpan={3}>
                  No evidence available.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function pointTone(points: number) {
  if (points >= 30) {
    return "bg-rose-100 text-rose-800 ring-1 ring-rose-200 dark:bg-rose-400/15 dark:text-rose-100 dark:ring-rose-400/30";
  }
  if (points >= 15) {
    return "bg-orange-100 text-orange-800 ring-1 ring-orange-200 dark:bg-orange-400/15 dark:text-orange-100 dark:ring-orange-400/30";
  }
  if (points > 0) {
    return "bg-amber-100 text-amber-800 ring-1 ring-amber-200 dark:bg-amber-300/15 dark:text-amber-100 dark:ring-amber-300/30";
  }
  return "bg-teal-100 text-teal-800 ring-1 ring-teal-200 dark:bg-teal-400/15 dark:text-teal-100 dark:ring-teal-400/30";
}
