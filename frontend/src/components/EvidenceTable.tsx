import type { RiskReport } from "../types/results";

type Props = {
  report: RiskReport | null;
};

export function EvidenceTable({ report }: Props) {
  return (
    <div className="overflow-hidden rounded-md border border-white/70 bg-white/90 shadow-sm ring-1 ring-zinc-200/60 backdrop-blur dark:border-white/10 dark:bg-slate-950/85 dark:ring-white/10">
      <div className="border-b border-zinc-200 bg-gradient-to-r from-zinc-50 to-cyan-50 p-4 dark:border-white/10 dark:from-slate-900 dark:to-cyan-950/60">
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
                <tr key={item.source_name} className="transition hover:bg-zinc-50 dark:hover:bg-white/5">
                  <td className="px-4 py-3 font-medium text-zinc-950 dark:text-zinc-100">{item.source_name}</td>
                  <td className="px-4 py-3">
                    <span className="rounded-md bg-zinc-100 px-2 py-1 text-xs font-semibold text-zinc-800 dark:bg-white/10 dark:text-zinc-100">{item.points}</span>
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
