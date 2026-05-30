import type { Severity } from "../types/results";

type Props = {
  severity: Severity;
};

const classes: Record<Severity, string> = {
  Low: "border-teal-200 bg-gradient-to-r from-teal-50 to-emerald-50 text-teal-800 dark:border-teal-400/40 dark:from-teal-500/15 dark:to-emerald-400/10 dark:text-teal-100",
  Medium: "border-amber-200 bg-gradient-to-r from-amber-50 to-yellow-50 text-amber-800 dark:border-amber-300/40 dark:from-amber-400/15 dark:to-yellow-300/10 dark:text-amber-100",
  High: "border-orange-200 bg-gradient-to-r from-orange-50 to-rose-50 text-orange-800 dark:border-orange-300/40 dark:from-orange-400/15 dark:to-rose-400/10 dark:text-orange-100",
  Critical: "border-rose-200 bg-gradient-to-r from-rose-50 to-fuchsia-50 text-rose-800 dark:border-rose-300/40 dark:from-rose-400/15 dark:to-fuchsia-400/10 dark:text-rose-100",
};

export function SeverityBadge({ severity }: Props) {
  return (
    <span className={`rounded-md border px-2 py-1 text-xs font-semibold ${classes[severity]}`}>
      {severity}
    </span>
  );
}
