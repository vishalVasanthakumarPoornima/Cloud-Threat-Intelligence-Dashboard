import type { Severity } from "../types/results";

type Props = {
  severity: Severity;
};

const classes: Record<Severity, string> = {
  Low: "border-teal-200 bg-teal-50 text-teal-800 dark:border-teal-400/40 dark:bg-teal-500/15 dark:text-teal-100",
  Medium: "border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-300/40 dark:bg-amber-400/15 dark:text-amber-100",
  High: "border-orange-200 bg-orange-50 text-orange-800 dark:border-orange-300/40 dark:bg-orange-400/15 dark:text-orange-100",
  Critical: "border-rose-200 bg-rose-50 text-rose-800 dark:border-rose-300/40 dark:bg-rose-400/15 dark:text-rose-100",
};

export function SeverityBadge({ severity }: Props) {
  return (
    <span className={`rounded-md border px-2 py-1 text-xs font-semibold ${classes[severity]}`}>
      {severity}
    </span>
  );
}
