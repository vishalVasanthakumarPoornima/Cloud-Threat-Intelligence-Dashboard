import { useEffect, useState } from "react";
import {
  Activity,
  ArrowRight,
  Database,
  FileJson,
  FileUp,
  Globe2,
  Layers3,
  Moon,
  Radar,
  ShieldCheck,
  Sparkles,
  Sun,
  Zap,
  type LucideIcon,
} from "lucide-react";

import { analyzeFile, analyzeIndicator } from "../api/client";
import { EvidenceTable } from "../components/EvidenceTable";
import { RiskScoreCard } from "../components/RiskScoreCard";
import { SourceStatusGrid } from "../components/SourceStatusGrid";
import type { AnalysisResponse } from "../types/results";

type ThemeMode = "light" | "dark";
type AnalyzeMode = "ioc" | "file";

const THEME_STORAGE_KEY = "ctid-theme";
const examples = ["8.8.8.8", "example.com", "https://example.com/login", "44d88612fea8a8f36de82e1278abb02f"];

export function AnalyzePage() {
  const [ioc, setIoc] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [mode, setMode] = useState<AnalyzeMode>("ioc");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [theme, setTheme] = useState<ThemeMode>(getInitialTheme);
  const sourceCounts = getSourceCounts(result);
  const canSubmit = mode === "file" ? Boolean(selectedFile) && !isLoading : Boolean(ioc.trim()) && !isLoading;

  useEffect(() => {
    const root = document.documentElement;
    root.classList.toggle("dark", theme === "dark");
    root.style.colorScheme = theme;
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  }, [theme]);

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setIsLoading(true);
    setError(null);

    try {
      const response = mode === "file" && selectedFile ? await analyzeFile(selectedFile) : await analyzeIndicator(ioc);
      setResult(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Analysis failed.");
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <main className="min-h-screen bg-[linear-gradient(135deg,#f8fafc_0%,#eef2ff_22%,#ecfeff_48%,#fef9c3_74%,#fff1f2_100%)] text-zinc-950 transition-colors dark:bg-[linear-gradient(135deg,#020617_0%,#0f172a_34%,#082f49_68%,#312e81_100%)] dark:text-zinc-50">
      <section className="overflow-hidden border-b border-white/70 bg-zinc-950 text-white shadow-xl dark:border-white/10 dark:bg-black/45">
        <div className="h-1 bg-[linear-gradient(90deg,#2dd4bf,#22d3ee,#fcd34d,#fb7185)]" />
        <div className="mx-auto max-w-7xl px-5 py-7 md:px-8">
          <div className="grid gap-6 lg:grid-cols-[1fr_420px] lg:items-end">
            <div>
              <div className="mb-4 flex flex-wrap items-center gap-3">
                <div className="inline-flex items-center gap-2 rounded-md border border-white/15 bg-white/10 px-3 py-2 text-sm font-medium text-cyan-100">
                  <Activity size={16} aria-hidden="true" />
                  Passive enrichment workspace
                </div>
                <button
                  type="button"
                  onClick={() => setTheme((current) => (current === "dark" ? "light" : "dark"))}
                  className="inline-flex items-center gap-2 rounded-md border border-white/15 bg-white/10 px-3 py-2 text-sm font-medium text-zinc-100 transition hover:border-cyan-300 hover:bg-cyan-300/15"
                  aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
                >
                  {theme === "dark" ? <Sun size={16} aria-hidden="true" /> : <Moon size={16} aria-hidden="true" />}
                  {theme === "dark" ? "Light" : "Dark"}
                </button>
              </div>
              <div>
                <div className="mb-3 flex items-center gap-3">
                  <div className="flex h-11 w-11 items-center justify-center rounded-md bg-gradient-to-br from-teal-400 via-cyan-400 to-amber-300 text-zinc-950 shadow-sm">
                    <ShieldCheck size={23} aria-hidden="true" />
                  </div>
                  <h1 className="text-2xl font-semibold tracking-normal md:text-3xl">
                    Cloud Threat Intelligence Dashboard
                  </h1>
                </div>
                <p className="max-w-2xl text-sm leading-6 text-zinc-300 md:text-base">
                  Submit an IOC, compare live third-party intelligence, and get a transparent risk score with analyst-ready evidence.
                </p>
              </div>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <SignalTile icon={Globe2} label="Connectors" value={result ? `${sourceCounts.total} checked` : "Ready"} tone="cyan" />
              <SignalTile icon={Layers3} label="Evidence" value={result ? `${result.risk_report.contributions.length} factors` : "Waiting"} tone="amber" />
            </div>
          </div>

          <form
            onSubmit={handleSubmit}
            className="mt-6 grid gap-3 rounded-md border border-white/10 bg-white/10 p-3 shadow-2xl shadow-black/20 backdrop-blur md:grid-cols-[1fr_auto]"
          >
            <div className="grid gap-3">
              <div className="inline-grid w-full grid-cols-2 gap-1 rounded-md border border-white/10 bg-black/20 p-1 sm:w-72">
                <ModeButton icon={Radar} label="IOC" isActive={mode === "ioc"} onClick={() => setMode("ioc")} />
                <ModeButton icon={FileUp} label="File" isActive={mode === "file"} onClick={() => setMode("file")} />
              </div>
              {mode === "ioc" ? (
                <>
                  <label className="sr-only" htmlFor="ioc-input">
                    Indicator
                  </label>
                  <input
                    id="ioc-input"
                    value={ioc}
                    onChange={(event) => setIoc(event.target.value)}
                    className="h-12 rounded-md border border-white/20 bg-white px-4 text-base text-zinc-950 shadow-sm outline-none ring-cyan-300 transition placeholder:text-zinc-400 focus:ring-2 dark:border-white/10 dark:bg-slate-950 dark:text-zinc-50 dark:placeholder:text-zinc-500"
                    placeholder="IP, domain, URL, or hash"
                    maxLength={2048}
                  />
                </>
              ) : (
                <div className="grid gap-3 sm:grid-cols-[auto_1fr]">
                  <label
                    htmlFor="file-input"
                    className="inline-flex h-12 cursor-pointer items-center justify-center gap-2 rounded-md border border-cyan-300/40 bg-cyan-300/15 px-4 text-sm font-semibold text-cyan-50 transition hover:bg-cyan-300/25"
                  >
                    <FileUp size={18} aria-hidden="true" />
                    Choose file
                  </label>
                  <input
                    id="file-input"
                    type="file"
                    className="sr-only"
                    onChange={(event) => setSelectedFile(event.target.files?.[0] ?? null)}
                  />
                  <div className="flex min-h-12 items-center rounded-md border border-white/15 bg-black/20 px-4 text-sm text-zinc-200">
                    {selectedFile ? `${selectedFile.name} · ${formatFileSize(selectedFile.size)}` : "No file selected"}
                  </div>
                </div>
              )}
            </div>
            <button
              type="submit"
              disabled={!canSubmit}
              className="inline-flex h-12 items-center justify-center gap-2 rounded-md bg-gradient-to-r from-teal-400 via-cyan-400 to-amber-300 px-5 text-sm font-semibold text-zinc-950 shadow-sm transition hover:brightness-110 disabled:cursor-not-allowed disabled:from-zinc-500 disabled:via-zinc-500 disabled:to-zinc-500 disabled:text-zinc-200"
            >
              <ShieldCheck size={18} aria-hidden="true" />
              {isLoading ? "Analyzing" : mode === "file" ? "Analyze file" : "Analyze"}
              <ArrowRight size={16} aria-hidden="true" />
            </button>
          </form>

          {mode === "ioc" ? (
            <div className="mt-3 flex flex-wrap gap-2">
              {examples.map((example) => (
                <button
                  key={example}
                  type="button"
                  onClick={() => setIoc(example)}
                  className="rounded-md border border-white/15 bg-white/10 px-3 py-1.5 text-sm text-zinc-200 shadow-sm transition hover:border-cyan-300 hover:bg-cyan-300/15 hover:text-white"
                >
                  {example}
                </button>
              ))}
            </div>
          ) : null}
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-5 py-6 md:px-8">
        <div className="mb-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <MetricCard icon={Radar} label="Severity" value={result?.risk_report.severity ?? "Ready"} tone="teal" />
          <MetricCard icon={Zap} label="Score" value={result ? `${result.risk_report.score}/100` : "0/100"} tone="amber" />
          <MetricCard icon={Globe2} label="Sources" value={result ? `${sourceCounts.success}/${sourceCounts.total} live` : "Not run"} tone="cyan" />
          <MetricCard icon={Sparkles} label="Overview" value={result ? "Generated" : "Ready"} tone="rose" />
        </div>

        <div className="grid gap-4 md:grid-cols-[360px_1fr]">
          <div className="space-y-4">
            <RiskScoreCard report={result?.risk_report ?? null} />
            <div className="overflow-hidden rounded-md border border-white/70 bg-white/[0.92] shadow-sm ring-1 ring-zinc-200/60 backdrop-blur dark:border-white/10 dark:bg-slate-950/85 dark:ring-white/10">
              <div className="h-1 bg-gradient-to-r from-cyan-500 to-teal-500" />
              <div className="p-4">
                <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-zinc-950 dark:text-zinc-100">
                  <Database size={17} aria-hidden="true" />
                  IOC Details
                </div>
                {result ? (
                  <dl className="grid gap-3 text-sm">
                    <div>
                      <dt className="text-zinc-500 dark:text-zinc-400">Type</dt>
                      <dd className="font-medium uppercase text-zinc-900 dark:text-zinc-100">{result.ioc.input_type}</dd>
                    </div>
                    <div>
                      <dt className="text-zinc-500 dark:text-zinc-400">{result.ioc.input_type === "file" ? "SHA-256" : "Normalized"}</dt>
                      <dd className="break-words font-mono text-xs text-zinc-900 dark:text-zinc-100">{result.ioc.normalized_value}</dd>
                    </div>
                    <div>
                      <dt className="text-zinc-500 dark:text-zinc-400">Analysis ID</dt>
                      <dd className="break-words font-mono text-xs text-zinc-900 dark:text-zinc-100">{result.analysis_id}</dd>
                    </div>
                  </dl>
                ) : (
                  <p className="text-sm text-zinc-500 dark:text-zinc-400">No analysis selected.</p>
                )}
              </div>
            </div>
          </div>

          <div className="space-y-4">
            {error ? (
              <div className="rounded-md border border-rose-200 bg-rose-50 p-4 text-sm text-rose-900 dark:border-rose-500/40 dark:bg-rose-950/60 dark:text-rose-100">
                {error}
              </div>
            ) : null}
            <div className="overflow-hidden rounded-md border border-white/70 bg-white/[0.92] shadow-sm ring-1 ring-zinc-200/60 backdrop-blur dark:border-white/10 dark:bg-slate-950/85 dark:ring-white/10">
              <div className="h-1 bg-gradient-to-r from-amber-400 via-cyan-500 to-teal-500" />
              <div className="p-4">
                <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-zinc-950 dark:text-zinc-100">
                  <FileJson size={17} aria-hidden="true" />
                  Analyst Summary
                </div>
                <p className="text-sm leading-6 text-zinc-700 dark:text-zinc-300">
                  {result?.risk_report.summary ?? "Run an analysis to generate the first report."}
                </p>
              </div>
            </div>
            <SourceStatusGrid sources={result?.source_results ?? []} />
            <EvidenceTable report={result?.risk_report ?? null} />
          </div>
        </div>
      </section>
    </main>
  );
}

function ModeButton({ icon: Icon, label, isActive, onClick }: { icon: LucideIcon; label: string; isActive: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`inline-flex h-9 items-center justify-center gap-2 rounded-md text-sm font-semibold transition ${
        isActive ? "bg-white text-zinc-950 shadow-sm" : "text-zinc-300 hover:bg-white/10 hover:text-white"
      }`}
      aria-pressed={isActive}
    >
      <Icon size={15} aria-hidden="true" />
      {label}
    </button>
  );
}

function SignalTile({ icon: Icon, label, value, tone }: { icon: LucideIcon; label: string; value: string; tone: "cyan" | "amber" }) {
  const tones = {
    cyan: "from-cyan-400/20 to-teal-400/10 text-cyan-100",
    amber: "from-amber-300/20 to-rose-300/10 text-amber-100",
  };

  return (
    <div className={`rounded-md border border-white/10 bg-gradient-to-br ${tones[tone]} p-4 shadow-sm`}>
      <div className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase text-white/60">
        <Icon size={15} aria-hidden="true" />
        {label}
      </div>
      <div className="text-lg font-semibold text-white">{value}</div>
    </div>
  );
}

function MetricCard({ icon: Icon, label, value, tone }: { icon: LucideIcon; label: string; value: string; tone: "teal" | "amber" | "cyan" | "rose" }) {
  const tones = {
    teal: "from-teal-500/20 via-white to-teal-50 text-teal-800 dark:from-teal-400/20 dark:via-slate-950/85 dark:to-emerald-950/70 dark:text-teal-200",
    amber: "from-amber-400/25 via-white to-amber-50 text-amber-800 dark:from-amber-300/20 dark:via-slate-950/85 dark:to-yellow-950/70 dark:text-amber-200",
    cyan: "from-cyan-500/20 via-white to-cyan-50 text-cyan-800 dark:from-cyan-400/20 dark:via-slate-950/85 dark:to-sky-950/70 dark:text-cyan-200",
    rose: "from-rose-500/20 via-white to-rose-50 text-rose-800 dark:from-rose-400/20 dark:via-slate-950/85 dark:to-fuchsia-950/70 dark:text-rose-200",
  };

  return (
    <div className={`rounded-md border border-white/80 bg-gradient-to-br ${tones[tone]} p-3 shadow-sm ring-1 ring-zinc-200/50 dark:border-white/10 dark:ring-white/10`}>
      <div className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase text-zinc-500 dark:text-zinc-400">
        <Icon size={15} aria-hidden="true" />
        {label}
      </div>
      <div className="text-lg font-semibold text-zinc-950 dark:text-zinc-50">{value}</div>
    </div>
  );
}

function getInitialTheme(): ThemeMode {
  if (typeof window === "undefined") {
    return "light";
  }
  const saved = window.localStorage.getItem(THEME_STORAGE_KEY);
  if (saved === "light" || saved === "dark") {
    return saved;
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function formatFileSize(size: number) {
  if (size < 1024) {
    return `${size} B`;
  }
  if (size < 1024 * 1024) {
    return `${(size / 1024).toFixed(1)} KB`;
  }
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}

function getSourceCounts(result: AnalysisResponse | null) {
  if (!result) {
    return { success: 0, total: 0 };
  }
  return {
    success: result.source_results.filter((source) => source.status === "success" || source.status === "partial").length,
    total: result.source_results.length,
  };
}
