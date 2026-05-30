import { type CSSProperties, useEffect, useRef, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock3,
  Cpu,
  Database,
  FileJson,
  FileUp,
  Github,
  Globe2,
  Instagram,
  Layers3,
  Linkedin,
  Mail,
  Moon,
  Network,
  Radar,
  Server,
  ShieldCheck,
  Sparkles,
  Sun,
  Terminal,
  UploadCloud,
  X,
  Zap,
  type LucideIcon,
} from "lucide-react";

import { analyzeFile, analyzeIndicator, runNmapScan } from "../api/client";
import { EvidenceTable } from "../components/EvidenceTable";
import { RiskScoreCard } from "../components/RiskScoreCard";
import { SourceStatusGrid } from "../components/SourceStatusGrid";
import type { AnalysisResponse, NmapPreset, NmapScanResponse, Severity } from "../types/results";

type ThemeMode = "light" | "dark";
type AnalyzeMode = "ioc" | "file";

const THEME_STORAGE_KEY = "ctid-theme";
const examples = ["8.8.8.8", "example.com", "https://example.com/login", "44d88612fea8a8f36de82e1278abb02f"];
const confettiColors = ["#2dd4bf", "#38bdf8", "#a78bfa", "#f472b6", "#fb7185", "#fbbf24", "#84cc16"];
const creatorName = "Vishal Vasanthakumar Poornima";
const creatorEmail = "vpvishal2005@gmail.com";
type SocialTone = "instagram" | "github" | "linkedin";
const socialLinks: Array<{ label: string; href: string; icon: LucideIcon; tone: SocialTone }> = [
  {
    label: "Instagram",
    href: "https://www.instagram.com/vishalvasanthakumarpoornima/",
    icon: Instagram,
    tone: "instagram",
  },
  {
    label: "GitHub",
    href: "https://github.com/vishalvasanthakumarpoornima",
    icon: Github,
    tone: "github",
  },
  {
    label: "LinkedIn",
    href: "https://www.linkedin.com/in/vishalvasanthakumarpoornima",
    icon: Linkedin,
    tone: "linkedin",
  },
];
const socialToneClasses: Record<SocialTone, string> = {
  instagram:
    "border-pink-300/45 bg-pink-500/15 text-pink-100 shadow-pink-500/10 hover:border-pink-200 hover:bg-pink-500/25 hover:text-white",
  github:
    "border-emerald-300/35 bg-black/45 text-emerald-100 shadow-emerald-500/10 hover:border-emerald-300 hover:bg-emerald-400/15 hover:text-white",
  linkedin:
    "border-sky-300/45 bg-sky-600/25 text-sky-50 shadow-sky-500/10 hover:border-sky-200 hover:bg-sky-500/35 hover:text-white",
};
const nmapPresets: Array<{ id: NmapPreset; label: string; detail: string; icon: LucideIcon }> = [
  {
    id: "quick_ports",
    label: "Quick ports",
    detail: "Top 100 TCP ports",
    icon: Network,
  },
  {
    id: "open_ports",
    label: "Open ports",
    detail: "Top 1000 TCP ports",
    icon: Server,
  },
  {
    id: "service_detection",
    label: "Services",
    detail: "Versions on open ports",
    icon: Terminal,
  },
  {
    id: "os_detection",
    label: "OS info",
    detail: "OS fingerprint attempt",
    icon: Cpu,
  },
  {
    id: "stealth_syn",
    label: "SYN scan",
    detail: "Stealth-style TCP SYN",
    icon: AlertTriangle,
  },
];

export function AnalyzePage() {
  const [ioc, setIoc] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [mode, setMode] = useState<AnalyzeMode>("ioc");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [theme, setTheme] = useState<ThemeMode>(getInitialTheme);
  const [scrollProgress, setScrollProgress] = useState(0);
  const [celebrationRun, setCelebrationRun] = useState(0);
  const [isFileDragging, setIsFileDragging] = useState(false);
  const [scanTarget, setScanTarget] = useState("");
  const [scanPreset, setScanPreset] = useState<NmapPreset>("quick_ports");
  const [scanTimeout, setScanTimeout] = useState(45);
  const [isScanAuthorized, setIsScanAuthorized] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<NmapScanResponse | null>(null);
  const fileDragDepth = useRef(0);
  const scanTargetTouched = useRef(false);
  const lastScanAutofillAnalysisId = useRef<string | null>(null);
  const sourceCounts = getSourceCounts(result);
  const canSubmit = mode === "file" ? Boolean(selectedFile) && !isLoading : Boolean(ioc.trim()) && !isLoading;
  const canRunScan = Boolean(scanTarget.trim()) && isScanAuthorized && !isScanning;

  useScrollReveal(result?.analysis_id ?? null);

  useEffect(() => {
    const root = document.documentElement;
    root.classList.toggle("dark", theme === "dark");
    root.style.colorScheme = theme;
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  }, [theme]);

  useEffect(() => {
    if (!result || !["ip", "domain"].includes(result.ioc.input_type)) {
      return;
    }
    if (lastScanAutofillAnalysisId.current !== result.analysis_id) {
      lastScanAutofillAnalysisId.current = result.analysis_id;
      scanTargetTouched.current = false;
    }
    if (scanTargetTouched.current) {
      return;
    }
    setScanTarget((current) => current || result.ioc.normalized_value);
  }, [result?.analysis_id]);

  useEffect(() => {
    let frame = 0;

    const updateScrollProgress = () => {
      window.cancelAnimationFrame(frame);
      frame = window.requestAnimationFrame(() => {
        const scrollableHeight = document.documentElement.scrollHeight - window.innerHeight;
        const nextProgress = scrollableHeight > 0 ? (window.scrollY / scrollableHeight) * 100 : 0;
        setScrollProgress(Math.min(100, Math.max(0, nextProgress)));
      });
    };

    updateScrollProgress();
    window.addEventListener("scroll", updateScrollProgress, { passive: true });
    window.addEventListener("resize", updateScrollProgress);

    return () => {
      window.cancelAnimationFrame(frame);
      window.removeEventListener("scroll", updateScrollProgress);
      window.removeEventListener("resize", updateScrollProgress);
    };
  }, []);

  useEffect(() => {
    if (!celebrationRun) {
      return undefined;
    }

    const timeout = window.setTimeout(() => setCelebrationRun(0), 4200);
    return () => window.clearTimeout(timeout);
  }, [celebrationRun]);

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setIsLoading(true);
    setError(null);

    try {
      const response = mode === "file" && selectedFile ? await analyzeFile(selectedFile) : await analyzeIndicator(ioc);
      setResult(response);
      setCelebrationRun((current) => current + 1);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Analysis failed.");
    } finally {
      setIsLoading(false);
    }
  }

  function handleFileDragEnter(event: React.DragEvent<HTMLFormElement>) {
    if (!hasFileDrag(event.dataTransfer)) {
      return;
    }
    event.preventDefault();
    fileDragDepth.current += 1;
    setMode("file");
    setIsFileDragging(true);
  }

  function handleFileDragOver(event: React.DragEvent<HTMLFormElement>) {
    if (!hasFileDrag(event.dataTransfer)) {
      return;
    }
    event.preventDefault();
    event.dataTransfer.dropEffect = "copy";
  }

  function handleFileDragLeave(event: React.DragEvent<HTMLFormElement>) {
    if (!hasFileDrag(event.dataTransfer) && !isFileDragging) {
      return;
    }
    event.preventDefault();
    fileDragDepth.current = Math.max(0, fileDragDepth.current - 1);
    if (fileDragDepth.current === 0) {
      setIsFileDragging(false);
    }
  }

  function handleFileDrop(event: React.DragEvent<HTMLFormElement>) {
    if (!hasFileDrag(event.dataTransfer)) {
      return;
    }
    event.preventDefault();
    fileDragDepth.current = 0;
    setIsFileDragging(false);
    setMode("file");
    const droppedFile = event.dataTransfer.files.item(0);
    if (droppedFile) {
      setSelectedFile(droppedFile);
      setError(null);
    }
  }

  function handleFileSelect(event: React.ChangeEvent<HTMLInputElement>) {
    setSelectedFile(event.target.files?.[0] ?? null);
    setError(null);
  }

  async function handleNmapSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setIsScanning(true);
    setScanError(null);

    try {
      const response = await runNmapScan({
        target: scanTarget,
        preset: scanPreset,
        confirmed_authorized: isScanAuthorized,
        timeout_seconds: scanTimeout,
      });
      setScanResult(response);
    } catch (err) {
      setScanError(err instanceof Error ? err.message : "Nmap scan failed.");
    } finally {
      setIsScanning(false);
    }
  }

  function handleScanTargetChange(target: string) {
    scanTargetTouched.current = true;
    setScanTarget(target);
  }

  async function runServiceFollowUp() {
    if (!scanTarget.trim() || !isScanAuthorized) {
      return;
    }
    setScanPreset("service_detection");
    setIsScanning(true);
    setScanError(null);

    try {
      const response = await runNmapScan({
        target: scanTarget,
        preset: "service_detection",
        confirmed_authorized: isScanAuthorized,
        timeout_seconds: scanTimeout,
      });
      setScanResult(response);
    } catch (err) {
      setScanError(err instanceof Error ? err.message : "Nmap service detection failed.");
    } finally {
      setIsScanning(false);
    }
  }

  return (
    <main className="dashboard-shell min-h-screen bg-[linear-gradient(135deg,#f8fafc_0%,#eef2ff_22%,#ecfeff_48%,#fef9c3_74%,#fff1f2_100%)] text-zinc-950 transition-colors dark:bg-[linear-gradient(135deg,#020617_0%,#0f172a_34%,#082f49_68%,#312e81_100%)] dark:text-zinc-50">
      <div className="scroll-progress" style={{ transform: `scaleX(${scrollProgress / 100})` }} aria-hidden="true" />
      {celebrationRun ? <ConfettiBurst key={celebrationRun} severity={result?.risk_report.severity ?? "Low"} /> : null}

      <section className="relative isolate overflow-hidden border-b border-white/70 bg-zinc-950 text-white shadow-xl dark:border-white/10 dark:bg-black/45">
        <div className="hero-circuitry" aria-hidden="true" />
        <div className="hero-sheen" aria-hidden="true" />
        <div className="h-1 bg-[linear-gradient(90deg,#2dd4bf,#22d3ee,#fcd34d,#fb7185)]" />
        <div className="relative z-10 mx-auto max-w-7xl px-5 py-7 md:px-8">
          <header className="mb-7 flex flex-col gap-4 border-b border-white/10 pb-5 lg:flex-row lg:items-center lg:justify-between" data-scroll-reveal>
            <div className="flex min-w-0 items-center gap-3">
              <div className="brand-mark flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-gradient-to-br from-teal-400 via-cyan-400 to-amber-300 text-zinc-950 shadow-sm">
                <ShieldCheck size={22} aria-hidden="true" />
              </div>
              <div className="min-w-0">
                <h1 className="truncate text-base font-semibold tracking-normal text-white md:text-lg">
                  Threat Intelligence Dashboard
                </h1>
                <p className="mt-0.5 text-xs font-medium uppercase text-zinc-400">Threat intelligence workbench</p>
              </div>
            </div>

            <div className="flex flex-col gap-3 lg:items-end">
              <div className="flex flex-wrap items-center gap-2 lg:justify-end">
                <a
                  href={`mailto:${creatorEmail}`}
                  className="inline-flex min-h-9 max-w-full items-center gap-2 rounded-md border border-white/15 bg-white/10 px-3 py-2 text-sm font-semibold text-white shadow-sm shadow-cyan-500/10 backdrop-blur transition hover:-translate-y-0.5 hover:border-cyan-300 hover:bg-cyan-300/15"
                  aria-label={`Email ${creatorName}`}
                >
                  <Mail size={15} aria-hidden="true" />
                  <span className="min-w-0">
                    <span className="block truncate">{creatorName}</span>
                    <span className="block truncate text-xs font-medium text-zinc-300">{creatorEmail}</span>
                  </span>
                </a>
                <button
                  type="button"
                  onClick={() => setTheme((current) => (current === "dark" ? "light" : "dark"))}
                  className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-white/15 bg-white/10 text-zinc-100 shadow-sm shadow-cyan-500/10 backdrop-blur transition hover:-translate-y-0.5 hover:border-cyan-300 hover:bg-cyan-300/15"
                  aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
                  title={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
                >
                  {theme === "dark" ? <Sun size={16} aria-hidden="true" /> : <Moon size={16} aria-hidden="true" />}
                </button>
              </div>
              <div className="flex flex-wrap items-center gap-1.5 lg:justify-end">
                {socialLinks.map((link) => (
                  <SocialLink key={link.label} {...link} />
                ))}
              </div>
            </div>
          </header>

          <div className="grid gap-6 lg:grid-cols-[1fr_420px] lg:items-end">
            <div data-scroll-reveal>
              <div>
                <p className="max-w-2xl text-sm leading-6 text-zinc-300 md:text-base">
                  Submit an Indicator of Compromise (IOC), compare live third-party intelligence, and get a transparent risk score with analyst-ready evidence.
                </p>
              </div>
            </div>

            <div className="grid gap-3 sm:grid-cols-2" data-scroll-reveal>
              <SignalTile icon={Globe2} label="Connectors" value={result ? `${sourceCounts.total} checked` : "Ready"} tone="cyan" />
              <SignalTile icon={Layers3} label="Evidence" value={result ? `${result.risk_report.contributions.length} factors` : "Waiting"} tone="amber" />
            </div>
          </div>

          <form
            onSubmit={handleSubmit}
            onDragEnter={handleFileDragEnter}
            onDragOver={handleFileDragOver}
            onDragLeave={handleFileDragLeave}
            onDrop={handleFileDrop}
            className="search-panel mt-6 grid gap-3 rounded-md border border-white/10 bg-white/10 p-3 shadow-2xl shadow-black/20 backdrop-blur md:grid-cols-[1fr_auto]"
            data-scroll-reveal
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
                    className="h-12 rounded-md border border-white/20 bg-white px-4 text-base text-zinc-950 shadow-sm outline-none ring-cyan-300 transition placeholder:text-zinc-400 focus:border-cyan-300 focus:ring-2 dark:border-white/10 dark:bg-slate-950 dark:text-zinc-50 dark:placeholder:text-zinc-500"
                    placeholder="IP, domain, URL, or hash"
                    maxLength={2048}
                  />
                </>
              ) : (
                <div className="grid gap-3">
                  <label
                    htmlFor="file-input"
                    className={`file-drop-zone flex min-h-28 cursor-pointer items-center gap-4 rounded-md border px-4 py-4 text-left transition ${
                      isFileDragging
                        ? "is-dragging border-amber-200 bg-amber-300/20 text-white"
                        : "border-cyan-300/40 bg-cyan-300/15 text-cyan-50 hover:-translate-y-0.5 hover:bg-cyan-300/25"
                    }`}
                  >
                    <span className="file-drop-icon flex h-14 w-14 shrink-0 items-center justify-center rounded-md border border-white/15 bg-white/10 text-cyan-100">
                      <UploadCloud size={27} aria-hidden="true" />
                    </span>
                    <span className="grid gap-1">
                      <span className="text-sm font-semibold">
                        {isFileDragging ? "Drop file for VirusTotal check" : selectedFile ? "File ready for VirusTotal" : "Drop file here or choose file"}
                      </span>
                      <span className="text-xs leading-5 text-cyan-100/80">
                        {selectedFile ? `${selectedFile.name} · ${formatFileSize(selectedFile.size)}` : "The backend hashes the upload first and checks VirusTotal by SHA-256."}
                      </span>
                    </span>
                  </label>
                  <input
                    id="file-input"
                    type="file"
                    className="sr-only"
                    onChange={handleFileSelect}
                  />
                  {selectedFile ? (
                    <div className="flex min-h-12 flex-wrap items-center justify-between gap-3 rounded-md border border-white/15 bg-black/20 px-4 text-sm text-zinc-200">
                      <span className="break-all">
                        {selectedFile.name} · {formatFileSize(selectedFile.size)}
                      </span>
                      <button
                        type="button"
                        onClick={() => setSelectedFile(null)}
                        className="inline-flex h-8 items-center justify-center gap-2 rounded-md border border-white/15 bg-white/10 px-3 text-xs font-semibold text-zinc-100 transition hover:border-rose-300 hover:bg-rose-400/15"
                      >
                        <X size={14} aria-hidden="true" />
                        Clear
                      </button>
                    </div>
                  ) : null}
                </div>
              )}
            </div>
            <button
              type="submit"
              disabled={!canSubmit}
              className="animated-submit inline-flex h-12 items-center justify-center gap-2 rounded-md bg-gradient-to-r from-teal-400 via-cyan-400 to-amber-300 px-5 text-sm font-semibold text-zinc-950 shadow-lg shadow-cyan-500/20 transition hover:-translate-y-0.5 hover:brightness-110 disabled:cursor-not-allowed disabled:from-zinc-500 disabled:via-zinc-500 disabled:to-zinc-500 disabled:text-zinc-200 disabled:shadow-none"
            >
              <ShieldCheck size={18} aria-hidden="true" />
              {isLoading ? "Analyzing" : mode === "file" ? "Analyze file" : "Analyze"}
              <ArrowRight size={16} aria-hidden="true" />
            </button>
          </form>

          {isLoading ? (
            <div className="analysis-beam mt-3" aria-hidden="true">
              <span />
            </div>
          ) : null}

          {mode === "ioc" ? (
            <div className="mt-3 flex flex-wrap gap-2">
              {examples.map((example) => (
                <button
                  key={example}
                  type="button"
                  onClick={() => setIoc(example)}
                  className="rounded-md border border-white/15 bg-white/10 px-3 py-1.5 text-sm text-zinc-200 shadow-sm transition hover:-translate-y-0.5 hover:border-cyan-300 hover:bg-cyan-300/15 hover:text-white"
                >
                  {example}
                </button>
              ))}
            </div>
          ) : null}
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-5 py-6 md:px-8">
        {result ? (
          <div
            className="result-toast mb-4 flex flex-wrap items-center gap-3 rounded-md border border-emerald-200/80 bg-emerald-50/90 px-4 py-3 text-sm text-emerald-950 shadow-lg shadow-emerald-500/10 ring-1 ring-white/80 backdrop-blur dark:border-emerald-300/20 dark:bg-emerald-400/10 dark:text-emerald-100 dark:ring-white/10"
            data-scroll-reveal
            role="status"
            aria-live="polite"
          >
            <span className="flex h-8 w-8 items-center justify-center rounded-md bg-emerald-500 text-white shadow-sm shadow-emerald-500/30">
              <CheckCircle2 size={18} aria-hidden="true" />
            </span>
            <span className="font-semibold">Analysis complete</span>
            <span className="text-emerald-800 dark:text-emerald-200">
              {result.risk_report.severity} risk · {sourceCounts.success}/{sourceCounts.total} sources returned signal
            </span>
          </div>
        ) : null}

        <div className="mb-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4" data-scroll-reveal>
          <MetricCard icon={Radar} label="Severity" value={result?.risk_report.severity ?? "Ready"} tone="teal" />
          <MetricCard icon={Zap} label="Score" value={result ? `${result.risk_report.score}/100` : "0/100"} tone="amber" />
          <MetricCard icon={Globe2} label="Sources" value={result ? `${sourceCounts.success}/${sourceCounts.total} live` : "Not run"} tone="cyan" />
          <MetricCard icon={Sparkles} label="Overview" value={result ? "Generated" : "Ready"} tone="rose" />
        </div>

        <ActiveScanPanel
          target={scanTarget}
          onTargetChange={handleScanTargetChange}
          preset={scanPreset}
          onPresetChange={setScanPreset}
          timeout={scanTimeout}
          onTimeoutChange={setScanTimeout}
          isAuthorized={isScanAuthorized}
          onAuthorizedChange={setIsScanAuthorized}
          canRun={canRunScan}
          isScanning={isScanning}
          error={scanError}
          result={scanResult}
          onSubmit={handleNmapSubmit}
          onRunServiceFollowUp={runServiceFollowUp}
        />

        <div className="grid min-w-0 gap-4 md:grid-cols-[360px_1fr]">
          <div className="min-w-0 space-y-4" data-scroll-reveal>
            <RiskScoreCard report={result?.risk_report ?? null} />
            <div className="effect-card overflow-hidden rounded-md border border-white/70 bg-white/[0.92] shadow-sm ring-1 ring-zinc-200/60 backdrop-blur dark:border-white/10 dark:bg-slate-950/85 dark:ring-white/10">
              <div className="h-1 bg-gradient-to-r from-cyan-500 to-teal-500" />
              <div className="p-4">
                <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-zinc-950 dark:text-zinc-100">
                  <Database size={17} aria-hidden="true" />
                  Indicator of Compromise Details
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

          <div className="min-w-0 space-y-4" data-scroll-reveal>
            {error ? (
              <div className="rounded-md border border-rose-200 bg-rose-50 p-4 text-sm text-rose-900 dark:border-rose-500/40 dark:bg-rose-950/60 dark:text-rose-100">
                {error}
              </div>
            ) : null}
            <div className={`effect-card overflow-hidden rounded-md border border-white/70 bg-white/[0.92] shadow-sm ring-1 ring-zinc-200/60 backdrop-blur dark:border-white/10 dark:bg-slate-950/85 dark:ring-white/10 ${result ? "result-glow" : ""}`}>
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

function ActiveScanPanel({
  target,
  onTargetChange,
  preset,
  onPresetChange,
  timeout,
  onTimeoutChange,
  isAuthorized,
  onAuthorizedChange,
  canRun,
  isScanning,
  error,
  result,
  onSubmit,
  onRunServiceFollowUp,
}: {
  target: string;
  onTargetChange: (target: string) => void;
  preset: NmapPreset;
  onPresetChange: (preset: NmapPreset) => void;
  timeout: number;
  onTimeoutChange: (timeout: number) => void;
  isAuthorized: boolean;
  onAuthorizedChange: (isAuthorized: boolean) => void;
  canRun: boolean;
  isScanning: boolean;
  error: string | null;
  result: NmapScanResponse | null;
  onSubmit: (event: React.FormEvent<HTMLFormElement>) => void;
  onRunServiceFollowUp: () => void;
}) {
  const canFollowUp =
    result !== null && result.ports.length > 0 && result.preset !== "service_detection" && isAuthorized && !isScanning;

  return (
    <section
      className="effect-card mb-4 overflow-hidden rounded-md border border-white/70 bg-white/[0.92] shadow-sm ring-1 ring-zinc-200/60 backdrop-blur dark:border-white/10 dark:bg-slate-950/85 dark:ring-white/10"
      data-scroll-reveal
    >
      <div className="border-b border-zinc-200 bg-gradient-to-r from-zinc-950 via-slate-900 to-cyan-950 p-4 text-white dark:border-white/10">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-sm font-semibold">
            <Terminal size={17} aria-hidden="true" />
            Active Nmap Scan
          </div>
          <div className="inline-flex items-center gap-2 rounded-md border border-amber-200/30 bg-amber-300/10 px-2.5 py-1 text-xs font-semibold text-amber-100">
            <AlertTriangle size={14} aria-hidden="true" />
            Authorized targets only
          </div>
        </div>
      </div>

      <form onSubmit={onSubmit} className="grid gap-4 p-4">
        <div className="grid gap-3 lg:grid-cols-[1fr_160px]">
          <div className="grid gap-2">
            <label className="text-xs font-semibold uppercase text-zinc-500 dark:text-zinc-400" htmlFor="nmap-target">
              Target
            </label>
            <input
              id="nmap-target"
              value={target}
              onChange={(event) => onTargetChange(event.target.value)}
              className="h-11 rounded-md border border-zinc-200 bg-white px-3 text-sm text-zinc-950 shadow-sm outline-none ring-cyan-300 transition placeholder:text-zinc-400 focus:border-cyan-400 focus:ring-2 dark:border-white/10 dark:bg-slate-950 dark:text-zinc-50"
              placeholder="IP address or domain"
              maxLength={253}
            />
          </div>
          <div className="grid gap-2">
            <label className="text-xs font-semibold uppercase text-zinc-500 dark:text-zinc-400" htmlFor="nmap-timeout">
              Timeout
            </label>
            <div className="flex h-11 items-center gap-2 rounded-md border border-zinc-200 bg-white px-3 text-sm text-zinc-950 shadow-sm dark:border-white/10 dark:bg-slate-950 dark:text-zinc-50">
              <Clock3 size={15} aria-hidden="true" />
              <input
                id="nmap-timeout"
                type="number"
                min={10}
                max={180}
                value={timeout}
                onChange={(event) => onTimeoutChange(Number(event.target.value))}
                className="w-full bg-transparent outline-none"
              />
              <span className="text-xs text-zinc-500 dark:text-zinc-400">sec</span>
            </div>
          </div>
        </div>

        <div className="grid gap-2">
          <div className="text-xs font-semibold uppercase text-zinc-500 dark:text-zinc-400">Preset</div>
          <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-5">
            {nmapPresets.map((item) => (
              <ScanPresetButton
                key={item.id}
                preset={item}
                isActive={preset === item.id}
                onClick={() => onPresetChange(item.id)}
              />
            ))}
          </div>
        </div>

        <label className="flex cursor-pointer items-start gap-3 rounded-md border border-amber-200 bg-amber-50/80 px-3 py-3 text-sm text-amber-950 transition hover:-translate-y-0.5 dark:border-amber-300/20 dark:bg-amber-300/10 dark:text-amber-100">
          <input
            type="checkbox"
            checked={isAuthorized}
            onChange={(event) => onAuthorizedChange(event.target.checked)}
            className="mt-1 h-4 w-4 accent-cyan-500"
          />
          <span>I am authorized to actively scan this target.</span>
        </label>

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="submit"
            disabled={!canRun}
            className="inline-flex h-10 items-center justify-center gap-2 rounded-md bg-zinc-950 px-4 text-sm font-semibold text-white shadow-sm transition hover:-translate-y-0.5 hover:bg-cyan-700 disabled:cursor-not-allowed disabled:bg-zinc-400 dark:bg-cyan-400 dark:text-zinc-950 dark:hover:bg-cyan-300 dark:disabled:bg-zinc-700 dark:disabled:text-zinc-400"
          >
            <Terminal size={16} aria-hidden="true" />
            {isScanning ? "Scanning" : "Run Nmap"}
          </button>
          {canFollowUp ? (
            <button
              type="button"
              onClick={onRunServiceFollowUp}
              className="inline-flex h-10 items-center justify-center gap-2 rounded-md border border-cyan-200 bg-cyan-50 px-4 text-sm font-semibold text-cyan-900 transition hover:-translate-y-0.5 hover:border-cyan-400 dark:border-cyan-300/30 dark:bg-cyan-300/10 dark:text-cyan-100"
            >
              <Server size={16} aria-hidden="true" />
              Detect services
            </button>
          ) : null}
          {result ? (
            <span className="text-sm text-zinc-500 dark:text-zinc-400">
              {result.status.replace("_", " ")} · {result.duration_seconds}s
            </span>
          ) : null}
        </div>
      </form>

      {error ? (
        <div className="mx-4 mb-4 rounded-md border border-rose-200 bg-rose-50 p-3 text-sm text-rose-900 dark:border-rose-500/40 dark:bg-rose-950/60 dark:text-rose-100">
          {error}
        </div>
      ) : null}

      {result ? <NmapResults result={result} /> : null}
    </section>
  );
}

function ScanPresetButton({
  preset,
  isActive,
  onClick,
}: {
  preset: { id: NmapPreset; label: string; detail: string; icon: LucideIcon };
  isActive: boolean;
  onClick: () => void;
}) {
  const Icon = preset.icon;
  return (
    <button
      type="button"
      onClick={onClick}
      className={`flex min-h-20 flex-col items-start justify-between rounded-md border p-3 text-left transition hover:-translate-y-0.5 ${
        isActive
          ? "border-cyan-400 bg-cyan-50 text-cyan-950 shadow-sm dark:border-cyan-300 dark:bg-cyan-300/15 dark:text-cyan-100"
          : "border-zinc-200 bg-white text-zinc-700 hover:border-cyan-300 dark:border-white/10 dark:bg-slate-950 dark:text-zinc-200"
      }`}
      aria-pressed={isActive}
    >
      <span className="flex items-center gap-2 text-sm font-semibold">
        <Icon size={16} aria-hidden="true" />
        {preset.label}
      </span>
      <span className="text-xs text-zinc-500 dark:text-zinc-400">{preset.detail}</span>
    </button>
  );
}

function NmapResults({ result }: { result: NmapScanResponse }) {
  return (
    <div className="border-t border-zinc-200 p-4 dark:border-white/10">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-sm font-semibold text-zinc-950 dark:text-zinc-100">{result.summary}</div>
          <div className="mt-1 font-mono text-xs text-zinc-500 dark:text-zinc-400">{result.command.join(" ")}</div>
        </div>
        {result.error_message ? (
          <span className="rounded-md border border-rose-200 bg-rose-50 px-2 py-1 text-xs font-semibold text-rose-800 dark:border-rose-400/30 dark:bg-rose-400/10 dark:text-rose-100">
            {result.error_message}
          </span>
        ) : null}
      </div>

      {result.ports.length ? (
        <div className="overflow-x-auto rounded-md border border-zinc-200 dark:border-white/10">
          <table className="w-full min-w-[680px] text-left text-sm">
            <thead className="bg-zinc-50 text-xs uppercase text-zinc-500 dark:bg-slate-900 dark:text-zinc-400">
              <tr>
                <th className="px-3 py-2 font-medium">Port</th>
                <th className="px-3 py-2 font-medium">State</th>
                <th className="px-3 py-2 font-medium">Service</th>
                <th className="px-3 py-2 font-medium">Version</th>
                <th className="px-3 py-2 font-medium">Reason</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-100 dark:divide-white/10">
              {result.ports.map((port) => (
                <tr key={`${port.protocol}-${port.port}`} className="transition hover:bg-cyan-50/70 dark:hover:bg-cyan-400/10">
                  <td className="px-3 py-2 font-mono text-xs text-zinc-950 dark:text-zinc-100">
                    {port.port}/{port.protocol}
                  </td>
                  <td className="px-3 py-2 text-zinc-700 dark:text-zinc-200">{port.state}</td>
                  <td className="px-3 py-2 text-zinc-700 dark:text-zinc-200">{port.service_name ?? "unknown"}</td>
                  <td className="px-3 py-2 text-zinc-600 dark:text-zinc-300">
                    {[port.product, port.version, port.extra_info].filter(Boolean).join(" ") || "not detected"}
                  </td>
                  <td className="px-3 py-2 text-zinc-500 dark:text-zinc-400">{port.reason ?? "n/a"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="rounded-md border border-zinc-200 bg-zinc-50 p-3 text-sm text-zinc-500 dark:border-white/10 dark:bg-white/5 dark:text-zinc-400">
          No open ports returned.
        </div>
      )}

      {result.os_matches.length ? (
        <div className="mt-3 flex flex-wrap gap-2">
          {result.os_matches.map((match) => (
            <span key={match.name} className="rounded-md bg-zinc-100 px-2 py-1 text-xs font-medium text-zinc-700 dark:bg-white/5 dark:text-zinc-200">
              {match.name}
              {match.accuracy ? ` · ${match.accuracy}%` : ""}
            </span>
          ))}
        </div>
      ) : null}

      {result.warnings.length ? (
        <div className="mt-3 grid gap-2">
          {result.warnings.map((warning) => (
            <div key={warning} className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-300/20 dark:bg-amber-300/10 dark:text-amber-100">
              {warning}
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function ConfettiBurst({ severity }: { severity: Severity }) {
  const pieces = Array.from({ length: severity === "Critical" || severity === "High" ? 64 : 52 }, (_, index) => {
    const spread = (index * 37) % 100;
    const drift = ((index % 13) - 6) * 16;
    const color = confettiColors[index % confettiColors.length];
    const size = 8 + (index % 5) * 2;
    const duration = 2.6 + (index % 8) * 0.12;

    return {
      id: index,
      style: {
        "--confetti-left": `${spread}%`,
        "--confetti-drift": `${drift}px`,
        "--confetti-color": color,
        "--confetti-size": `${size}px`,
        "--confetti-height": `${Math.round(size * 1.55)}px`,
        "--confetti-delay": `${(index % 9) * 0.035}s`,
        "--confetti-duration": `${duration}s`,
        "--confetti-rotate": `${(index * 29) % 180}deg`,
      } as CSSProperties,
    };
  });

  return (
    <div className="confetti-layer" aria-hidden="true">
      {pieces.map((piece) => (
        <span key={piece.id} className="confetti-piece" style={piece.style} />
      ))}
    </div>
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

function SocialLink({ href, label, icon: Icon, tone }: { href: string; label: string; icon: LucideIcon; tone: SocialTone }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer"
      className={`inline-flex h-8 items-center justify-center gap-1.5 rounded-md border px-2.5 text-xs font-semibold shadow-sm transition hover:-translate-y-0.5 ${socialToneClasses[tone]}`}
      aria-label={`Visit ${creatorName}'s ${label}`}
      title={label}
    >
      <Icon size={14} aria-hidden="true" />
      <span>{label}</span>
    </a>
  );
}

function SignalTile({ icon: Icon, label, value, tone }: { icon: LucideIcon; label: string; value: string; tone: "cyan" | "amber" }) {
  const tones = {
    cyan: "from-cyan-400/20 to-teal-400/10 text-cyan-100",
    amber: "from-amber-300/20 to-rose-300/10 text-amber-100",
  };

  return (
    <div className={`effect-card rounded-md border border-white/10 bg-gradient-to-br ${tones[tone]} p-4 shadow-sm`}>
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
    <div className={`effect-card rounded-md border border-white/80 bg-gradient-to-br ${tones[tone]} p-3 shadow-sm ring-1 ring-zinc-200/50 dark:border-white/10 dark:ring-white/10`}>
      <div className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase text-zinc-500 dark:text-zinc-400">
        <Icon size={15} aria-hidden="true" />
        {label}
      </div>
      <div className="text-lg font-semibold text-zinc-950 dark:text-zinc-50">{value}</div>
    </div>
  );
}

function useScrollReveal(refreshKey: string | null) {
  useEffect(() => {
    const elements = Array.from(document.querySelectorAll<HTMLElement>("[data-scroll-reveal]"));

    if (!elements.length) {
      return undefined;
    }

    if (!("IntersectionObserver" in window)) {
      elements.forEach((element) => element.classList.add("is-visible"));
      return undefined;
    }

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-visible");
            observer.unobserve(entry.target);
          }
        });
      },
      { rootMargin: "0px 0px -10% 0px", threshold: 0.14 },
    );

    elements.forEach((element, index) => {
      element.style.setProperty("--reveal-delay", `${Math.min(index * 55, 330)}ms`);
      observer.observe(element);
    });

    return () => observer.disconnect();
  }, [refreshKey]);
}

function hasFileDrag(dataTransfer: DataTransfer) {
  return Array.from(dataTransfer.types).includes("Files");
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
