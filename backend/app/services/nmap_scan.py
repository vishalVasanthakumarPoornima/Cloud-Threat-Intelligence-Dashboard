import asyncio
import shutil
import time
from datetime import datetime, timezone
from html.parser import HTMLParser

from app.core.config import Settings
from app.schemas.active_scan import NmapOsMatch, NmapPortResult, NmapScanRequest, NmapScanResponse
from app.services.classifier import ClassifiedIOC

PRESET_ARGS: dict[str, list[str]] = {
    "quick_ports": ["-Pn", "-T3", "--top-ports", "100", "--open"],
    "open_ports": ["-Pn", "-T3", "--top-ports", "1000", "--open"],
    "service_detection": ["-Pn", "-T3", "-sV", "--version-light", "--top-ports", "1000", "--open"],
    "os_detection": ["-Pn", "-T3", "-O", "--osscan-limit", "--top-ports", "100", "--open"],
    "stealth_syn": ["-Pn", "-T2", "-sS", "--top-ports", "1000", "--open"],
}
FALLBACK_PRESET_ARGS: dict[str, list[str]] = {
    "os_detection": ["-Pn", "-T3", "-sV", "--version-light", "--top-ports", "1000", "--open"],
    "stealth_syn": ["-Pn", "-T3", "-sT", "--top-ports", "1000", "--open"],
}
PRIVILEGED_PRESETS = {"os_detection", "stealth_syn"}


async def run_nmap_scan(
    *,
    request: NmapScanRequest,
    classified: ClassifiedIOC,
    settings: Settings,
) -> NmapScanResponse:
    started_at = datetime.now(timezone.utc)
    start_time = time.monotonic()
    nmap_path = settings.nmap_path or shutil.which("nmap")

    if not nmap_path:
        return _failed_response(
            request=request,
            classified=classified,
            command=["nmap"],
            started_at=started_at,
            start_time=start_time,
            status="not_available",
            message="Nmap is not installed or is not available on the backend PATH.",
        )

    command = build_nmap_command(
        nmap_path=nmap_path,
        preset=request.preset,
        target=classified.normalized_value,
        timeout_seconds=request.timeout_seconds,
        use_sudo=should_use_sudo(request.preset, settings=settings),
        sudo_path=settings.nmap_sudo_path,
    )

    stdout, stderr, returncode, execution_error = await _run_command(command, timeout_seconds=request.timeout_seconds)
    if execution_error:
        return _failed_response(
            request=request,
            classified=classified,
            command=command,
            started_at=started_at,
            start_time=start_time,
            status="timeout" if returncode is None else "failed",
            message=execution_error,
        )

    stderr_lines = _clean_stderr(stderr)
    fallback_warning = None
    privilege_message = _privilege_error_message(stderr_lines)
    if returncode != 0 and not stdout.strip() and privilege_message and request.preset in FALLBACK_PRESET_ARGS:
        fallback_warning = _fallback_warning(request.preset, privilege_message)
        command = build_nmap_command(
            nmap_path=nmap_path,
            preset=request.preset,
            target=classified.normalized_value,
            timeout_seconds=request.timeout_seconds,
            use_sudo=False,
            args=FALLBACK_PRESET_ARGS[request.preset],
        )
        stdout, fallback_stderr, returncode, execution_error = await _run_command(command, timeout_seconds=request.timeout_seconds)
        if execution_error:
            return _failed_response(
                request=request,
                classified=classified,
                command=command,
                started_at=started_at,
                start_time=start_time,
                status="timeout" if returncode is None else "failed",
                message=execution_error,
                warnings=[fallback_warning],
            )
        stderr_lines = [fallback_warning, *_clean_stderr(fallback_stderr)]

    if returncode != 0 and not stdout.strip():
        message = _privilege_error_message(stderr_lines)
        return _failed_response(
            request=request,
            classified=classified,
            command=command,
            started_at=started_at,
            start_time=start_time,
            status="failed",
            message=message or (stderr_lines[0] if stderr_lines else "Nmap scan failed before returning XML output."),
            warnings=stderr_lines,
        )

    try:
        ports, os_matches = parse_nmap_xml(stdout)
    except ValueError as exc:
        return _failed_response(
            request=request,
            classified=classified,
            command=command,
            started_at=started_at,
            start_time=start_time,
            status="failed",
            message=f"Nmap returned invalid XML output: {exc}.",
            warnings=stderr_lines,
        )

    warnings = stderr_lines
    if not ports:
        warnings.append("No open ports were returned by this Nmap preset.")
    if request.preset in {"os_detection", "stealth_syn"}:
        if fallback_warning:
            pass
        elif settings.nmap_use_sudo:
            warnings.append("Privileged Nmap mode was enabled for this preset.")
        else:
            warnings.append("This preset may require elevated backend privileges on some systems.")

    return NmapScanResponse(
        status="completed" if returncode == 0 else "failed",
        target=request.target,
        normalized_target=classified.normalized_value,
        input_type=classified.input_type,  # type: ignore[arg-type]
        preset=request.preset,
        command=_display_command(command),
        started_at=started_at,
        finished_at=datetime.now(timezone.utc),
        duration_seconds=round(time.monotonic() - start_time, 2),
        ports=ports,
        os_matches=os_matches,
        warnings=warnings,
        summary=_summary(request.preset, ports, os_matches),
        error_message=None if returncode == 0 else (stderr_lines[0] if stderr_lines else "Nmap completed with warnings."),
    )


def build_nmap_command(
    *,
    nmap_path: str,
    preset: str,
    target: str,
    timeout_seconds: int,
    use_sudo: bool = False,
    sudo_path: str = "/usr/bin/sudo",
    args: list[str] | None = None,
) -> list[str]:
    preset_args = args or PRESET_ARGS[preset]
    command = [
        nmap_path,
        *preset_args,
        "--max-retries",
        "2",
        "--host-timeout",
        f"{timeout_seconds}s",
        "-oX",
        "-",
        target,
    ]
    if use_sudo:
        return [sudo_path, "-n", *command]
    return command


def should_use_sudo(preset: str, *, settings: Settings) -> bool:
    return settings.nmap_use_sudo and preset in PRIVILEGED_PRESETS


async def _run_command(command: list[str], *, timeout_seconds: int) -> tuple[bytes, bytes, int | None, str | None]:
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        return b"", b"", 1, f"Nmap could not be started: {exc}"

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout_seconds + 5,
        )
    except asyncio.TimeoutError:
        process.kill()
        await process.communicate()
        return b"", b"", None, f"Nmap scan exceeded the {timeout_seconds} second timeout."
    return stdout, stderr, process.returncode, None


def parse_nmap_xml(xml_output: bytes) -> tuple[list[NmapPortResult], list[NmapOsMatch]]:
    parser = _NmapXmlParser()
    parser.feed(xml_output.decode("utf-8", errors="replace"))
    parser.close()
    if not parser.saw_nmaprun:
        raise ValueError("missing nmaprun root")
    parser.ports.sort(key=lambda item: (item.protocol, item.port))
    parser.os_matches.sort(key=lambda item: item.accuracy or 0, reverse=True)
    return parser.ports, parser.os_matches[:5]


class _NmapXmlParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.saw_nmaprun = False
        self.ports: list[NmapPortResult] = []
        self.os_matches: list[NmapOsMatch] = []
        self._current_port: dict | None = None
        self._current_cpe = ""
        self._in_cpe = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {key: value or "" for key, value in attrs}
        if tag == "nmaprun":
            self.saw_nmaprun = True
        elif tag == "port":
            self._current_port = {
                "port": int(attr.get("portid") or 0),
                "protocol": attr.get("protocol") or "tcp",
                "state": "unknown",
                "reason": None,
                "service_name": None,
                "product": None,
                "version": None,
                "extra_info": None,
                "cpes": [],
            }
        elif tag == "state" and self._current_port is not None:
            self._current_port["state"] = attr.get("state") or "unknown"
            self._current_port["reason"] = attr.get("reason") or None
        elif tag == "service" and self._current_port is not None:
            self._current_port["service_name"] = attr.get("name") or None
            self._current_port["product"] = attr.get("product") or None
            self._current_port["version"] = attr.get("version") or None
            self._current_port["extra_info"] = attr.get("extrainfo") or None
        elif tag == "cpe" and self._current_port is not None:
            self._current_cpe = ""
            self._in_cpe = True
        elif tag == "osmatch":
            accuracy = attr.get("accuracy")
            self.os_matches.append(
                NmapOsMatch(
                    name=attr.get("name") or "Unknown OS",
                    accuracy=int(accuracy) if accuracy and accuracy.isdigit() else None,
                )
            )

    def handle_data(self, data: str) -> None:
        if self._in_cpe:
            self._current_cpe += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "cpe" and self._current_port is not None:
            cpe = self._current_cpe.strip()
            if cpe:
                self._current_port["cpes"].append(cpe)
            self._current_cpe = ""
            self._in_cpe = False
        elif tag == "port" and self._current_port is not None:
            if self._current_port["state"] in {"open", "open|filtered"}:
                self.ports.append(NmapPortResult(**self._current_port))
            self._current_port = None


def _failed_response(
    *,
    request: NmapScanRequest,
    classified: ClassifiedIOC,
    command: list[str],
    started_at: datetime,
    start_time: float,
    status: str,
    message: str,
    warnings: list[str] | None = None,
) -> NmapScanResponse:
    return NmapScanResponse(
        status=status,  # type: ignore[arg-type]
        target=request.target,
        normalized_target=classified.normalized_value,
        input_type=classified.input_type,  # type: ignore[arg-type]
        preset=request.preset,
        command=_display_command(command),
        started_at=started_at,
        finished_at=datetime.now(timezone.utc),
        duration_seconds=round(time.monotonic() - start_time, 2),
        ports=[],
        os_matches=[],
        warnings=warnings or [],
        summary="Nmap scan did not complete.",
        error_message=message,
    )


def _clean_stderr(stderr: bytes) -> list[str]:
    return [
        line.strip()
        for line in stderr.decode("utf-8", errors="replace").splitlines()
        if line.strip()
    ][:8]


def _privilege_error_message(stderr_lines: list[str]) -> str | None:
    stderr_text = " ".join(stderr_lines).lower()
    if "a password is required" in stderr_text or "no tty present" in stderr_text or "a terminal is required" in stderr_text:
        return (
            "Passwordless sudo for Nmap is not configured. Run the privileged Nmap setup step "
            "or set NMAP_USE_SUDO=false for this backend."
        )
    if "requires root privileges" in stderr_text or "you requested a scan type which requires root" in stderr_text:
        return "This Nmap preset requires root privileges on this system."
    return None


def _fallback_warning(preset: str, privilege_message: str) -> str:
    if preset == "os_detection":
        fallback = "ran service/version fingerprinting instead of OS fingerprinting"
    elif preset == "stealth_syn":
        fallback = "ran a TCP connect scan instead of SYN scan"
    else:
        fallback = "ran a non-privileged fallback"
    if "passwordless sudo" in privilege_message.lower():
        privilege_message = "Privileged Nmap is not available in this environment."
    return f"{privilege_message} The backend {fallback} so the scan can still complete."


def _display_command(command: list[str]) -> list[str]:
    if not command:
        return command
    if command[0].endswith("/sudo") or command[0] == "sudo":
        nmap_index = next((index for index, part in enumerate(command) if part.endswith("/nmap") or part == "nmap"), None)
        if nmap_index is None:
            return ["sudo", *command[1:]]
        return ["sudo", "-n", "nmap", *command[nmap_index + 1 :]]
    return ["nmap", *command[1:]]


def _summary(preset: str, ports: list[NmapPortResult], os_matches: list[NmapOsMatch]) -> str:
    if ports:
        service_count = sum(1 for port in ports if port.service_name)
        summary = f"Nmap found {len(ports)} open port{'s' if len(ports) != 1 else ''}"
        if service_count:
            summary += f" and identified {service_count} service{'s' if service_count != 1 else ''}"
        summary += "."
    else:
        summary = "Nmap did not return open ports for this target and preset."

    if preset == "os_detection" and os_matches:
        summary += f" Top OS guess: {os_matches[0].name}."
    return summary
