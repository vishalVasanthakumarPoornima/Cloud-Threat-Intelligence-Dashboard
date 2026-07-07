import asyncio
import socket
import time
from datetime import datetime, timezone
from typing import Any

from app.schemas.active_scan import PortScanPortResult, PortScanRequest, PortScanResponse
from app.services.classifier import ClassifiedIOC

TCP_SCAN_CONCURRENCY = 160
SCAPY_SCAN_CONCURRENCY = 64
TCP_CONNECT_TIMEOUT_SECONDS = 1.15
TCP_BANNER_TIMEOUT_SECONDS = 0.65
SCAPY_SYN_TIMEOUT_SECONDS = 0.9

COMMON_TCP_PORTS = (
    80,
    443,
    22,
    21,
    25,
    3389,
    110,
    445,
    139,
    143,
    53,
    135,
    3306,
    8080,
    1723,
    111,
    995,
    993,
    5900,
    1025,
    587,
    8888,
    199,
    1720,
    465,
    548,
    113,
    81,
    6001,
    10000,
    514,
    5060,
    179,
    1026,
    2000,
    8443,
    8000,
    32768,
    554,
    26,
    1433,
    49152,
    2001,
    515,
    8008,
    49154,
    1027,
    5666,
    646,
    5000,
    5631,
    631,
    49153,
    8081,
    2049,
    88,
    79,
    5800,
    106,
    2121,
    1110,
    49155,
    6000,
    513,
    990,
    5357,
    427,
    49156,
    543,
    544,
    5101,
    144,
    7,
    389,
    8009,
    3128,
    444,
    9999,
    5009,
    7070,
    5190,
    3000,
    5432,
    1900,
    3986,
    13,
    1029,
    9,
    6646,
    49157,
    1028,
    873,
    1755,
    2717,
    4899,
    9100,
    119,
    37,
    1000,
    3001,
    5001,
)
HTTP_LIKE_PORTS = {80, 8000, 8008, 8080, 8081, 8888}


async def run_port_scan(*, request: PortScanRequest, classified: ClassifiedIOC) -> PortScanResponse:
    started_at = datetime.now(timezone.utc)
    start_time = time.monotonic()

    if request.preset == "stealth_syn":
        scapy_response = await _run_scapy_syn_scan(
            request=request,
            classified=classified,
            started_at=started_at,
            start_time=start_time,
        )
        if scapy_response is not None:
            return scapy_response

    return await _run_tcp_connect_scan(
        request=request,
        classified=classified,
        started_at=started_at,
        start_time=start_time,
        extra_warnings=_preset_warnings(request.preset),
    )


async def _run_tcp_connect_scan(
    *,
    request: PortScanRequest,
    classified: ClassifiedIOC,
    started_at: datetime,
    start_time: float,
    extra_warnings: list[str] | None = None,
) -> PortScanResponse:
    ports_to_scan = scan_ports_for_preset(request.preset)
    semaphore = asyncio.Semaphore(TCP_SCAN_CONCURRENCY)
    capture_banner = request.preset == "service_detection"
    tasks = [
        asyncio.create_task(
            _probe_tcp_port(
                target=classified.normalized_value,
                port=port,
                semaphore=semaphore,
                capture_banner=capture_banner,
            )
        )
        for port in ports_to_scan
    ]
    done, pending = await asyncio.wait(tasks, timeout=request.timeout_seconds)

    for task in pending:
        task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)

    ports = _successful_ports(done)
    warnings = [
        "Python TCP connect scan checks port reachability directly from the backend.",
        *(extra_warnings or []),
    ]
    if pending:
        warnings.append(
            f"Scan reached the {request.timeout_seconds} second timeout after checking "
            f"{len(done)} of {len(tasks)} ports."
        )
    if not ports:
        warnings.append("No open TCP ports were found for this preset.")

    return _response(
        request=request,
        classified=classified,
        started_at=started_at,
        start_time=start_time,
        command=["python-port-scan", "--mode", "tcp-connect", "--ports", str(len(ports_to_scan)), classified.normalized_value],
        ports=ports,
        warnings=warnings,
        summary=_summary(request.preset, ports, mode="TCP connect"),
    )


async def _probe_tcp_port(
    *,
    target: str,
    port: int,
    semaphore: asyncio.Semaphore,
    capture_banner: bool,
) -> PortScanPortResult | None:
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=TCP_CONNECT_TIMEOUT_SECONDS,
            )
        except (OSError, asyncio.TimeoutError):
            return None

        banner = await _read_banner(reader, writer, target=target, port=port) if capture_banner else None
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

    return PortScanPortResult(
        port=port,
        protocol="tcp",
        state="open",
        reason="tcp-connect",
        service_name=_service_name(port),
        extra_info=banner,
        cpes=[],
    )


async def _read_banner(async_reader: asyncio.StreamReader, writer: asyncio.StreamWriter, *, target: str, port: int) -> str | None:
    if port in HTTP_LIKE_PORTS:
        try:
            writer.write(f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode("ascii", errors="ignore"))
            await writer.drain()
        except OSError:
            return None

    try:
        data = await asyncio.wait_for(async_reader.read(180), timeout=TCP_BANNER_TIMEOUT_SECONDS)
    except (OSError, asyncio.TimeoutError):
        return None

    first_line = data.decode("utf-8", errors="replace").strip().splitlines()
    if not first_line:
        return None
    return first_line[0][:140]


async def _run_scapy_syn_scan(
    *,
    request: PortScanRequest,
    classified: ClassifiedIOC,
    started_at: datetime,
    start_time: float,
) -> PortScanResponse | None:
    scapy_tools, load_error = _load_scapy_tools()
    if load_error:
        return None

    try:
        target_ip = socket.gethostbyname(classified.normalized_value)
    except OSError:
        return None

    ports_to_scan = scan_ports_for_preset(request.preset)
    semaphore = asyncio.Semaphore(SCAPY_SCAN_CONCURRENCY)
    tasks = [
        asyncio.create_task(
            _probe_scapy_syn_port(
                target_ip=target_ip,
                port=port,
                semaphore=semaphore,
                scapy_tools=scapy_tools,
            )
        )
        for port in ports_to_scan
    ]
    done, pending = await asyncio.wait(tasks, timeout=request.timeout_seconds)

    for task in pending:
        task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)

    ports: list[PortScanPortResult] = []
    fatal_errors: list[str] = []
    for task in done:
        if task.cancelled() or task.exception() is not None:
            continue
        port, fatal_error = task.result()
        if port:
            ports.append(port)
        if fatal_error:
            fatal_errors.append(fatal_error)

    if fatal_errors and not ports:
        return None

    ports.sort(key=lambda item: item.port)
    warnings = [
        "Scapy SYN probe was used for this preset. It requires raw socket support and reports SYN-ACK responses as open ports.",
    ]
    if pending:
        warnings.append(
            f"Scapy scan reached the {request.timeout_seconds} second timeout after checking "
            f"{len(done)} of {len(tasks)} ports."
        )
    if not ports:
        warnings.append("No open TCP ports returned SYN-ACK responses for this preset.")

    return _response(
        request=request,
        classified=classified,
        started_at=started_at,
        start_time=start_time,
        command=["python-port-scan", "--mode", "scapy-syn", "--ports", str(len(ports_to_scan)), classified.normalized_value],
        ports=ports,
        warnings=warnings,
        summary=_summary(request.preset, ports, mode="Scapy SYN"),
    )


async def _probe_scapy_syn_port(
    *,
    target_ip: str,
    port: int,
    semaphore: asyncio.Semaphore,
    scapy_tools: dict[str, Any],
) -> tuple[PortScanPortResult | None, str | None]:
    async with semaphore:
        return await asyncio.to_thread(_probe_scapy_syn_port_sync, target_ip, port, scapy_tools)


def _probe_scapy_syn_port_sync(
    target_ip: str,
    port: int,
    scapy_tools: dict[str, Any],
) -> tuple[PortScanPortResult | None, str | None]:
    ip_cls = scapy_tools["IP"]
    tcp_cls = scapy_tools["TCP"]
    sr1 = scapy_tools["sr1"]
    send = scapy_tools["send"]

    try:
        packet = ip_cls(dst=target_ip) / tcp_cls(dport=port, flags="S")
        response = sr1(packet, timeout=SCAPY_SYN_TIMEOUT_SECONDS, verbose=False)
    except (PermissionError, OSError) as exc:
        return None, f"Scapy SYN probes need raw socket permission: {exc}"

    if response is None or not response.haslayer(tcp_cls):
        return None, None

    tcp_layer = response.getlayer(tcp_cls)
    flags = int(tcp_layer.flags)
    if flags & 0x12 != 0x12:
        return None, None

    try:
        reset = ip_cls(dst=target_ip) / tcp_cls(
            sport=tcp_layer.dport,
            dport=tcp_layer.sport,
            flags="R",
            seq=tcp_layer.ack,
        )
        send(reset, verbose=False)
    except (PermissionError, OSError):
        pass

    return (
        PortScanPortResult(
            port=port,
            protocol="tcp",
            state="open",
            reason="syn-ack",
            service_name=_service_name(port),
            cpes=[],
        ),
        None,
    )


def scan_ports_for_preset(preset: str) -> tuple[int, ...]:
    count = 100 if preset == "quick_ports" else 1000
    ordered_ports = list(dict.fromkeys((*COMMON_TCP_PORTS, *range(1, 1001))))
    return tuple(ordered_ports[:count])


def _successful_ports(done: set[asyncio.Task[PortScanPortResult | None]]) -> list[PortScanPortResult]:
    ports = []
    for task in done:
        if task.cancelled() or task.exception() is not None:
            continue
        result = task.result()
        if result:
            ports.append(result)
    ports.sort(key=lambda item: item.port)
    return ports


def _load_scapy_tools() -> tuple[dict[str, Any], str | None]:
    try:
        from scapy.all import IP, TCP, send, sr1
    except ImportError as exc:
        return {}, f"Scapy is not installed: {exc}"
    return {"IP": IP, "TCP": TCP, "send": send, "sr1": sr1}, None


def _service_name(port: int) -> str | None:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return None


def _preset_warnings(preset: str) -> list[str]:
    if preset == "service_detection":
        return [
            "Service names are inferred from well-known port numbers; lightweight banner reads are attempted when safe.",
        ]
    if preset == "os_detection":
        return [
            "Python port scanning does not perform OS fingerprinting, so this preset checks a broader TCP port set instead.",
        ]
    if preset == "stealth_syn":
        return [
            "Scapy SYN probing was not available or did not return results, so the scanner fell back to TCP connect checks.",
        ]
    return []


def _response(
    *,
    request: PortScanRequest,
    classified: ClassifiedIOC,
    started_at: datetime,
    start_time: float,
    command: list[str],
    ports: list[PortScanPortResult],
    warnings: list[str],
    summary: str,
) -> PortScanResponse:
    return PortScanResponse(
        status="completed",
        target=request.target,
        normalized_target=classified.normalized_value,
        input_type=classified.input_type,  # type: ignore[arg-type]
        preset=request.preset,
        command=command,
        started_at=started_at,
        finished_at=datetime.now(timezone.utc),
        duration_seconds=round(time.monotonic() - start_time, 2),
        ports=ports,
        os_matches=[],
        warnings=warnings,
        summary=summary,
        error_message=None,
    )


def _summary(preset: str, ports: list[PortScanPortResult], *, mode: str) -> str:
    if not ports:
        return f"{mode} scan did not find open ports for this target and preset."

    service_count = sum(1 for port in ports if port.service_name)
    summary = f"{mode} scan found {len(ports)} open port{'s' if len(ports) != 1 else ''}"
    if preset == "service_detection" and service_count:
        summary += f" and inferred {service_count} service name{'s' if service_count != 1 else ''}"
    summary += "."
    return summary
