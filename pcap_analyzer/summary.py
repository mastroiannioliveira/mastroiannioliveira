from collections import Counter
from dataclasses import dataclass
from typing import Dict, Iterable, List

from .parser import ParsedPacket


@dataclass
class Summary:
    total_packets: int
    total_bytes: int
    protocols: Counter
    source_ips: Counter
    destination_ips: Counter
    ports: Dict[str, Counter]
    conversations: Counter
    first_timestamp: float
    last_timestamp: float


def protocol_name(protocol: int) -> str:
    names = {1: "ICMP", 6: "TCP", 17: "UDP"}
    return names.get(protocol, f"PROTO-{protocol}")


def summarize_packets(packets: Iterable[ParsedPacket]) -> Summary:
    total_packets = 0
    total_bytes = 0
    protocols: Counter = Counter()
    source_ips: Counter = Counter()
    destination_ips: Counter = Counter()
    ports: Dict[str, Counter] = {"TCP": Counter(), "UDP": Counter()}
    conversations: Counter = Counter()

    first_timestamp = float("inf")
    last_timestamp = 0.0

    for pkt in packets:
        total_packets += 1
        total_bytes += pkt.original_len

        first_timestamp = min(first_timestamp, pkt.timestamp)
        last_timestamp = max(last_timestamp, pkt.timestamp)

        proto_label = protocol_name(pkt.ip_protocol) if pkt.ip_protocol is not None else "NON-IP"
        protocols[proto_label] += 1

        if pkt.src_ip:
            source_ips[pkt.src_ip] += 1
        if pkt.dst_ip:
            destination_ips[pkt.dst_ip] += 1

        if proto_label in ("TCP", "UDP") and pkt.src_port and pkt.dst_port:
            ports[proto_label][pkt.dst_port] += 1
            conversation_key = (pkt.src_ip or "unknown", pkt.dst_ip or "unknown", proto_label)
            conversations[conversation_key] += 1

    if first_timestamp == float("inf"):
        first_timestamp = 0.0

    return Summary(
        total_packets=total_packets,
        total_bytes=total_bytes,
        protocols=protocols,
        source_ips=source_ips,
        destination_ips=destination_ips,
        ports=ports,
        conversations=conversations,
        first_timestamp=first_timestamp,
        last_timestamp=last_timestamp,
    )


def render_text_report(summary: Summary, top_n: int = 5) -> str:
    lines: List[str] = []
    lines.append("=== Visão Geral ===")
    lines.append(f"Pacotes totais: {summary.total_packets}")
    lines.append(f"Bytes totais: {summary.total_bytes}")
    if summary.total_packets:
        duration = summary.last_timestamp - summary.first_timestamp
        lines.append(f"Duração capturada: {duration:.6f}s")

    lines.append("")
    lines.append("=== Protocolos ===")
    for proto, count in summary.protocols.most_common():
        percent = (count / summary.total_packets * 100) if summary.total_packets else 0
        lines.append(f"{proto}: {count} ({percent:.2f}%)")

    lines.append("")
    lines.append(f"=== Top {top_n} IPs de origem ===")
    for ip, count in summary.source_ips.most_common(top_n):
        lines.append(f"{ip}: {count}")

    lines.append("")
    lines.append(f"=== Top {top_n} IPs de destino ===")
    for ip, count in summary.destination_ips.most_common(top_n):
        lines.append(f"{ip}: {count}")

    lines.append("")
    lines.append(f"=== Top {top_n} portas TCP ===")
    for port, count in summary.ports["TCP"].most_common(top_n):
        lines.append(f"TCP/{port}: {count}")

    lines.append("")
    lines.append(f"=== Top {top_n} portas UDP ===")
    for port, count in summary.ports["UDP"].most_common(top_n):
        lines.append(f"UDP/{port}: {count}")

    lines.append("")
    lines.append(f"=== Top {top_n} conversas ===")
    for (src, dst, proto), count in summary.conversations.most_common(top_n):
        lines.append(f"{src} -> {dst} ({proto}): {count}")

    return "\n".join(lines)
