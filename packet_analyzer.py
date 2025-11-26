#!/usr/bin/env python3
"""Ferramenta simples para análise de capturas PCAP."""

import argparse
import json
from pathlib import Path

from pcap_analyzer import PcapParser, render_text_report, summarize_packets


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analise rápida de pacotes de rede a partir de um arquivo PCAP")
    parser.add_argument("pcap", help="Caminho para o arquivo .pcap a ser analisado")
    parser.add_argument("--top", type=int, default=5, help="Quantidade de itens em seções de Top N")
    parser.add_argument("--json", dest="json_path", help="Salva o resumo também em formato JSON")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        raise SystemExit(f"Arquivo não encontrado: {pcap_path}")

    parser = PcapParser(str(pcap_path))
    summary = summarize_packets(parser)

    print(render_text_report(summary, top_n=args.top))

    if args.json_path:
        output_path = Path(args.json_path)
        output_path.write_text(
            json.dumps(
                {
                    "total_packets": summary.total_packets,
                    "total_bytes": summary.total_bytes,
                    "protocols": dict(summary.protocols),
                    "sources": dict(summary.source_ips),
                    "destinations": dict(summary.destination_ips),
                    "ports": {proto: dict(counter) for proto, counter in summary.ports.items()},
                    "conversations": [
                        {"src": src, "dst": dst, "protocol": proto, "count": count}
                        for (src, dst, proto), count in summary.conversations.items()
                    ],
                    "first_timestamp": summary.first_timestamp,
                    "last_timestamp": summary.last_timestamp,
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        print(f"Resumo salvo em {output_path.resolve()}")


if __name__ == "__main__":
    main()
