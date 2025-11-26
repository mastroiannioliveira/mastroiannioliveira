import struct
import tempfile
import unittest
from pathlib import Path

from pcap_analyzer import PcapParser, protocol_name, summarize_packets


def _mac_bytes(addr: str) -> bytes:
    return bytes(int(part, 16) for part in addr.split(":"))


def _ipv4_bytes(addr: str) -> bytes:
    return bytes(int(part) for part in addr.split("."))


def _build_ipv4_header(total_length: int, proto: int, src: str, dst: str, identification: int = 0) -> bytes:
    version = 4
    ihl = 5
    ver_ihl = (version << 4) + ihl
    tos = 0
    flags_frag = 0
    ttl = 64
    checksum = 0
    return struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl,
        tos,
        total_length,
        identification,
        flags_frag,
        ttl,
        proto,
        checksum,
        _ipv4_bytes(src),
        _ipv4_bytes(dst),
    )


def _build_udp_segment(src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    checksum = 0
    return struct.pack("!HHHH", src_port, dst_port, length, checksum) + payload


def _build_tcp_segment(src_port: int, dst_port: int, payload: bytes, seq: int = 1) -> bytes:
    data_offset = 5  # 20 bytes header
    offset_reserved_flags = (data_offset << 12) | 0x0002  # SYN
    window = 1024
    checksum = 0
    urg_pointer = 0
    header = struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq,
        0,
        offset_reserved_flags,
        window,
        checksum,
        urg_pointer,
    )
    return header + payload


def _write_sample_pcap(path: Path) -> None:
    magic = 0xD4C3B2A1
    global_header = struct.pack("<IHHIIII", magic, 2, 4, 0, 0, 65535, 1)

    # Packet 1: UDP DNS-like query
    udp_payload = b"hello"
    udp_segment = _build_udp_segment(1234, 53, udp_payload)
    ip_total_length = 20 + len(udp_segment)
    ip_header = _build_ipv4_header(ip_total_length, 17, "192.168.0.10", "8.8.8.8")
    eth_header = _mac_bytes("ff:ff:ff:ff:ff:ff") + _mac_bytes("00:11:22:33:44:55") + struct.pack("!H", 0x0800)
    udp_packet = eth_header + ip_header + udp_segment

    # Packet 2: TCP SYN
    tcp_payload = b"hi"
    tcp_segment = _build_tcp_segment(443, 51514, tcp_payload)
    tcp_ip_total_length = 20 + len(tcp_segment)
    tcp_ip_header = _build_ipv4_header(tcp_ip_total_length, 6, "10.0.0.2", "93.184.216.34", identification=1)
    tcp_eth_header = _mac_bytes("00:11:22:33:44:55") + _mac_bytes("66:55:44:33:22:11") + struct.pack("!H", 0x0800)
    tcp_packet = tcp_eth_header + tcp_ip_header + tcp_segment

    with path.open("wb") as handle:
        handle.write(global_header)

        for idx, packet in enumerate((udp_packet, tcp_packet), start=1):
            ts_sec = 1680000000 + idx
            ts_usec = 500 * idx
            incl_len = len(packet)
            orig_len = len(packet)
            handle.write(struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len))
            handle.write(packet)


class PcapAnalyzerTests(unittest.TestCase):
    def test_parser_extracts_core_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "sample.pcap"
            _write_sample_pcap(path)

            packets = list(PcapParser(str(path)))
            self.assertEqual(len(packets), 2)

            udp, tcp = packets

            self.assertEqual(udp.src_ip, "192.168.0.10")
            self.assertEqual(udp.dst_ip, "8.8.8.8")
            self.assertEqual(udp.ip_protocol, 17)
            self.assertEqual(udp.src_port, 1234)
            self.assertEqual(udp.dst_port, 53)
            self.assertEqual(udp.payload_length, len(b"hello"))

            self.assertEqual(tcp.src_ip, "10.0.0.2")
            self.assertEqual(tcp.dst_ip, "93.184.216.34")
            self.assertEqual(tcp.ip_protocol, 6)
            self.assertEqual(tcp.src_port, 443)
            self.assertEqual(tcp.dst_port, 51514)
            # TCP data offset 5 (20 bytes) -> payload len 2
            self.assertEqual(tcp.payload_length, len(b"hi"))

    def test_summary_counts_packets_and_protocols(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "sample.pcap"
            _write_sample_pcap(path)

            summary = summarize_packets(PcapParser(str(path)))

            self.assertEqual(summary.total_packets, 2)
            self.assertGreater(summary.total_bytes, 0)
            self.assertEqual(summary.protocols["UDP"], 1)
            self.assertEqual(summary.protocols["TCP"], 1)
            self.assertEqual(summary.source_ips["192.168.0.10"], 1)
            self.assertEqual(summary.destination_ips["8.8.8.8"], 1)
            self.assertEqual(summary.ports["UDP"][53], 1)
            self.assertEqual(summary.ports["TCP"][51514], 1)
            self.assertEqual(summary.conversations[("192.168.0.10", "8.8.8.8", "UDP")], 1)
            self.assertEqual(summary.conversations[("10.0.0.2", "93.184.216.34", "TCP")], 1)

    def test_protocol_name_fallback(self):
        self.assertEqual(protocol_name(1), "ICMP")
        self.assertEqual(protocol_name(250), "PROTO-250")


if __name__ == "__main__":
    unittest.main()
