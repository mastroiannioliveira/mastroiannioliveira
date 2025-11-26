import ipaddress
import struct
from dataclasses import dataclass
from typing import Generator, Optional


@dataclass
class ParsedPacket:
    """Normalized representation of a parsed packet."""

    timestamp: float
    captured_len: int
    original_len: int
    src_mac: Optional[str]
    dst_mac: Optional[str]
    ether_type: Optional[int]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    ip_protocol: Optional[int]
    src_port: Optional[int]
    dst_port: Optional[int]
    payload_length: Optional[int]


class PcapParser:
    """Simple PCAP parser that only uses the Python standard library."""

    _GLOBAL_HEADER_FMT = {
        0xA1B2C3D4: ">IHHIIII",  # big endian
        0xD4C3B2A1: "<IHHIIII",  # little endian
        0xA1B23C4D: ">IHHIIII",  # nanosecond (big endian)
        0x4D3CB2A1: "<IHHIIII",  # nanosecond (little endian)
    }

    def __init__(self, path: str):
        self.path = path
        self.endian = "<"

    def _detect_header(self, header: bytes) -> struct.Struct:
        if len(header) != 24:
            raise ValueError("PCAP global header is incomplete")

        magic = struct.unpack("<I", header[:4])[0]
        fmt = self._GLOBAL_HEADER_FMT.get(magic)
        if fmt:
            self.endian = fmt[0]
            return struct.Struct(fmt)

        magic = struct.unpack(">I", header[:4])[0]
        fmt = self._GLOBAL_HEADER_FMT.get(magic)
        if fmt:
            self.endian = fmt[0]
            return struct.Struct(fmt)

        raise ValueError("Unrecognized PCAP magic number")

    def __iter__(self) -> Generator[ParsedPacket, None, None]:
        with open(self.path, "rb") as handle:
            global_header = handle.read(24)
            header_struct = self._detect_header(global_header)
            _magic, _version_major, _version_minor, _thiszone, _sigfigs, _snaplen, _network = header_struct.unpack(
                global_header
            )

            packet_header = handle.read(16)
            while packet_header:
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{self.endian}IIII", packet_header)
                data = handle.read(incl_len)
                if len(data) != incl_len:
                    break

                packet = self._parse_packet(ts_sec, ts_usec, incl_len, orig_len, data)
                if packet:
                    yield packet

                packet_header = handle.read(16)

    # noqa: C901 - parsing helper
    def _parse_packet(
        self, ts_sec: int, ts_usec: int, incl_len: int, orig_len: int, data: bytes
    ) -> Optional[ParsedPacket]:
        timestamp = ts_sec + ts_usec / 1_000_000
        if len(data) < 14:
            return None

        dst_mac = ":".join(f"{b:02x}" for b in data[0:6])
        src_mac = ":".join(f"{b:02x}" for b in data[6:12])
        ether_type = struct.unpack("!H", data[12:14])[0]

        src_ip = dst_ip = None
        ip_protocol = None
        src_port = dst_port = None
        payload_length = None

        if ether_type == 0x0800 and len(data) >= 14 + 20:  # IPv4
            ip_header_start = 14
            ver_ihl = data[ip_header_start]
            version = ver_ihl >> 4
            ihl = (ver_ihl & 0x0F) * 4
            if version == 4 and len(data) >= ip_header_start + ihl:
                total_length = struct.unpack("!H", data[ip_header_start + 2 : ip_header_start + 4])[0]
                ip_protocol = data[ip_header_start + 9]
                src_ip = str(ipaddress.IPv4Address(data[ip_header_start + 12 : ip_header_start + 16]))
                dst_ip = str(ipaddress.IPv4Address(data[ip_header_start + 16 : ip_header_start + 20]))

                transport_start = ip_header_start + ihl
                transport_len = total_length - ihl if total_length >= ihl else 0

                if ip_protocol in (6, 17) and len(data) >= transport_start + 4:
                    src_port, dst_port = struct.unpack("!HH", data[transport_start : transport_start + 4])

                if ip_protocol == 6:  # TCP
                    if len(data) >= transport_start + 14:
                        data_offset = (data[transport_start + 12] >> 4) * 4
                        payload_length = max(transport_len - data_offset, 0)
                elif ip_protocol == 17:  # UDP
                    if len(data) >= transport_start + 6:
                        udp_length = struct.unpack("!H", data[transport_start + 4 : transport_start + 6])[0]
                        payload_length = max(udp_length - 8, 0)
                else:
                    payload_length = max(transport_len, 0)

        return ParsedPacket(
            timestamp=timestamp,
            captured_len=incl_len,
            original_len=orig_len,
            src_mac=src_mac,
            dst_mac=dst_mac,
            ether_type=ether_type,
            src_ip=src_ip,
            dst_ip=dst_ip,
            ip_protocol=ip_protocol,
            src_port=src_port,
            dst_port=dst_port,
            payload_length=payload_length,
        )
