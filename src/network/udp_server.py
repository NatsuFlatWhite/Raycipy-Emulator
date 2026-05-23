from __future__ import annotations

import asyncio
import logging
import os
import struct
import time
from dataclasses import dataclass
from typing import Optional

from src.packets.packet_registry import PACKET_IDS, Packet, packet_name as get_packet_name
from src.packets.protocol import build_object_payload


logger = logging.getLogger("UdpServer")

RAYCITY_UDP_CHECKSUM_XOR = 0x4F3816C3
ALT_UDP_CHECKSUM_XOR = 0xC9F84A90
_UDP_SEED_STEP = 0x01473F19

_LAST_ENTER_KEY = 8
_LAST_SELECTED_CHAR_ID = 0
_LAST_UPDATE_REASON = "default"
_UDP_HANDSHAKE_GENERATION = 0


def update_udp_enter_key(enter_key: int, selected_char_id: int = 0, reason: str = "") -> None:
    global _LAST_ENTER_KEY, _LAST_SELECTED_CHAR_ID, _LAST_UPDATE_REASON, _UDP_HANDSHAKE_GENERATION
    if enter_key:
        _LAST_ENTER_KEY = enter_key & 0xFFFFFFFF
    if selected_char_id:
        _LAST_SELECTED_CHAR_ID = selected_char_id & 0xFFFFFFFF
    _LAST_UPDATE_REASON = reason or "runtime"
    _UDP_HANDSHAKE_GENERATION = (_UDP_HANDSHAKE_GENERATION + 1) & 0xFFFFFFFF
    logger.info(
        "UDP enter key armed enter_key=%d selected_char_id=%d generation=%d reason=%s",
        _LAST_ENTER_KEY,
        _LAST_SELECTED_CHAR_ID,
        _UDP_HANDSHAKE_GENERATION,
        _LAST_UPDATE_REASON,
    )


def u32(value: int) -> int:
    return value & 0xFFFFFFFF


def udp_checksum(data: bytes) -> int:
    checksum = 0
    block_end = (len(data) // 16) * 16
    for offset in range(0, block_end, 16):
        a, b, c, d = struct.unpack_from("<IIII", data, offset)
        checksum = u32(checksum ^ a ^ b ^ c ^ d)
    for index, value in enumerate(data[block_end:]):
        checksum = u32(checksum ^ ((value & 0xFF) << index))
    return checksum


def udp_crypt(data: bytes, seed: int) -> tuple[bytes, int]:
    seed = u32(seed)
    keys = (
        u32(seed ^ 0x14B307C8),
        u32(seed ^ 0x8CBF12AC),
        u32(seed ^ 0x240397C1),
        u32(seed ^ 0xF3BD29C0),
    )
    key_bytes = struct.pack("<IIII", *keys)
    out = bytearray(len(data))
    checksum = 0
    block_end = (len(data) // 16) * 16
    for offset in range(0, block_end, 16):
        a, b, c, d = struct.unpack_from("<IIII", data, offset)
        checksum = u32(checksum ^ a ^ b ^ c ^ d)
        struct.pack_into(
            "<IIII",
            out,
            offset,
            u32(a ^ keys[0]),
            u32(b ^ keys[1]),
            u32(c ^ keys[2]),
            u32(d ^ keys[3]),
        )
    for index, value in enumerate(data[block_end:]):
        checksum = u32(checksum ^ ((value & 0xFF) << index))
        out[block_end + index] = value ^ key_bytes[index]
    return bytes(out), checksum


def build_udp_frame(
    payload: bytes,
    seed: int,
    checksum_xor: int = RAYCITY_UDP_CHECKSUM_XOR,
) -> bytes:
    seed = u32(seed)
    encrypted, _ = udp_crypt(payload, seed)
    checksum = u32(udp_checksum(payload) ^ seed ^ checksum_xor)
    return struct.pack("<I", seed) + encrypted + struct.pack("<I", checksum)


def decrypt_udp_frame(data: bytes) -> tuple[Optional[int], bytes, dict[str, int | bool]]:
    if len(data) < 8:
        return None, b"", {"valid": False}
    seed = struct.unpack_from("<I", data, 0)[0]
    encrypted = data[4:-4]
    received_checksum = struct.unpack_from("<I", data, len(data) - 4)[0]
    plain, encrypted_checksum = udp_crypt(encrypted, seed)
    plain_checksum = udp_checksum(plain)
    expected_plain_client = u32(plain_checksum ^ seed ^ RAYCITY_UDP_CHECKSUM_XOR)
    expected_plain_server = u32(plain_checksum ^ seed ^ ALT_UDP_CHECKSUM_XOR)
    expected_encrypted_client = u32(
        encrypted_checksum ^ seed ^ RAYCITY_UDP_CHECKSUM_XOR
    )
    expected_encrypted_server = u32(
        encrypted_checksum ^ seed ^ ALT_UDP_CHECKSUM_XOR
    )
    valid = received_checksum in (
        expected_plain_client,
        expected_plain_server,
        expected_encrypted_client,
        expected_encrypted_server,
    )
    return seed, plain, {
        "valid": valid,
        "received_checksum": received_checksum,
        "expected_plain_client": expected_plain_client,
        "expected_plain_server": expected_plain_server,
        "expected_encrypted_client": expected_encrypted_client,
        "expected_encrypted_server": expected_encrypted_server,
    }


def packet_body(base_key: int, status: int = 0) -> bytes:
    return b"\x00" + struct.pack("<II", base_key & 0xFFFFFFFF, status & 0xFFFFFFFF)


def make_pr_enter_field_payload(header: bytes, enter_key: int) -> bytes:
    return header + build_object_payload(Packet.PrEnterField, packet_body(enter_key, 0))


def make_pr_udp_echo_payload(header: bytes, enter_key: int) -> bytes:
    # dword_A5E610 (PrUdpEcho) is the UDP object the login field-wait loop
    return header + build_object_payload(
        Packet.PrUdpEcho,
        b"\x00" + struct.pack("<I", enter_key & 0xFFFFFFFF),
    )


def make_pr_time_sync_payload(header: bytes, server_time: int) -> bytes:
    return header + build_object_payload(
        Packet.PrTimeSync,
        b"\x00" + struct.pack("<I", server_time & 0xFFFFFFFF),
    )


def env_enabled(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


def udp_verbose() -> bool:
    return env_enabled("RAYCITY_UDP_VERBOSE", "0")


def log_time_sync() -> bool:
    return udp_verbose() or env_enabled("RAYCITY_LOG_TIMESYNC", "0")


def fallback_header(enter_key: int) -> bytes:
    return struct.pack("<IIB", enter_key & 0xFFFFFFFF, 0, 0)


def class_at(payload: bytes, offset: int) -> Optional[int]:
    if len(payload) < offset + 4:
        return None
    return struct.unpack_from("<I", payload, offset)[0]


def find_known_packet(payload: bytes) -> tuple[Optional[int], int]:
    for offset in (9, 0, 4, 8, 13):
        class_id = class_at(payload, offset)
        if class_id in PACKET_IDS:
            return class_id, offset
    known_ids = (Packet.PqUdpEcho, Packet.PrUdpEcho, Packet.PqTimeSync, Packet.PrTimeSync, Packet.PrEnterField)
    for offset in range(0, max(0, len(payload) - 3)):
        class_id = class_at(payload, offset)
        if class_id in known_ids:
            return class_id, offset
    return None, -1


@dataclass
class UdpPeerState:
    header: bytes
    enter_key: int
    last_seed: int
    last_seen: float
    sent_enter_field: bool = False
    handshake_log_count: int = 0
    handshake_generation: int = 0


class RaycityUdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, label: str):
        self.label = label
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.peers: dict[tuple[str, int], UdpPeerState] = {}
        seed = int(time.time() * 1000) & 0xFFFFFFFF
        self._next_seed = seed or 1

    def connection_made(self, transport):
        self.transport = transport
        sock = transport.get_extra_info("sockname")
        logger.info("UDP %s listener ready on %s", self.label, sock)

    def connection_lost(self, exc):
        logger.info("UDP %s listener closed", self.label)

    def peer_name(self, addr: tuple[str, int]) -> str:
        return f"{addr[0]}:{addr[1]}"

    def allocate_seed(self, last_seed: int = 0) -> int:
        if last_seed:
            seed = u32(last_seed + _UDP_SEED_STEP)
        else:
            seed = u32(self._next_seed + _UDP_SEED_STEP)
        if seed == 0:
            seed = 1
        self._next_seed = seed
        return seed

    def datagram_received(self, data: bytes, addr):
        if not isinstance(addr, tuple) or len(addr) < 2:
            return
        peer = (addr[0], int(addr[1]))
        if udp_verbose():
            logger.info(
                "RAW UDP %s data len=%d head=%s from %s",
                self.label,
                len(data),
                data[:64].hex(" "),
                self.peer_name(peer),
            )

        seed, payload, checksum_info = decrypt_udp_frame(data)
        plain_packet, packet_offset = find_known_packet(payload)
        plain_header = payload[:9] if len(payload) >= 9 else b""

        if plain_packet is None and len(data) >= 4:
            plain_len = struct.unpack_from("<I", data, 0)[0]
            if 0 <= plain_len <= len(data) - 4:
                plain_payload = data[4 : 4 + plain_len]
                plain_packet, packet_offset = find_known_packet(plain_payload)
                if plain_packet is not None:
                    payload = plain_payload
                    plain_header = payload[:9] if len(payload) >= 9 else b""

        packet_name = get_packet_name(plain_packet)
        enter_key = _LAST_ENTER_KEY or 1
        if len(plain_header) >= 4:
            header_key = struct.unpack_from("<I", plain_header, 0)[0]
            if header_key:
                enter_key = header_key
        header = plain_header if len(plain_header) == 9 else fallback_header(enter_key)
        state = self.peers.get(peer)
        if state is None:
            state = UdpPeerState(
                header,
                enter_key,
                seed or 0,
                time.monotonic(),
                handshake_generation=_UDP_HANDSHAKE_GENERATION,
            )
            self.peers[peer] = state
        else:
            if state.handshake_generation != _UDP_HANDSHAKE_GENERATION:
                # The client can reuse the same UDP source port after returning to
                # character select. Treat each newly armed login/select key as a
                # fresh handshake so relogin can receive PrUdpEcho again.
                state.sent_enter_field = False
                state.handshake_generation = _UDP_HANDSHAKE_GENERATION
            state.header = header
            state.enter_key = enter_key
            state.last_seed = seed or state.last_seed
            state.last_seen = time.monotonic()

        if udp_verbose():
            logger.info(
                "UDP %s decoded packet=%s class=0x%08X offset=%d seed=%s checksum_valid=%s header=%s enter_key=%d armed_key=%d generation=%d reason=%s from %s",
                self.label,
                packet_name,
                plain_packet or 0,
                packet_offset,
                f"0x{seed:08X}" if seed is not None else "n/a",
                checksum_info.get("valid"),
                header.hex(" "),
                enter_key,
                _LAST_ENTER_KEY,
                _UDP_HANDSHAKE_GENERATION,
                _LAST_UPDATE_REASON,
                self.peer_name(peer),
            )

        if plain_packet == Packet.PqUdpEcho or plain_packet is None:
            self.send_enter_field(peer, state, "pq_udp_echo" if plain_packet else "raw_udp")
        elif plain_packet == Packet.PqTimeSync:
            self.send_time_sync(peer, state)

    def send_time_sync(self, peer: tuple[str, int], state: UdpPeerState) -> None:
        if self.transport is None:
            return
        server_time = int(time.time() * 1000) & 0xFFFFFFFF
        payload = make_pr_time_sync_payload(state.header, server_time)
        reply_seed = self.allocate_seed(state.last_seed)
        state.last_seed = reply_seed
        frame = build_udp_frame(payload, reply_seed, RAYCITY_UDP_CHECKSUM_XOR)
        self.transport.sendto(frame, peer)
        if log_time_sync():
            logger.info(
                "SENT UDP PrTimeSync len=%d class=0x%08X server_time=%d header=%s to %s",
                len(frame),
                Packet.PrTimeSync,
                server_time,
                state.header.hex(" "),
                self.peer_name(peer),
            )

    def send_enter_field(self, peer: tuple[str, int], state: UdpPeerState, reason: str) -> None:
        if state.sent_enter_field:
            return
        self.send_enter_field_now(peer, state, reason)

    def send_enter_field_now(self, peer: tuple[str, int], state: UdpPeerState, reason: str) -> None:
        if self.transport is None or state.sent_enter_field:
            return
        enter_key = state.enter_key or _LAST_ENTER_KEY or 1
        echo_payload = make_pr_udp_echo_payload(state.header, enter_key)
        reply_seed = self.allocate_seed(state.last_seed)
        state.last_seed = reply_seed
        echo_frame = build_udp_frame(
            echo_payload,
            reply_seed,
            RAYCITY_UDP_CHECKSUM_XOR,
        )
        self.transport.sendto(echo_frame, peer)
        state.sent_enter_field = True
        if udp_verbose() or state.handshake_log_count == 0:
            logger.info(
                "SENT UDP PrUdpEcho reason=%s len=%d class=0x%08X enter_key=%d generation=%d to %s",
                reason,
                len(echo_frame),
                Packet.PrUdpEcho,
                enter_key,
                state.handshake_generation,
                self.peer_name(peer),
            )
        state.handshake_log_count += 1


async def start_udp_server(host: str = "0.0.0.0", port: int = 2180, label: str = "login"):
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: RaycityUdpProtocol(label),
        local_addr=(host, port),
    )
    logger.info("UDP %s server listening on %s:%d", label, host, port)
    return transport, protocol
