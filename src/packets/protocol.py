from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator, Optional


FRAME_HEADER_SIZE = 4
CLASS_ID_SIZE = 4
MAX_PAYLOAD_SIZE = 1024 * 1024
RAYCITY_1325_VERSION = 0x052D


KNOWN_PACKET_NAMES = (
    "PcFirstAccept",
    "PqFirstPacket",
    "PrFirstPacket",
    "PqLoginAgent",
    "PrLoginAgent",
    "PqUserLogin",
    "PrUserLogin",
    "PqGetCarInfo",
    "PrGetCarInfo",
    "PqGetInventory",
    "PrGetInventory",
    "PqCheckExistCharacter",
    "PrCheckExistCharacter",
    "PqNewCharacter",
    "PrNewCharacter",
    "PqDelCharacter",
    "PrDelCharacter",
    "PqSelectCharacter",
    "PrSelectCharacter",
    "PcGameAgentList",
    "PqEnterChannel",
    "PrEnterChannel",
    "PqEnterField",
    "PrEnterField",
    "PqLeaveField",
    "PqMoveField",
    "PqSetLastTown",
    "PqUpdateMaxCombo",
    "PrUpdateMaxCombo",
    "PqGetCarList",
    "PrGetCarList",
    "PqSelectCar",
    "PrSelectCar",
    "PqBuyStock",
    "PrBuyStock",
    "PqMoveInventoryItem",
    "PrMoveInventoryItem",
    "PqGetRaceList",
    "PrGetRaceList",
    "PqMakeRace",
    "PrMakeRace",
    "PqJoinRace",
    "PrJoinRace",
    "PqLeaveRace",
    "PrLeaveRace",
    "PqKeepAlive",
    "PqTimeSync",
    "PrTimeSync",
    "PcUpdateExp",
    "PcUpdateInventory",
    "PcUpdateSkill",
    "CharacterInfo",
    "CarInfo",
    "SecCarInfo",
    "Inventory",
)


def raycity_class_id(name: str) -> int:
    a = 0
    b = 0
    for value in name.encode("ascii"):
        a = (a + value) % 0xFFF1
        b = (b + a) % 0xFFF1
    result = ((b << 16) | a) & 0xFFFFFFFF
    return result if result not in (0, 0xFFFFFFFF) else 1


CLASS_IDS = {name: raycity_class_id(name) for name in KNOWN_PACKET_NAMES}
CLASS_NAMES = {class_id: name for name, class_id in CLASS_IDS.items()}

PC_FIRST_ACCEPT = CLASS_IDS["PcFirstAccept"]
PQ_FIRST_PACKET = CLASS_IDS["PqFirstPacket"]
PR_FIRST_PACKET = CLASS_IDS["PrFirstPacket"]
PQ_LOGIN_AGENT = CLASS_IDS["PqLoginAgent"]
PR_LOGIN_AGENT = CLASS_IDS["PrLoginAgent"]
PQ_USER_LOGIN = CLASS_IDS["PqUserLogin"]
PR_USER_LOGIN = CLASS_IDS["PrUserLogin"]
PQ_SELECT_CHARACTER = CLASS_IDS["PqSelectCharacter"]
PR_SELECT_CHARACTER = CLASS_IDS["PrSelectCharacter"]
PC_GAME_AGENT_LIST = CLASS_IDS["PcGameAgentList"]
PQ_ENTER_CHANNEL = CLASS_IDS["PqEnterChannel"]
PR_ENTER_CHANNEL = CLASS_IDS["PrEnterChannel"]
PQ_ENTER_FIELD = CLASS_IDS["PqEnterField"]
PR_ENTER_FIELD = CLASS_IDS["PrEnterField"]


@dataclass(frozen=True)
class ObjectPacket:
    class_id: int
    body: bytes

    @property
    def class_name(self) -> str:
        return CLASS_NAMES.get(self.class_id, f"unknown_0x{self.class_id:08X}")


def build_object_payload(class_id: int, body: bytes = b"") -> bytes:
    return struct.pack("<I", class_id) + body


def build_frame_payload(payload: bytes) -> bytes:
    return struct.pack("<I", len(payload)) + payload


def build_object_frame(class_id: int, body: bytes = b"") -> bytes:
    return build_frame_payload(build_object_payload(class_id, body))


def build_packet(packet_type: int, payload: bytes = b"") -> bytes:
    """Compatibility wrapper for older server code."""
    return build_object_frame(packet_type, payload)


def make_pc_first_accept() -> bytes:
    """
    Build the server-first handshake packet.

    These fields intentionally make the client's key derivation produce zero:
      high32(field2 << shift) ^ high32(field1 << shift) ^ 0xA815B623 == 0
    A zero key keeps the following PqFirstPacket unencrypted while we continue
    filling in the rest of the login flow.
    """
    field1 = 0
    field2 = 0xA815B623 << 32
    shift = 0
    body = b"\x00" + struct.pack("<QQB", field1, field2, shift)
    return build_object_frame(PC_FIRST_ACCEPT, body)


def make_pr_first_packet(
    status: int = 0,
    version: int = RAYCITY_1325_VERSION,
    patch_version: int = RAYCITY_1325_VERSION,
) -> bytes:
    """
    Build PrFirstPacket.

    The client exits from its PrFirstPacket handler when status is non-zero.
    The following two 16-bit fields are forwarded into the client's patch/version
    context; for the 1.325 client they should carry 1325 (0x052D).
    """
    body = b"\x00" + struct.pack(
        "<BHHB",
        status & 0xFF,
        version & 0xFFFF,
        patch_version & 0xFFFF,
        0,
    )
    return build_object_frame(PR_FIRST_PACKET, body)


def try_parse_header(data: bytes) -> Optional[int]:
    if len(data) < FRAME_HEADER_SIZE:
        return None
    return struct.unpack_from("<I", data)[0]


class PacketBuffer:
    """Reassembles TCP stream data into Raycity object packets."""

    def __init__(self):
        self._buf = bytearray()

    def feed(self, data: bytes):
        self._buf.extend(data)

    def packets(self) -> Iterator[tuple[int, bytes]]:
        """Yield (class_id, body) for each complete unencrypted object packet."""
        while True:
            if len(self._buf) < FRAME_HEADER_SIZE:
                break

            payload_len = struct.unpack_from("<I", self._buf)[0]
            if payload_len < CLASS_ID_SIZE or payload_len > MAX_PAYLOAD_SIZE:
                del self._buf[0]
                continue

            total_len = FRAME_HEADER_SIZE + payload_len
            if len(self._buf) < total_len:
                break

            payload = bytes(self._buf[FRAME_HEADER_SIZE:total_len])
            class_id = struct.unpack_from("<I", payload)[0]
            body = payload[CLASS_ID_SIZE:]
            del self._buf[:total_len]
            yield class_id, body


class PacketReader:
    """Convenience wrapper around struct.unpack_from with a cursor."""

    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    def remaining(self) -> int:
        return len(self._data) - self._pos

    def read_u8(self) -> int:
        v = struct.unpack_from("B", self._data, self._pos)[0]
        self._pos += 1
        return v

    def read_u16(self) -> int:
        v = struct.unpack_from("<H", self._data, self._pos)[0]
        self._pos += 2
        return v

    def read_u32(self) -> int:
        v = struct.unpack_from("<I", self._data, self._pos)[0]
        self._pos += 4
        return v

    def read_i32(self) -> int:
        v = struct.unpack_from("<i", self._data, self._pos)[0]
        self._pos += 4
        return v

    def read_f32(self) -> float:
        v = struct.unpack_from("<f", self._data, self._pos)[0]
        self._pos += 4
        return v

    def read_bytes(self, n: int) -> bytes:
        v = self._data[self._pos:self._pos + n]
        self._pos += n
        return v

    def read_str_fixed(self, n: int, encoding: str = "cp949") -> str:
        raw = self.read_bytes(n)
        return raw.rstrip(b"\x00").decode(encoding, errors="replace")

    def read_str_pascal(self, encoding: str = "cp949") -> str:
        length = self.read_u16()
        raw = self.read_bytes(length)
        return raw.decode(encoding, errors="replace")


class PacketWriter:
    """Convenience wrapper to build packet bodies."""

    def __init__(self):
        self._buf = bytearray()

    def write_u8(self, v: int):
        self._buf += struct.pack("B", v)

    def write_u16(self, v: int):
        self._buf += struct.pack("<H", v)

    def write_u32(self, v: int):
        self._buf += struct.pack("<I", v)

    def write_i32(self, v: int):
        self._buf += struct.pack("<i", v)

    def write_f32(self, v: float):
        self._buf += struct.pack("<f", v)

    def write_bytes(self, b: bytes):
        self._buf += b

    def write_str_fixed(self, s: str, n: int, encoding: str = "cp949"):
        encoded = s.encode(encoding, errors="replace")
        self._buf += encoded[:n].ljust(n, b"\x00")

    def write_str_pascal(self, s: str, encoding: str = "cp949"):
        encoded = s.encode(encoding, errors="replace")
        self._buf += struct.pack("<H", len(encoded))
        self._buf += encoded

    def getvalue(self) -> bytes:
        return bytes(self._buf)
