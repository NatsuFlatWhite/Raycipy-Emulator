import asyncio
import logging
import struct
from typing import Optional

from src.game.database import (
    DEFAULT_CAR_FUEL,
    DEFAULT_COMBO,
    DEFAULT_UNKNOWN_VALUE,
    DEFAULT_INVENTORY_SLOTS,
    DEFAULT_ITEM_EXPIRE_TIME,
    DEFAULT_RP,
    DEFAULT_TRUNK_SLOTS,
    db,
    Account,
    Car,
    Character,
    InventoryItem,
)
from src.packets.protocol import (
    PacketBuffer,
    PacketWriter,
    build_packet,
    make_pc_first_accept,
    make_pr_first_packet as build_pr_first_packet,
)
from src.packets.packet_registry import Packet, packet_name

logger = logging.getLogger("LoginServer")
ACTIVE_LOGIN_SESSIONS = set()


CAR_MODELS = {
    "s35": (1, 5),
    "altoqq": (2, 5),
    "sparrow": (3, 1),
    "mato": (4, 1),
    "torino": (5, 5),
    "sonnet6": (6, 3),
    "angelo": (7, 6),
    "clio": (8, 1),
    "tusco": (9, 7),
    "spa": (10, 7),
    "versante3": (11, 2),
    "versante4": (12, 2),
    "sonnet5": (13, 3),
    "kalo": (14, 1),
    "lego": (15, 3),
    "uphima": (16, 3),
    "royal": (17, 3),
    "margio": (18, 4),
    "versante3s": (19, 2),
    "s5": (20, 3),
    "altoa6": (21, 3),
    "veloce9": (22, 6),
    "altoa8": (23, 4),
    "gabriel": (24, 6),
    "velocegt": (25, 6),
    "bzo": (26, 6),
    "romans": (27, 6),
    "grafico": (28, 5),
    "escarabajo": (29, 6),
    "mayer": (30, 4),
    "milano": (31, 6),
    "anx": (32, 6),
    "universal": (33, 4),
    "superior": (34, 6),
    "blizzard6": (35, 6),
    "neobee": (36, 1),
    "piedevile": (37, 6),
    "spatola": (38, 6),
    "c": (39, 2),
    "bonzes": (43, 4),
    "bnv3": (48, 2),
    "porter2": (58, 8),
    "toporter": (60, 8),
    "bus": (62, 8),
    "cc8": (64, 5),
    "inno8": (67, 3),
    "echo": (70, 4),
    "s3": (75, 2),
    "gx04": (86, 3),
    "je98": (87, 2),
    "jatcar": (1001, 6),
}
CAR_MODEL_BY_ID = {model_id: (name, grade) for name, (model_id, grade) in CAR_MODELS.items()}


def is_name_char(ch: str) -> bool:
    return (
        ch.isalnum()
        or ch in "_-"
        or "\uac00" <= ch <= "\ud7a3"
)

FALLBACK_MAX_SP = 100


def clean_character_name(text: str) -> str:
    text = text.split("\x00", 1)[0].strip()
    return "".join(ch for ch in text if is_name_char(ch))


def decode_name_candidate(raw: bytes) -> str:
    return clean_character_name(raw.decode("cp949", errors="ignore"))


def read_utf16_string_at(payload: bytes, offset: int) -> tuple[str, int] | None:
    if len(payload) < offset + 4:
        return None
    length = struct.unpack_from("<I", payload, offset)[0]
    byte_len = length * 2
    start = offset + 4
    end = start + byte_len
    if length > 32 or end > len(payload):
        return None
    text = clean_character_name(payload[start:end].decode("utf-16le", errors="ignore"))
    if not text:
        return None
    return text, end


def read_pq_new_character_appearance(payload: bytes) -> tuple[int, int]:
    decoded = read_utf16_string_at(payload, 1)
    if not decoded:
        return DEFAULT_COMBO, DEFAULT_UNKNOWN_VALUE
    _, offset = decoded
    if len(payload) < offset + 2:
        return DEFAULT_COMBO, DEFAULT_UNKNOWN_VALUE
    appearance_code = struct.unpack_from("<H", payload, offset)[0]
    offset += 2
    decoded_car_name = read_utf16_string_at(payload, offset)
    if decoded_car_name:
        _, offset = decoded_car_name
    if len(payload) <= offset:
        return appearance_code, DEFAULT_UNKNOWN_VALUE
    return appearance_code, payload[offset]


def extract_name_candidate(payload: bytes) -> Optional[str]:
    for offset in (1, 0):
        decoded = read_utf16_string_at(payload, offset)
        if decoded:
            name, _ = decoded
            if 2 <= len(name) <= 16:
                return name

    for offset in (1, 0):
        if len(payload) >= offset + 32:
            name = decode_name_candidate(payload[offset:offset + 32])
            if 2 <= len(name) <= 16:
                return name

    best = ""
    for start in range(min(len(payload), 96)):
        end = payload.find(b"\x00", start, min(len(payload), start + 33))
        if end < 0:
            continue
        raw = payload[start:end]
        if len(raw) < 2:
            continue
        name = decode_name_candidate(raw)
        if 2 <= len(name) <= 16 and len(name) > len(best):
            best = name
    return best or None


def read_base_u32(payload: bytes, default: int = 0) -> int:
    if len(payload) >= 5:
        return struct.unpack_from("<I", payload, 1)[0]
    if len(payload) >= 4:
        return struct.unpack_from("<I", payload, 0)[0]
    return default


def read_pq_get_car_info(payload: bytes) -> tuple[int, int, int]:
    char_id = struct.unpack_from("<I", payload, 1)[0] if len(payload) >= 5 else 0
    car_id = struct.unpack_from("<I", payload, 5)[0] if len(payload) >= 9 else 0
    flag = payload[9] if len(payload) >= 10 else 0
    return char_id, car_id, flag


def decode_login_field(
    raw: bytes,
    min_len: int = 2,
    *,
    allow_blank: bool = False,
) -> Optional[str]:
    raw = raw.rstrip(b"\x00")
    if not raw:
        return "" if allow_blank else None

    text = raw.decode("cp949", errors="ignore").split("\x00", 1)[0].strip()
    text = "".join(ch for ch in text if is_name_char(ch) or ch in ".@")

    if not text and allow_blank:
        return ""
    if len(text) >= min_len and any(ch.isalnum() for ch in text):
        return text
    return None


def read_login_name(payload: bytes) -> Optional[str]:
    for offset in (1, 0):
        if len(payload) < offset + 4:
            continue
        length = struct.unpack_from("<I", payload, offset)[0]
        if 0 <= length <= 32 and len(payload) >= offset + 4 + length:
            start = offset + 4
            name = decode_login_field(
                payload[start:start + length],
                min_len=1,
                allow_blank=True,
            )
            if name is not None:
                return name
    return None


def login_username_from_payload(payload: bytes) -> str:
    name = read_login_name(payload)
    if name is not None:
        return name
    raw = payload[:32].ljust(32, b"\x00")
    name = decode_login_field(raw, min_len=1, allow_blank=True)
    return "" if name is None else name


def login_password_from_payload(payload: bytes) -> str:
    raw = payload[32:64]
    return decode_login_field(raw) or "raycity-dev"


def account_character(account: Account, char_id: int = 0) -> Optional[Character]:
    if char_id:
        char = db.get_character(char_id)
        if char and char.account_id == account.account_id:
            return char
    if account.selected_char_id:
        char = db.get_character(account.selected_char_id)
        if char and char.account_id == account.account_id:
            return char
    return account.characters[-1] if account.characters else None


def account_character_by_name(account: Account, name: str) -> Optional[Character]:
    lowered = name.lower()
    for char in account.characters:
        if char.name.lower() == lowered:
            return char
    return None


def get_selected_car(char: Character, car_id: int = 0) -> Optional[Car]:
    if car_id:
        for car in char.cars:
            if car.car_id == car_id:
                return car
    if char.selected_car_id:
        for car in char.cars:
            if car.car_id == char.selected_car_id:
                return car
    return char.cars[-1] if char.cars else None


def car_model_id(car: Car) -> int:
    if isinstance(car.model_id, int):
        return car.model_id
    return CAR_MODELS.get(str(car.model_id).lower(), (1, 5))[0]


def car_grade(car: Car) -> int:
    if isinstance(car.model_id, int):
        return CAR_MODEL_BY_ID.get(car.model_id, ("s35", 5))[1]
    return CAR_MODELS.get(str(car.model_id).lower(), (1, 5))[1]


def car_model_name(car: Car) -> str:
    if isinstance(car.model_id, str):
        return car.model_id
    return CAR_MODEL_BY_ID.get(car.model_id, ("s35", 5))[0]


def positive_int(value, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    return number if number > 0 else default


def nonnegative_int(value, default: int = 0) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    return number if number >= 0 else default


def character_rp_value(char: Character) -> int:
    return positive_int(getattr(char, "rp", DEFAULT_RP), DEFAULT_RP)


def character_sp_max(char: Character) -> int:
    # CharacterInfo +0x20 is copied to the client's SecCharacterInfo +0x44,
    # Edit `max_sp` in raycity_db.json to change the visible SP maximum.
    return positive_int(getattr(char, "max_sp", FALLBACK_MAX_SP), FALLBACK_MAX_SP)


def character_reserved_stat(char: Character) -> int:
    # Unknown u32 fields around the EXP/money block.
    return nonnegative_int(getattr(char, "max_sp", 0), 0)


def inventory_slots(char: Character) -> int:
    return positive_int(
        getattr(char, "inventory_slots", DEFAULT_INVENTORY_SLOTS),
        DEFAULT_INVENTORY_SLOTS,
    )


def inventory_owner_id(char: Character, owner_id: int = 0) -> int:
    return int(owner_id or getattr(char, "char_id", 0) or 0)


def owner_is_car_inventory(char: Character, owner_id: int) -> bool:
    owner_id = int(owner_id or 0)
    return any(int(getattr(car, "car_id", 0) or 0) == owner_id for car in getattr(char, "cars", []) or [])


def inventory_slots_for_owner(char: Character, owner_id: int = 0) -> int:
    owner_id = inventory_owner_id(char, owner_id)
    if owner_id == int(getattr(char, "char_id", 0) or 0):
        return inventory_slots(char)
    if owner_is_car_inventory(char, owner_id):
        return DEFAULT_TRUNK_SLOTS
    return 0


def inventory_slot_limit_for_owner(char: Character, owner_id: int = 0) -> int:
    owner_id = inventory_owner_id(char, owner_id)
    if owner_id == int(getattr(char, "char_id", 0) or 0):
        return 0x100
    if owner_is_car_inventory(char, owner_id):
        return 0x100
    return 0


def car_fuel(car: Car) -> tuple[int, int]:
    fuel = positive_int(getattr(car, "fuel", DEFAULT_CAR_FUEL), DEFAULT_CAR_FUEL)
    max_fuel = positive_int(getattr(car, "max_fuel", DEFAULT_CAR_FUEL), DEFAULT_CAR_FUEL)
    return fuel, max(max_fuel, fuel)


def car_mileage(car: Car) -> int:
    return nonnegative_int(getattr(car, "mileage", 0), 0)



# ─── Response builders ────────────────────────────────────────────────────────

def make_pr_first_packet() -> bytes:
    return build_pr_first_packet()


def make_pr_login_agent(success: bool = True) -> bytes:
    w = PacketWriter()
    # PrLoginAgent read path (0x436650) starts with the shared packet-base
    # flag, then reads a status byte, a u32, and a vector<u32>.
    w.write_u8(0)
    w.write_u8(1 if success else 0)
    w.write_u32(0)
    w.write_u32(0)
    return build_packet(Packet.PrLoginAgent, w.getvalue())


def ip_to_wire_u32(ip: str) -> int:
    octets = bytes(int(part) & 0xFF for part in ip.split("."))
    return struct.unpack("<I", octets)[0]


def allocate_game_agent_id() -> int:
    try:
        from src.network.game_server import allocate_game_agent_id

        return allocate_game_agent_id()
    except Exception:
        return 1


def make_pc_game_agent_list(
    ip: str = "127.0.0.1",
    port: int = 2181,
    agent_id: Optional[int] = None,
) -> bytes:
    if agent_id is None:
        agent_id = allocate_game_agent_id()
    w = PacketWriter()
    w.write_u8(0)
    w.write_u32(1)
    write_utf16_string(w, "race")
    w.write_u32(agent_id)
    w.write_u32(ip_to_wire_u32(ip))
    w.write_u16(port)
    return build_packet(Packet.PcGameAgentList, w.getvalue())


def make_pr_user_login(account: Optional[Account], success: bool) -> bytes:
    w = PacketWriter()
    w.write_u8(0)
    w.write_u8(1 if success else 0)
    if success and account:
        # Client reads PrUserLogin as: success, account id, u16, UDP enter
        # key, status/flags, empty vector.  Keep this order aligned with the
        # 1.325 serializer; the UDP wait state later compares against +0x30.
        w.write_u32(account.account_id)
        w.write_u16(0)
        w.write_u32(account.account_id)
        w.write_u32(0)
        w.write_u32(0)
    else:
        w.write_u32(1)
    return build_packet(Packet.PrUserLogin, w.getvalue())


def make_pr_check_exist_char(exists: bool) -> bytes:
    w = PacketWriter()
    w.write_u8(0)
    w.write_u8(1 if exists else 0)
    return build_packet(Packet.PrCheckExistCharacter, w.getvalue())


def write_utf16_string(w: PacketWriter, text: str):
    encoded = text.encode("utf-16le", errors="replace")
    w.write_u32(len(encoded) // 2)
    w.write_bytes(encoded)


def write_u32_triplet(w: PacketWriter, a: int = 0, b: int = 0, c: int = 0):
    w.write_u32(a)
    w.write_u32(b)
    w.write_u32(c)


def existing_character_list_selected_car_mode() -> str:
    return "model"


def make_character_info_object(char: Character, selected_car_mode: Optional[str] = None) -> bytes:
    rp = character_rp_value(char)
    sp_max = character_sp_max(char)
    reserved_stat = character_reserved_stat(char)
    w = PacketWriter()
    w.write_u32(char.char_id)
    write_utf16_string(w, char.name)
    w.write_u32(0)
    w.write_u16(char.level)
    w.write_u32(char.exp)
    w.write_u32(reserved_stat)
    w.write_u32(reserved_stat)
    w.write_u32(char.money)
    w.write_bytes(struct.pack("<Q", 0))
    w.write_u16(sp_max)
    w.write_u16(char.combo)
    w.write_u8(char.unk_value)
    w.write_u32(rp)
    w.write_u32(char.mileage)
    w.write_u32(char.town_id)
    write_u32_triplet(w)
    w.write_u16(0)
    w.write_u32(0)
    w.write_u32(rp)
    w.write_u32(reserved_stat)
    write_u32_triplet(w)
    write_u32_triplet(w)
    write_u32_triplet(w)
    return struct.pack("<I", Packet.CharacterInfo) + w.getvalue()


def make_sec_character_info_object(char: Character, selected_car_mode: Optional[str] = None) -> bytes:
    rp = character_rp_value(char)
    sp_max = character_sp_max(char)
    reserved_stat = character_reserved_stat(char)
    w = PacketWriter()
    w.write_u32(char.char_id)
    write_utf16_string(w, char.name)
    w.write_u32(0)
    w.write_u16(char.level)
    w.write_u32(char.exp)
    w.write_u32(reserved_stat)
    w.write_u32(reserved_stat)
    w.write_u32(char.money)
    w.write_bytes(struct.pack("<Q", 0))
    w.write_u16(sp_max)
    w.write_u16(char.combo)
    w.write_u8(char.unk_value)
    w.write_u32(rp)
    w.write_u32(char.mileage)
    w.write_u32(char.town_id)
    write_u32_triplet(w)
    w.write_u16(0)
    w.write_u32(0)
    w.write_u32(rp)
    w.write_u32(reserved_stat)
    write_u32_triplet(w)
    write_u32_triplet(w)
    write_u32_triplet(w)
    return struct.pack("<I", Packet.SecCharacterInfo) + w.getvalue()


def make_field_race_dest_node_object(char: Character) -> bytes:
    w = PacketWriter()
    w.write_u16(0)
    write_utf16_string(w, "")
    w.write_u32(0)
    write_u32_triplet(w)
    w.write_u8(0)
    return struct.pack("<I", Packet.FieldRaceDestNode) + w.getvalue()


def make_race_dest_node_object(char: Character) -> bytes:
    w = PacketWriter()
    w.write_u32(0)
    w.write_u8(0)
    w.write_u8(0)
    w.write_u32(0)
    return struct.pack("<I", Packet.RaceDestNode) + w.getvalue()


def make_select_secondary_character_object(
    char: Character,
    selected_car_mode: Optional[str] = None,
    mode: Optional[str] = None,
) -> bytes:
    return make_inventory_object(char.char_id, inventory_slots(char), inventory_items(char))


def make_select_secondary_route_object(
    char: Character,
    car: Car,
    mode: Optional[str] = None,
) -> bytes:
    return make_empty_car_inventory_object(car)


def make_select_optional_object(char: Character, car: Car, mode: str) -> Optional[bytes]:
    mode = mode.strip().lower()
    if mode in ("", "0", "none", "null"):
        return None
    if mode == "character":
        return make_character_info_object(char)
    if mode == "sec":
        return make_sec_character_info_object(char)
    if mode == "car":
        return make_car_info_object(car)
    if mode == "sec_car":
        return make_sec_car_info_object(car)
    if mode == "inventory":
        return make_empty_car_inventory_object(car)
    if mode == "field":
        return make_field_race_dest_node_object(char)
    return make_race_dest_node_object(char)


def write_select_optional_slots(w: PacketWriter, char: Character, car: Car) -> None:
    for _ in range(4):
        w.write_u8(0)


def make_character_info_vector(
    chars: list[Character],
    selected_car_mode: Optional[str] = None,
) -> bytes:
    w = PacketWriter()
    w.write_u32(len(chars))
    for char in chars:
        w.write_bytes(make_character_info_object(char, selected_car_mode))
    return w.getvalue()


def make_car_info_object(car: Car) -> bytes:
    model_id = car_model_id(car)
    level = getattr(car, "level", 1)
    fuel, max_fuel = car_fuel(car)
    mileage = car_mileage(car)
    w = PacketWriter()
    w.write_u32(car.car_id)
    w.write_u16(model_id)
    write_utf16_string(w, car.name or f"Car{car.car_id}")
    w.write_u8(car.unk & 0xFF)
    w.write_u32(car.car_id)
    w.write_u16(level)
    w.write_u32(car.exp)
    w.write_u32(car.endurance)
    w.write_u32(car.max_endurance)
    w.write_bytes(struct.pack("<Q", mileage))
    w.write_f32((fuel * 100.0) / max_fuel if max_fuel else 0.0)
    return struct.pack("<I", Packet.CarInfo) + w.getvalue()


def make_sec_car_info_object(car: Car) -> bytes:
    model_id = car_model_id(car)
    level = getattr(car, "level", 1)
    fuel, max_fuel = car_fuel(car)
    mileage = car_mileage(car)
    w = PacketWriter()
    w.write_u32(car.car_id)
    w.write_u16(model_id)
    write_utf16_string(w, car.name or f"Car{car.car_id}")
    w.write_u8(car.unk & 0xFF)
    w.write_u32(car.car_id)
    w.write_u16(level)
    w.write_u32(car.exp)
    w.write_u32(car.endurance)
    w.write_u32(car.max_endurance)
    w.write_bytes(struct.pack("<Q", mileage))
    w.write_f32((fuel * 100.0) / max_fuel if max_fuel else 0.0)
    return struct.pack("<I", Packet.SecCarInfo) + w.getvalue()


def make_get_car_info_secondary_object(car: Car, char: Optional[Character] = None) -> bytes:
    # The second object in PrGetCarInfo is consumed by the garage UI as the
    # selected car inventory/equipment container. Sending SecCarInfo here can
    # be misread as 0x38-byte item records and crash the client.
    if char:
        return make_inventory_object(
            car.car_id,
            DEFAULT_TRUNK_SLOTS,
            inventory_items(char, car.car_id),
        )
    return make_empty_car_inventory_object(car)


def inventory_items(char: Character, owner_id: int = 0) -> list[InventoryItem]:
    owner_id = inventory_owner_id(char, owner_id)
    slot_limit = inventory_slot_limit_for_owner(char, owner_id)
    items: list[InventoryItem] = []
    for raw in getattr(char, "inventory", []) or []:
        try:
            slot = int(raw.slot)
            item_id = int(raw.item_id)
        except (TypeError, ValueError):
            continue
        item_owner_id = int(getattr(raw, "owner_id", 0) or char.char_id)
        if item_owner_id != owner_id:
            continue
        if 0 <= slot < slot_limit and item_id > 0:
            items.append(
                InventoryItem(
                    slot=slot,
                    item_id=item_id,
                    count=positive_int(getattr(raw, "count", 1), 1),
                    expire_time=(
                        nonnegative_int(
                            getattr(raw, "expire_time", DEFAULT_ITEM_EXPIRE_TIME),
                            DEFAULT_ITEM_EXPIRE_TIME,
                        )
                        or DEFAULT_ITEM_EXPIRE_TIME
                    ),
                    owner_id=owner_id,
                )
            )
    return sorted(items, key=lambda item: item.slot)



def write_inventory_item(w: PacketWriter, item: InventoryItem) -> None:
    unique_id = ((int(item.item_id) & 0xFFFFFFFF) << 32) | (int(item.slot) & 0xFFFFFFFF)
    w.write_bytes(struct.pack("<Q", unique_id))
    w.write_u8(int(item.slot) & 0xFF)
    w.write_bytes(struct.pack("<Q", int(item.expire_time) & 0xFFFFFFFFFFFFFFFF))
    w.write_u32(int(item.item_id) & 0xFFFFFFFF)
    w.write_u8(0)
    w.write_u16(max(1, int(item.count)) & 0xFFFF)
    w.write_u16(0)


def make_inventory_object(
    owner_id: int,
    slot_count: int = DEFAULT_INVENTORY_SLOTS,
    items: Optional[list[InventoryItem]] = None,
) -> bytes:
    slot_count = max(1, min(int(slot_count or DEFAULT_INVENTORY_SLOTS), 0xFF))
    w = PacketWriter()
    w.write_u32(owner_id)
    w.write_u8(0)
    w.write_u8(slot_count)
    visible_items = list(items or [])
    w.write_u32(len(visible_items))
    for item in visible_items:
        write_inventory_item(w, item)
    w.write_u16(0)
    w.write_u16(0)
    return struct.pack("<I", Packet.Inventory) + w.getvalue()


def make_empty_car_inventory_object(car: Car) -> bytes:
    return make_inventory_object(car.car_id, DEFAULT_TRUNK_SLOTS)


def make_car_list_item(car: Car) -> bytes:
    fuel, max_fuel = car_fuel(car)
    w = PacketWriter()
    w.write_u32(car.car_id)
    write_utf16_string(w, car.name or car_model_name(car))
    w.write_u16(car_model_id(car))
    w.write_u16(car_grade(car))
    w.write_u32(fuel)
    w.write_u32(max_fuel)
    return w.getvalue()


def make_pr_get_car_list(char: Optional[Character]) -> bytes:
    cars = char.cars if char else []
    w = PacketWriter()
    w.write_u8(0)
    w.write_u32(len(cars))
    for car in cars:
        w.write_bytes(make_car_list_item(car))
    return build_packet(Packet.PrGetCarList, w.getvalue())


def make_pr_get_car_info(
    success: bool,
    car: Optional[Car] = None,
    char: Optional[Character] = None,
) -> bytes:
    w = PacketWriter()
    w.write_u8(0)
    if success and car:
        w.write_bytes(make_car_info_object(car))
        w.write_bytes(make_get_car_info_secondary_object(car, char))
    else:
        dummy = Car(car_id=0, model_id=1, name="")
        w.write_bytes(make_car_info_object(dummy))
        w.write_bytes(make_get_car_info_secondary_object(dummy, char))
    return build_packet(Packet.PrGetCarInfo, w.getvalue())




def make_pr_select_car(
    success: bool,
    car: Optional[Car] = None,
    char: Optional[Character] = None,
) -> bytes:
    w = PacketWriter()
    w.write_u8(0)

    if success and car:
        # PrSelectCar owns three object references after the packet base.
        # SecCarInfo is *not* used here; sending it as the second object makes
        # the garage car-select handler walk the wrong object and can crash at
        # Raycity.exe!0x8199AE. Keep this response aligned with the garage flow:
        #   1) selected car information
        #   2) selected car inventory/trunk container
        #   3) character inventory/equipment container
        w.write_bytes(make_car_info_object(car))
        if char:
            w.write_bytes(
                make_inventory_object(
                    car.car_id,
                    DEFAULT_TRUNK_SLOTS,
                    inventory_items(char, car.car_id),
                )
            )
            w.write_bytes(
                make_inventory_object(
                    char.char_id,
                    inventory_slots(char),
                    inventory_items(char, char.char_id),
                )
            )
        else:
            w.write_bytes(make_empty_car_inventory_object(car))
            w.write_bytes(make_inventory_object(0, DEFAULT_INVENTORY_SLOTS, []))
    else:
        dummy = Car(car_id=0, model_id=1, name="")
        w.write_bytes(make_car_info_object(dummy))
        w.write_bytes(make_empty_car_inventory_object(dummy))
        w.write_bytes(make_inventory_object(0, DEFAULT_INVENTORY_SLOTS, []))

    return build_packet(Packet.PrSelectCar, w.getvalue())



def make_pr_get_inventory(char: Optional[Character], owner_id: int = 0) -> bytes:
    w = PacketWriter()
    w.write_u8(0)
    if char:
        owner_id = inventory_owner_id(char, owner_id)
        w.write_bytes(
            make_inventory_object(
                owner_id,
                inventory_slots_for_owner(char, owner_id) or inventory_slots(char),
                inventory_items(char, owner_id),
            )
        )
    else:
        w.write_bytes(make_inventory_object(owner_id, DEFAULT_INVENTORY_SLOTS))
    return build_packet(Packet.PrGetInventory, w.getvalue())


def make_pc_update_inventory(char: Optional[Character], owner_id: int = 0) -> bytes:
    w = PacketWriter()
    w.write_u8(0)
    if char:
        owner_id = inventory_owner_id(char, owner_id)
        w.write_bytes(
            make_inventory_object(
                owner_id,
                inventory_slots_for_owner(char, owner_id) or inventory_slots(char),
                inventory_items(char, owner_id),
            )
        )
    else:
        w.write_bytes(make_inventory_object(owner_id, DEFAULT_INVENTORY_SLOTS))
    return build_packet(Packet.PcUpdateInventory, w.getvalue())


def make_pr_buy_stock(status: int = 0) -> bytes:
    w = PacketWriter()
    w.write_u8(0)
    w.write_u32(status & 0xFFFFFFFF)
    return build_packet(Packet.PrBuyStock, w.getvalue())


def make_pr_move_inventory_item(status: int = 0, detail: int = 0) -> bytes:
    w = PacketWriter()
    w.write_u8(0)
    w.write_u32(status & 0xFFFFFFFF)
    w.write_u32(detail & 0xFFFFFFFF)
    return build_packet(Packet.PrMoveInventoryItem, w.getvalue())


def make_pr_update_max_combo(status: int = 0, combo: int = 0) -> bytes:
    w = PacketWriter()
    w.write_u8(0)
    w.write_u8(status & 0xFF)
    w.write_u16(combo & 0xFFFF)
    return build_packet(Packet.PrUpdateMaxCombo, w.getvalue())


def make_pc_update_money(char: Optional[Character]) -> bytes:
    money = nonnegative_int(getattr(char, "money", 0) if char else 0, 0)
    w = PacketWriter()
    w.write_u8(0)
    w.write_u32(money)
    w.write_u32(money)
    w.write_u32(money)
    return build_packet(Packet.PcUpdateMoney, w.getvalue())


def parse_pq_buy_stock(payload: bytes) -> tuple[int, int, list[int]]:
    offset = 1
    if len(payload) < offset + 12:
        return 0, 0, []
    shop_id = struct.unpack_from("<I", payload, offset)[0]
    category = struct.unpack_from("<I", payload, offset + 4)[0]
    count = struct.unpack_from("<I", payload, offset + 8)[0]
    offset += 12
    item_ids: list[int] = []
    for _ in range(min(count, 64)):
        if len(payload) < offset + 8:
            break
        low, high = struct.unpack_from("<II", payload, offset)
        offset += 8
        item_id = low or high
        if item_id:
            item_ids.append(item_id)
    return shop_id, category, item_ids


def first_free_inventory_slot(char: Character, owner_id: int = 0) -> Optional[int]:
    owner_id = inventory_owner_id(char, owner_id)
    slot_count = inventory_slots_for_owner(char, owner_id)
    if slot_count <= 0:
        return None
    used = {item.slot for item in inventory_items(char, owner_id)}
    for slot in range(slot_count):
        if slot not in used:
            return slot
    return None


def parse_pq_move_inventory_item(payload: bytes) -> dict[str, int]:
    if len(payload) >= 31:
        long_item_id = struct.unpack_from("<I", payload, 9)[0]
        repeated_item_id = struct.unpack_from("<I", payload, 18)[0]
        if long_item_id and long_item_id == repeated_item_id:
            return {
                "source_key": struct.unpack_from("<I", payload, 1)[0],
                "source_owner_id": struct.unpack_from("<I", payload, 13)[0],
                "source_slot": struct.unpack_from("<I", payload, 5)[0] & 0xFF,
                "item_id": long_item_id,
                "target_owner_id": struct.unpack_from("<I", payload, 22)[0],
                "target_slot": struct.unpack_from("<I", payload, 26)[0] & 0xFF,
                "detail": payload[30],
            }
    if len(payload) < 23:
        return {
            "source_key": 0,
            "source_owner_id": 0,
            "source_slot": 0,
            "item_id": 0,
            "target_owner_id": 0,
            "target_slot": 0,
            "detail": 0,
        }
    return {
        "source_key": struct.unpack_from("<I", payload, 1)[0],
        "source_owner_id": struct.unpack_from("<I", payload, 5)[0],
        "source_slot": payload[9],
        "item_id": struct.unpack_from("<I", payload, 10)[0],
        "target_owner_id": struct.unpack_from("<I", payload, 14)[0],
        "target_slot": payload[18],
        "detail": struct.unpack_from("<I", payload, 19)[0],
    }


def apply_move_inventory_item(
    char: Optional[Character],
    payload: bytes,
) -> tuple[int, dict[str, int], bool]:
    move = parse_pq_move_inventory_item(payload)
    if not char or not move["item_id"]:
        return 1, move, False

    items = getattr(char, "inventory", []) or []
    source_owner_id = move["source_owner_id"] or char.char_id
    target_owner_id = move["target_owner_id"] or char.char_id
    item = next(
        (
            raw
            for raw in items
            if int(getattr(raw, "item_id", 0) or 0) == move["item_id"]
            and int(getattr(raw, "slot", -1)) == move["source_slot"]
            and int(getattr(raw, "owner_id", 0) or char.char_id) == source_owner_id
        ),
        None,
    )
    if item is None:
        item = next(
            (
                raw
                for raw in items
                if int(getattr(raw, "item_id", 0) or 0) == move["item_id"]
                and int(getattr(raw, "owner_id", 0) or char.char_id) == source_owner_id
            ),
            None,
        )
    if item is None:
        return 1, move, False

    target_slot_limit = inventory_slot_limit_for_owner(char, target_owner_id)
    if target_slot_limit <= 0 or not (0 <= move["target_slot"] < target_slot_limit):
        return 1, move, False

    changed = False
    occupied = next(
        (
            raw
            for raw in items
            if raw is not item
            and int(getattr(raw, "slot", -1)) == move["target_slot"]
            and int(getattr(raw, "owner_id", 0) or char.char_id) == target_owner_id
        ),
        None,
    )
    if occupied is not None:
        return 1, move, False

    if int(getattr(item, "owner_id", 0) or char.char_id) != target_owner_id:
        item.owner_id = target_owner_id
        changed = True
    if int(getattr(item, "slot", -1)) != move["target_slot"]:
        item.slot = move["target_slot"]
        changed = True

    if changed:
        db.save()
    return 0, move, changed


def parse_field_position(payload: bytes) -> Optional[tuple[float, float, float, float]]:
    if len(payload) < 17:
        return None
    x, y, z = struct.unpack_from("<fff", payload, 5)
    if abs(x) < 0.0001 and abs(y) < 0.0001 and abs(z) < 0.0001:
        return None
    heading = 0.0
    if len(payload) >= 21:
        heading = float(struct.unpack_from("<I", payload, 17)[0])
    return x, y, z, heading


def save_character_position(char: Optional[Character], payload: bytes) -> Optional[tuple[float, float, float, float]]:
    position = parse_field_position(payload)
    if not char or position is None:
        return position
    char.last_x, char.last_y, char.last_z, char.last_heading = position
    db.save()
    return position


def parse_pq_set_last_town(payload: bytes) -> int:
    if len(payload) < 3:
        return 0
    return struct.unpack_from("<H", payload, 1)[0]


def save_character_last_town(char: Optional[Character], payload: bytes) -> int:
    town_id = parse_pq_set_last_town(payload)
    if char and town_id:
        char.town_id = town_id
        db.save()
    return town_id


def parse_pq_update_max_combo(payload: bytes) -> tuple[int, int]:
    if len(payload) >= 4:
        return payload[1], struct.unpack_from("<H", payload, 2)[0]
    if len(payload) >= 3:
        return 0, struct.unpack_from("<H", payload, 1)[0]
    return 1, 0


def apply_update_max_combo(char: Optional[Character], payload: bytes) -> tuple[int, int, int]:
    request_status, combo = parse_pq_update_max_combo(payload)
    if not char:
        return 1, request_status, combo
    if combo > int(getattr(char, "combo", 0) or 0):
        char.combo = combo
        db.save()
    return 0, request_status, int(getattr(char, "combo", combo) or combo)


def buy_stock_for_character(char: Optional[Character], payload: bytes) -> tuple[int, int, int, list[int]]:
    shop_id, category, item_ids = parse_pq_buy_stock(payload)
    if not char or not item_ids:
        return 1, shop_id, category, item_ids

    added = 0
    if getattr(char, "inventory", None) is None:
        char.inventory = []
    for item_id in item_ids:
        slot = first_free_inventory_slot(char)
        if slot is None:
            break
        char.inventory.append(
            InventoryItem(
                slot=slot,
                item_id=item_id,
                count=1,
                expire_time=DEFAULT_ITEM_EXPIRE_TIME,
                owner_id=char.char_id,
            )
        )
        added += 1

    if added:
        db.save()
    status = 0 if added == len(item_ids) else 1
    return status, shop_id, category, item_ids


def make_pc_update_exp(char: Optional[Character]) -> bytes:
    w = PacketWriter()
    w.write_u8(0)
    w.write_u16(getattr(char, "level", 1) if char else 1)
    w.write_u32(getattr(char, "exp", 0) if char else 0)
    w.write_u32(0)
    w.write_u32(0)
    w.write_u32(0)
    return build_packet(Packet.PcUpdateExp, w.getvalue())


def make_pc_update_skill() -> bytes:
    w = PacketWriter()
    w.write_u8(0)

    # PcUpdateSkill = vector<u16>
    # Known working skill id list from earlier tests.
    skill_ids = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

    w.write_u32(len(skill_ids))
    for skill_id in skill_ids:
        w.write_u16(skill_id)

    return build_packet(Packet.PcUpdateSkill, w.getvalue())

def make_pr_new_character(success: bool, char: Optional[Character] = None) -> bytes:
    w = PacketWriter()
    w.write_u8(0)
    w.write_u8(0 if success else 1)
    if success and char:
        w.write_bytes(make_character_info_vector([char]))
    else:
        w.write_u32(0)
    return build_packet(Packet.PrNewCharacter, w.getvalue())


def make_pr_character_list(chars: list[Character]) -> bytes:
    w = PacketWriter()
    w.write_u8(0)
    w.write_u8(0)
    selected_car_mode = existing_character_list_selected_car_mode()
    w.write_bytes(make_character_info_vector(chars, selected_car_mode))
    return build_packet(Packet.PrNewCharacter, w.getvalue())


def make_pr_del_character(success: bool) -> bytes:
    w = PacketWriter()
    w.write_u8(0)
    w.write_u8(0 if success else 1)
    w.write_u32(0)
    return build_packet(Packet.PrDelCharacter, w.getvalue())


def select_character_object(char_id: int) -> bytes:
    w = PacketWriter()
    w.write_u8(0)
    w.write_u32(char_id)
    return struct.pack("<I", Packet.PqSelectCharacter) + w.getvalue()


def make_pr_select_character_full(
    success: bool,
    char: Optional[Character] = None,
    selected_car_mode: Optional[str] = None,
    tail_zeroes: Optional[int] = None,
    full_tail: bool = False,
    pre_optional_zeroes: int = 0,
    secondary_character_mode: Optional[str] = None,
    secondary_route_mode: Optional[str] = None,
) -> bytes:
    w = PacketWriter()
    w.write_u8(0)
    if success and char:
        car = get_selected_car(char)
        if car is None:
            car = Car(
                car_id=char.selected_car_id or 0,
                model_id=29,
                name="escarabajo",
            )

        w.write_bytes(make_character_info_object(char, selected_car_mode))
        w.write_bytes(
            make_select_secondary_character_object(
                char,
                selected_car_mode,
                secondary_character_mode,
            )
        )
        w.write_bytes(make_car_info_object(car))
        w.write_bytes(make_select_secondary_route_object(char, car, secondary_route_mode))
        w.write_bytes(make_empty_car_inventory_object(car))
    else:
        dummy_char = Character(
            char_id=0,
            account_id=0,
            name="",
            selected_car_id=0,
        )
        dummy_car = Car(car_id=0, model_id=29, name="")
        w.write_bytes(make_character_info_object(dummy_char))
        w.write_bytes(make_select_secondary_character_object(dummy_char))
        w.write_bytes(make_car_info_object(dummy_car))
        w.write_bytes(make_select_secondary_route_object(dummy_char, dummy_car, secondary_route_mode))
        w.write_bytes(make_empty_car_inventory_object(dummy_car))
    if full_tail:
        for _ in range(4):
            w.write_u8(0)
    else:
        if pre_optional_zeroes > 0:
            w.write_bytes(b"\x00" * pre_optional_zeroes)
        for _ in range(4):
            w.write_u8(0)
    if tail_zeroes is None:
        tail_zeroes = 0
    if tail_zeroes > 0:
        w.write_bytes(b"\x00" * tail_zeroes)
    return build_packet(Packet.PrSelectCharacter, w.getvalue())


def make_pr_select_character(
    success: bool,
    char: Optional[Character] = None,
    selected_car_mode: Optional[str] = None,
    tail_zeroes: Optional[int] = None,
    full_tail: bool = False,
    pre_optional_zeroes: int = 0,
    secondary_character_mode: Optional[str] = None,
    secondary_route_mode: Optional[str] = None,
) -> bytes:
    return make_pr_select_character_full(
        success,
        char,
        selected_car_mode,
        tail_zeroes,
        full_tail,
        pre_optional_zeroes,
        secondary_character_mode,
        secondary_route_mode,
    )


def make_pr_enter_channel(success: bool, channel_id: int = 1) -> bytes:
    w = PacketWriter()
    w.write_u8(0)
    w.write_u8(0 if success else 1)
    w.write_u32(channel_id if success else 0)
    return build_packet(Packet.PrEnterChannel, w.getvalue())


def make_pr_enter_field(success: bool, enter_key: int = 1) -> bytes:
    w = PacketWriter()
    w.write_u8(0)
    w.write_u32(enter_key if success else 0)
    w.write_u32(0 if success else 1)
    return build_packet(Packet.PrEnterField, w.getvalue())


# ─── Session handler ──────────────────────────────────────────────────────────

class LoginSession:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.buf = PacketBuffer()
        self.account: Optional[Account] = None
        self.character: Optional[Character] = None
        self.pending_character_name: Optional[str] = None
        self.game_agent_list_sent = False
        self.had_existing_characters_at_login = False
        peer = writer.get_extra_info("peername")
        self.peer = f"{peer[0]}:{peer[1]}" if peer else "?"
    def send(self, data: bytes):
        if self.writer.is_closing():
            raise ConnectionResetError(f"connection already closing for {self.peer}")
        self.writer.write(data)

    async def send_login_exp_update(self, reason: str) -> None:
        char = self.character or db.latest_character()
        if char:
            self.character = char
        try:
            response = make_pc_update_exp(char)
            self.send(response)
            await self.writer.drain()
        except Exception as e:
            logger.exception("Failed to send login PcUpdateExp for %s: %s", self.peer, e)
            return
        logger.info(
            "SENT PcUpdateExp on login socket reason=%s selected_id=%s response_len=%d to %s",
            reason,
            char.char_id if char else None,
            len(response),
            self.peer,
        )

    async def send_login_skill_update(self, reason: str) -> None:
        try:
            response = make_pc_update_skill()
            self.send(response)
            await self.writer.drain()
        except Exception as e:
            logger.exception("Failed to send login PcUpdateSkill for %s: %s", self.peer, e)
            return
        logger.info(
            "SENT PcUpdateSkill on login socket reason=%s response_len=%d to %s",
            reason,
            len(response),
            self.peer,
        )

    async def send_login_inventory_update(self, reason: str, char: Optional[Character] = None) -> None:
        char = char or self.character or db.latest_character()
        if char:
            self.character = char

        owner_ids: list[int] = []
        if char:
            owner_ids.append(int(char.char_id))
            selected_car = get_selected_car(char)
            selected_car_id = int(getattr(selected_car, "car_id", 0) or getattr(char, "selected_car_id", 0) or 0)
            if selected_car_id and selected_car_id not in owner_ids:
                owner_ids.append(selected_car_id)

        if not owner_ids:
            owner_ids = [0]

        try:
            total_len = 0
            for owner_id in owner_ids:
                response = make_pc_update_inventory(char, owner_id)
                self.send(response)
                total_len += len(response)
            await self.writer.drain()
        except Exception as e:
            logger.exception("Failed to send login PcUpdateInventory for %s: %s", self.peer, e)
            return

        logger.info(
            "SENT PcUpdateInventory on login socket reason=%s selected_id=%s owners=%s total_len=%d to %s",
            reason,
            char.char_id if char else None,
            owner_ids,
            total_len,
            self.peer,
        )

    def send_game_agent_list(self, reason: str, force: bool = False) -> bool:
        if self.game_agent_list_sent and not force:
            return False
        if self.writer.is_closing():
            logger.info(
                "SKIP PcGameAgentList reason=%s: connection already closing for %s",
                reason,
                self.peer,
            )
            return False
        agent_id = allocate_game_agent_id()
        agent_list = make_pc_game_agent_list(agent_id=agent_id)
        try:
            self.send(agent_list)
        except (ConnectionResetError, BrokenPipeError):
            logger.info(
                "SKIP PcGameAgentList reason=%s: connection lost for %s",
                reason,
                self.peer,
            )
            return False
        self.game_agent_list_sent = True
        logger.info(
            "SENT PcGameAgentList reason=%s len=%d agent=race id=%d endpoint=127.0.0.1:2181 to %s",
            reason,
            len(agent_list),
            agent_id,
            self.peer,
        )
        logger.debug(
            "PcGameAgentList raw to %s: %s",
            self.peer,
            agent_list[:128].hex(" ") if agent_list else "",
        )
        return True

    async def send_select_character_response_later(self, raw_char_id: int, char: Character):
        try:
            selected_car_mode = "model" if self.had_existing_characters_at_login else None
            select_tail_zeroes = 0 if self.had_existing_characters_at_login else None
            select_full_tail = False
            select_pre_optional_zeroes = 0
            select_secondary_character_mode = "inventory" if self.had_existing_characters_at_login else None
            select_secondary_route_mode = "inventory" if self.had_existing_characters_at_login else None
            response = make_pr_select_character(
                True,
                char,
                selected_car_mode,
                select_tail_zeroes,
                select_full_tail,
                select_pre_optional_zeroes,
                select_secondary_character_mode,
                select_secondary_route_mode,
            )
            self.send(response)
            await self.writer.drain()
            logger.info(
                "PqSelectCharacter raw_id=%d selected_id=%d name=%r response_len=%d selected_car_mode=%s tail_zeroes=%s full_tail=%s pre_optional_zeroes=%d secondary=%s route_secondary=%s from %s",
                raw_char_id,
                char.char_id,
                char.name,
                len(response),
                selected_car_mode,
                select_tail_zeroes,
                select_full_tail,
                select_pre_optional_zeroes,
                select_secondary_character_mode,
                select_secondary_route_mode,
                self.peer,
            )
            logger.debug(
                "PrSelectCharacter raw to %s: %s",
                self.peer,
                response[:256].hex(" ") if response else "",
            )
            await self.send_login_skill_update("select_character")
            await self.send_login_inventory_update("select_character", char)
            if self.writer.is_closing():
                logger.info(
                    "Select character post-send aborted: connection already closing for %s",
                    self.peer,
                )
                return
            if self.account:
                try:
                    from src.network.udp_server import update_udp_enter_key

                    update_udp_enter_key(
                        self.account.account_id,
                        char.char_id,
                        "select_character",
                    )
                except Exception:
                    logger.debug("Could not arm UDP enter key after select", exc_info=True)
            await self.writer.drain()

        except (ConnectionResetError, BrokenPipeError):
            logger.info("Select character response aborted: connection lost for %s", self.peer)

    async def send_new_character_response_later(
        self,
        success: bool,
        char: Optional[Character],
        reason: str,
    ):
        try:
            response = make_pr_new_character(success, char)
            self.send(response)
            await self.writer.drain()
            logger.info(
                "SENT PrNewCharacter len=%d class=0x%08X success=%s char_id=%s reason=%s to %s",
                len(response),
                Packet.PrNewCharacter,
                success,
                char.char_id if char else None,
                reason,
                self.peer,
            )
        except (ConnectionResetError, BrokenPipeError):
            logger.info("New character response aborted: connection lost for %s", self.peer)

    async def send_existing_character_list_later(self, send_agent_list_after: bool = False):
        try:
            if not self.account or not self.account.characters:
                return
            if not self.account or not self.account.characters:
                return
            response = make_pr_character_list(self.account.characters)
            self.send(response)
            await self.writer.drain()
            selected_char = account_character(self.account)
            selected_car = get_selected_car(selected_char) if selected_char else None
            logger.info(
                "SENT existing character list len=%d count=%d selected=%s selected_car_mode=%s car_id=%s model=%s grade=%s to %s",
                len(response),
                len(self.account.characters),
                self.account.selected_char_id,
                existing_character_list_selected_car_mode(),
                selected_car.car_id if selected_car else None,
                car_model_id(selected_car) if selected_car else None,
                car_grade(selected_car) if selected_car else None,
                self.peer,
            )
        except (ConnectionResetError, BrokenPipeError):
            logger.info("Existing character list aborted: connection lost for %s", self.peer)

    async def run(self):
        logger.info("Client connected: %s", self.peer)
        ACTIVE_LOGIN_SESSIONS.add(self)
        try:
            first_accept = make_pc_first_accept()
            self.send(first_accept)
            await self.writer.drain()
            logger.info(
                "SENT PcFirstAccept len=%d class=0x%08X to %s",
                len(first_accept),
                Packet.PcFirstAccept,
                self.peer,
            )
            while True:
                data = await asyncio.wait_for(self.reader.read(4096), timeout=120.0)
                if not data:
                    break
                self.buf.feed(data)
                for pkt_type, payload in self.buf.packets():
                    self.handle(pkt_type, payload)
                await self.writer.drain()
        except asyncio.TimeoutError:
            logger.info("Client timeout: %s", self.peer)
        except ConnectionResetError:
            pass
        except Exception as e:
            logger.exception("Session error (%s): %s", self.peer, e)
        finally:
            logger.info("Client disconnected: %s", self.peer)
            ACTIVE_LOGIN_SESSIONS.discard(self)
            self.writer.close()

    def handle(self, pkt_type: int, payload: bytes):
        pkt_name = packet_name(pkt_type)
        logger.debug(
            "RECV %s class=0x%08X body_len=%d head=%s from %s",
            pkt_name,
            pkt_type,
            len(payload),
            payload[:32].hex(" "),
            self.peer,
        )

        if pkt_type == Packet.PqFirstPacket:
            self.on_first_packet(payload)
        elif pkt_type == Packet.PqLoginAgent:
            self.on_login_agent(payload)
        elif pkt_type == Packet.PqUserLogin:
            self.on_user_login(payload)
        elif pkt_type == Packet.PqCheckExistCharacter:
            self.on_check_exist_char(payload)
        elif pkt_type == Packet.PqNewCharacter:
            self.on_new_character(payload)
        elif pkt_type == Packet.PqDelCharacter:
            self.on_del_character(payload)
        elif pkt_type == Packet.PqSelectCharacter:
            self.on_select_character(payload)
        elif pkt_type == Packet.PqGetCarList:
            self.on_get_car_list(payload)
        elif pkt_type == Packet.PqGetCarInfo:
            self.on_get_car_info(payload)
        elif pkt_type == Packet.PqSelectCar:
            self.on_select_car(payload)
        elif pkt_type == Packet.PqGetInventory:
            self.on_get_inventory(payload)
        elif pkt_type == Packet.PqBuyStock:
            self.on_buy_stock(payload)
        elif pkt_type == Packet.PqMoveInventoryItem:
            self.on_move_inventory_item(payload)
        elif pkt_type == Packet.PqMoveField:
            self.on_move_field(payload)
        elif pkt_type == Packet.PqSetLastTown:
            self.on_set_last_town(payload)
        elif pkt_type == Packet.PqUpdateMaxCombo:
            self.on_update_max_combo(payload)
        elif pkt_type == Packet.PqEnterField:
            logger.info("PqEnterField on login socket len=%d head=%s from %s",
                        len(payload), payload[:32].hex(" "), self.peer)
        elif pkt_type == Packet.PqLeaveField:
            logger.info("PqLeaveField on login socket from %s", self.peer)
        elif pkt_type == Packet.PqEnterChannel:
            self.on_enter_channel(payload)
        elif pkt_type == Packet.PqKeepAlive:
            pass  # silently drop
        else:
            logger.warning(
                "Unhandled packet class=0x%08X name=%s len=%d head=%s",
                pkt_type,
                pkt_name,
                len(payload),
                payload[:64].hex(" "),
            )

    # ─── Packet handlers ──────────────────────────────────────────────────────

    def on_first_packet(self, payload: bytes):
        if len(payload) >= 5:
            base_flag = payload[0]
            field20 = struct.unpack_from("<I", payload, 1)[0]
            logger.info(
                "PqFirstPacket from %s body_len=%d base=%d field20=0x%08X/%d",
                self.peer,
                len(payload),
                base_flag,
                field20,
                field20,
            )
        else:
            logger.info("PqFirstPacket from %s body_len=%d", self.peer, len(payload))
        response = make_pr_first_packet()
        self.send(response)
        logger.info(
            "SENT PrFirstPacket len=%d class=0x%08X status=0 version=0x052D to %s",
            len(response),
            Packet.PrFirstPacket,
            self.peer,
        )

    def on_login_agent(self, payload: bytes):
        # Client sends some token/agent info — accept unconditionally for now
        logger.info("PqLoginAgent from %s (len=%d)", self.peer, len(payload))
        response = make_pr_login_agent(success=True)
        self.send(response)
        logger.info(
            "SENT PrLoginAgent len=%d class=0x%08X success=True to %s",
            len(response),
            Packet.PrLoginAgent,
            self.peer,
        )
    def on_user_login(self, payload: bytes):
        if len(payload) < 32:
            logger.warning("Malformed PqUserLogin from %s", self.peer)
            self.send(make_pr_user_login(None, False))
            return
        username = login_username_from_payload(payload)
        password = login_password_from_payload(payload)
        logger.info("PqUserLogin user=%r from %s", username, self.peer)
        self.account = db.authenticate(username, password)
        self.had_existing_characters_at_login = bool(self.account and self.account.characters)
        response = make_pr_user_login(self.account, self.account is not None)
        self.send(response)
        logger.info(
            "SENT PrUserLogin len=%d class=0x%08X success=%s account_id=%s udp_enter_key=%s to %s",
            len(response),
            Packet.PrUserLogin,
            self.account is not None,
            self.account.account_id if self.account else None,
            self.account.account_id if self.account else None,
            self.peer,
        )
        if self.account:
            try:
                from src.network.udp_server import update_udp_enter_key

                update_udp_enter_key(
                    self.account.account_id,
                    self.account.selected_char_id or 0,
                    "pr_user_login",
                )
            except Exception:
                logger.debug("Could not arm UDP enter key after PrUserLogin", exc_info=True)
        has_existing_characters = self.had_existing_characters_at_login
        send_existing_character_list = has_existing_characters
        send_agent_list_on_login = self.account is not None
        if send_agent_list_on_login and not send_existing_character_list:
            self.send_game_agent_list("user_login")
        if send_existing_character_list:
            asyncio.create_task(
                self.send_existing_character_list_later(
                    send_agent_list_after=bool(send_agent_list_on_login)
                )
            )

    def on_check_exist_char(self, payload: bytes):
        name = extract_name_candidate(payload) or f"Player{db.next_char_id_hint()}"
        self.pending_character_name = name
        exists = db.check_name_exists(name)
        logger.info(
            "PqCheckExistCharacter name=%r exists=%s body_len=%d head=%s",
            name,
            exists,
            len(payload),
            payload[:48].hex(" "),
        )
        self.send(make_pr_check_exist_char(exists))

    def on_new_character(self, payload: bytes):
        if not self.account:
            asyncio.create_task(
                self.send_new_character_response_later(False, None, "no_account")
            )
            return
        name = self.pending_character_name or extract_name_candidate(payload)
        if not name:
            name = f"Player{db.next_char_id_hint()}"
        gender = 0
        appearance_code, appearance_unknown_value = read_pq_new_character_appearance(payload)
        combo = DEFAULT_COMBO
        unknown_value = DEFAULT_UNKNOWN_VALUE
        logger.info(
            "PqNewCharacter name=%r gender=%d appearance_code=%d appearance_unknown_value=%d combo=%d unknown_value=%d body_len=%d head=%s",
            name,
            gender,
            appearance_code,
            appearance_unknown_value,
            combo,
            unknown_value,
            len(payload),
            payload[:64].hex(" "),
        )
        if db.check_name_exists(name):
            existing = account_character_by_name(self.account, name)
            if existing:
                self.account.selected_char_id = existing.char_id
                self.character = existing
                db.save()
                asyncio.create_task(
                    self.send_new_character_response_later(
                        True, existing, "duplicate_same_account"
                    )
                )
            else:
                asyncio.create_task(
                    self.send_new_character_response_later(False, None, "duplicate_name")
                )
            return
        char = db.create_character(self.account, name, gender, combo, unknown_value)
        self.account.selected_char_id = char.char_id
        self.character = char
        self.pending_character_name = None
        asyncio.create_task(
            self.send_new_character_response_later(True, char, "created")
        )

    def on_del_character(self, payload: bytes):
        if not self.account:
            self.send(make_pr_del_character(False))
            return
        char_id = read_base_u32(payload)
        success = db.delete_character(self.account, char_id)
        self.send(make_pr_del_character(success))

    def on_select_character(self, payload: bytes):
        if not self.account:
            self.send(make_pr_select_character(False))
            return
        char_id = read_base_u32(payload)
        char = account_character(self.account, char_id)
        if char:
            self.account.selected_char_id = char.char_id
            self.character = char
            db.save()
            asyncio.create_task(self.send_select_character_response_later(char_id, char))
        else:
            self.send(make_pr_select_character(False))
            logger.info(
                "PqSelectCharacter raw_id=%d failed: no character for account=%d",
                char_id,
                self.account.account_id,
            )

    def on_get_car_list(self, payload: bytes):
        if not self.account:
            self.send(make_pr_get_car_list(None))
            return
        char_id = read_base_u32(payload)
        char = account_character(self.account, char_id)
        if char:
            self.character = char
        response = make_pr_get_car_list(char)
        self.send(response)
        logger.info(
            "PqGetCarList char_id=%d cars=%d response_len=%d to %s",
            char_id,
            len(char.cars) if char else 0,
            len(response),
            self.peer,
        )

    def on_get_car_info(self, payload: bytes):
        if not self.account:
            self.send(make_pr_get_car_info(False))
            return
        char_id, requested_car_id, flag = read_pq_get_car_info(payload)
        char = account_character(self.account, char_id)
        car = get_selected_car(char, requested_car_id) if char else None
        if char and car:
            self.character = char
        response = make_pr_get_car_info(car is not None, car, char)
        self.send(response)
        logger.info(
            "PqGetCarInfo char_id=%d requested_car_id=%d flag=%d selected_car_id=%s model=%s grade=%s response_len=%d to %s",
            char_id,
            requested_car_id,
            flag,
            car.car_id if car else None,
            car_model_id(car) if car else None,
            car_grade(car) if car else None,
            len(response),
            self.peer,
        )

    def on_select_car(self, payload: bytes):
        if not self.account:
            self.send(make_pr_select_car(False))
            return

        requested_car_id = read_base_u32(payload)
        char = account_character(self.account, 0)
        car = get_selected_car(char, requested_car_id) if char else None

        if char and car:
            self.character = char
            char.selected_car_id = car.car_id
            db.save()
            response = make_pr_select_car(True, car, char)
            self.send(response)
            logger.info(
                "PqSelectCar requested_car_id=%d selected_car_id=%d model=%d grade=%d response_len=%d to %s",
                requested_car_id,
                car.car_id,
                car_model_id(car),
                car_grade(car),
                len(response),
                self.peer,
            )
        else:
            response = make_pr_select_car(False)
            self.send(response)
            logger.warning(
                "PqSelectCar requested_car_id=%d failed: no car for account=%s response_len=%d to %s",
                requested_car_id,
                self.account.account_id if self.account else None,
                len(response),
                self.peer,
            )

    def on_get_inventory(self, payload: bytes):
        if not self.account:
            self.send(make_pr_get_inventory(None))
            return
        owner_id = read_base_u32(payload)
        char = account_character(self.account, owner_id)
        if not char:
            selected = account_character(self.account, self.account.selected_char_id)
            if selected and (owner_id == 0 or owner_is_car_inventory(selected, owner_id)):
                char = selected
        if char:
            self.character = char
        response = make_pr_get_inventory(char, owner_id)
        self.send(response)
        logger.info(
            "PqGetInventory owner_id=%d selected_id=%s slots=%d response_len=%d to %s",
            owner_id,
            char.char_id if char else None,
            inventory_slots_for_owner(char, owner_id) if char else DEFAULT_INVENTORY_SLOTS,
            len(response),
            self.peer,
        )

    def on_buy_stock(self, payload: bytes):
        char = self.character
        if self.account:
            char = account_character(self.account, self.account.selected_char_id) or char
        if not char:
            char = db.latest_character()
        if char:
            self.character = char

        status, shop_id, category, item_ids = buy_stock_for_character(char, payload)
        ack = make_pr_buy_stock(status)
        self.send(ack)
        if status == 0 and char:
            inv = make_pc_update_inventory(char, char.char_id)
            money = make_pc_update_money(char)
            self.send(inv)
            self.send(money)
            update_len = len(inv) + len(money)
        else:
            update_len = 0
        logger.info(
            "PqBuyStock shop=%d category=%d items=%s status=%d selected_id=%s ack_len=%d update_len=%d to %s",
            shop_id,
            category,
            item_ids,
            status,
            char.char_id if char else None,
            len(ack),
            update_len,
            self.peer,
        )

    def on_move_inventory_item(self, payload: bytes):
        char = self.character
        if self.account:
            char = account_character(self.account, self.account.selected_char_id) or char
        if not char:
            char = db.latest_character()
        if char:
            self.character = char
        status, move, changed = apply_move_inventory_item(char, payload)
        ack = make_pr_move_inventory_item(status)
        self.send(ack)
        update_len = 0
        if changed and char:
            update_len = 0
            owner_ids = []
            for owner_id in (
                move["source_owner_id"] or char.char_id,
                move["target_owner_id"] or char.char_id,
            ):
                if owner_id not in owner_ids:
                    owner_ids.append(owner_id)
            for owner_id in owner_ids:
                inv = make_pc_update_inventory(char, owner_id)
                self.send(inv)
                update_len += len(inv)
        logger.info(
            "PqMoveInventoryItem status=%d changed=%s move=%s selected_id=%s ack_len=%d update_len=%d to %s",
            status,
            changed,
            move,
            char.char_id if char else None,
            len(ack),
            update_len,
            self.peer,
        )

    def on_move_field(self, payload: bytes):
        char = self.character
        if self.account:
            char = account_character(self.account, self.account.selected_char_id) or char
        if not char:
            char = db.latest_character()
        if char:
            self.character = char
        position = save_character_position(char, payload)
        if position is not None:
            logger.info(
                "PqMoveField selected_id=%s x=%.3f y=%.3f z=%.3f heading=%.3f from %s",
                char.char_id if char else None,
                position[0],
                position[1],
                position[2],
                position[3],
                self.peer,
            )

    def on_set_last_town(self, payload: bytes):
        char = self.character
        if self.account:
            char = account_character(self.account, self.account.selected_char_id) or char
        if not char:
            char = db.latest_character()
        if char:
            self.character = char
        town_id = save_character_last_town(char, payload)
        logger.info(
            "PqSetLastTown selected_id=%s town_id=%d from %s",
            char.char_id if char else None,
            town_id,
            self.peer,
        )

    def on_update_max_combo(self, payload: bytes):
        char = self.character
        if self.account:
            char = account_character(self.account, self.account.selected_char_id) or char
        if not char:
            char = db.latest_character()
        if char:
            self.character = char
        status, request_status, combo = apply_update_max_combo(char, payload)
        response = make_pr_update_max_combo(status, combo)
        self.send(response)
        logger.info(
            "PqUpdateMaxCombo request_status=%d status=%d combo=%d selected_id=%s response_len=%d to %s",
            request_status,
            status,
            combo,
            char.char_id if char else None,
            len(response),
            self.peer,
        )

    def on_enter_channel(self, payload: bytes):
        logger.info("PqEnterChannel body_len=%d head=%s from %s",
                    len(payload), payload[:32].hex(" "), self.peer)
        self.send(make_pr_enter_channel(True, channel_id=1))


# ─── Server entry point ───────────────────────────────────────────────────────

async def start_login_server(host: str = "0.0.0.0", port: int = 2180):
    server = await asyncio.start_server(
        lambda r, w: LoginSession(r, w).run(), host, port
    )
    logger.info("Login server listening on %s:%d", host, port)
    return server
