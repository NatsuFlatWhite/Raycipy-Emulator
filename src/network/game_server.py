import asyncio
import logging
import os
import time
from typing import Optional

from src.game.database import db, Character
from src.packets.protocol import (
    PacketBuffer,
    PacketReader,
    PacketWriter,
    build_packet,
    make_pr_first_packet as build_pr_first_packet,
)
from src.packets.packet_registry import Packet, packet_name

logger = logging.getLogger("GameServer")
ACTIVE_GAME_SESSIONS = set()


_FIXED_GAME_AGENT_ID = os.environ.get("RAYCITY_GAME_AGENT_ID")
GAME_AGENT_ID = (
    int(_FIXED_GAME_AGENT_ID)
    if _FIXED_GAME_AGENT_ID
    else (int(time.time()) & 0x7FFFFFFF) or 1
)


def get_game_agent_id() -> int:
    return GAME_AGENT_ID


def allocate_game_agent_id() -> int:
    global GAME_AGENT_ID
    if _FIXED_GAME_AGENT_ID:
        return GAME_AGENT_ID
    GAME_AGENT_ID = (GAME_AGENT_ID + 1) & 0x7FFFFFFF
    if GAME_AGENT_ID == 0:
        GAME_AGENT_ID = 1
    return GAME_AGENT_ID


import time as _time


def read_base_u32(payload: bytes, default: int = 0) -> int:
    if len(payload) >= 5:
        return int.from_bytes(payload[1:5], "little")
    if len(payload) >= 4:
        return int.from_bytes(payload[:4], "little")
    return default


def read_base_u32_index(payload: bytes, index: int, default: int = 0) -> int:
    offset = 1 + index * 4
    if len(payload) >= offset + 4:
        return int.from_bytes(payload[offset:offset + 4], "little")
    if index == 0:
        return read_base_u32(payload, default)
    return default


def env_enabled(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


def latest_character() -> Optional[Character]:
    return db.latest_character()


def write_utf16_string(w: PacketWriter, text: str):
    encoded = text.encode("utf-16le", errors="replace")
    w.write_u32(len(encoded) // 2)
    w.write_bytes(encoded)


def ip_to_wire_u32(ip: str) -> int:
    octets = bytes(int(part) & 0xFF for part in ip.split("."))
    return int.from_bytes(octets, "little")


def make_pc_game_agent_list(ip: str = "127.0.0.1", port: int = 2181) -> bytes:
    w = PacketWriter()
    w.write_u8(0)
    w.write_u32(1)
    write_utf16_string(w, "race")
    w.write_u32(GAME_AGENT_ID)
    w.write_u32(ip_to_wire_u32(ip))
    w.write_u16(port)
    return build_packet(Packet.PcGameAgentList, w.getvalue())


def make_pr_login_agent(success: bool = True, agent_key: Optional[int] = None) -> bytes:
    w = PacketWriter()
    # The game-agent handler treats status 0 as success.  The u32 is the
    # PcGameAgentList item id used to find the pending agent entry.
    if agent_key is None:
        agent_key = get_game_agent_id()
    w.write_u8(0)
    w.write_u8(0 if success else 1)
    w.write_u32(agent_key)
    allowed_packets = [Packet.PqEnterField] if success else []
    w.write_u32(len(allowed_packets))
    for packet_id in allowed_packets:
        w.write_u32(packet_id)
    return build_packet(Packet.PrLoginAgent, w.getvalue())


def make_pr_enter_field(success: bool, enter_key: int = 1) -> bytes:
    w = PacketWriter()
    w.write_u8(0)
    # PrEnterField serializes two u32s after Object base: object+0x20 is the
    # key the login state compares, object+0x24 is the status.
    w.write_u32(enter_key if success else 0)
    w.write_u32(0 if success else 1)
    return build_packet(Packet.PrEnterField, w.getvalue())


def choose_enter_field_key(
    request_key: int,
    selected_char_id: int,
    profile_key: int,
    response_agent_id: int,
) -> tuple[int, str]:
    # PqLoginAgent +0x28 profile key is the key compared by the login-state
    # PrEnterField branch.
    return profile_key or request_key or selected_char_id or 1, "profile_key"


def make_pr_get_race_list(races: list) -> bytes:
    w = PacketWriter()
    w.write_u16(len(races))
    for race in races:
        w.write_u32(race["id"])
        w.write_str_fixed(race["name"], 32)
        w.write_u8(race["track_id"])
        w.write_u8(race["laps"])
        w.write_u8(race["current_players"])
        w.write_u8(race["max_players"])
        w.write_u8(1 if race["is_open"] else 0)
    return build_packet(Packet.PrGetRaceList, w.getvalue())


def make_pr_time_sync(server_time: int) -> bytes:
    w = PacketWriter()
    w.write_u32(server_time)
    return build_packet(Packet.PrTimeSync, w.getvalue())


# ─── Session ──────────────────────────────────────────────────────────────────

class GameSession:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 channel_id: int = 1):
        self.reader = reader
        self.writer = writer
        self.buf = PacketBuffer()
        self.char: Optional[Character] = None
        self.channel_id = channel_id
        self.enter_field_response_sent = False
        self.client_enter_field_seen = False
        peer = writer.get_extra_info("peername")
        self.peer = f"{peer[0]}:{peer[1]}" if peer else "?"
    def send(self, data: bytes):
        self.writer.write(data)

    async def send_login_agent_frame(self, reason: str, agent_key: Optional[int] = None) -> bool:
        if self.writer.is_closing():
            return False
        if agent_key is None:
            agent_key = get_game_agent_id()
        response = make_pr_login_agent(success=True, agent_key=agent_key)
        self.send(response)
        await self.writer.drain()
        logger.info(
            "SENT PrLoginAgent reason=%s len=%d class=0x%08X status=0 agent_key=%d allowed=PqEnterField to %s",
            reason,
            len(response),
            Packet.PrLoginAgent,
            agent_key,
            self.peer,
        )
        return True

    async def send_enter_field_frame(self, reason: str, enter_key: int) -> bool:
        if self.writer.is_closing():
            return False
        response = make_pr_enter_field(True, enter_key if enter_key else 1)
        self.send(response)
        await self.writer.drain()
        logger.info(
            "SENT PrEnterField reason=%s len=%d class=0x%08X status=0 enter_key=%d to %s",
            reason,
            len(response),
            Packet.PrEnterField,
            enter_key if enter_key else 1,
            self.peer,
        )
        return True

    async def send_enter_field_accept(self, reason: str, enter_key: int) -> bool:
        if self.enter_field_response_sent or self.writer.is_closing():
            return False
        sent = await self.send_enter_field_frame(reason, enter_key)
        if not sent:
            return False
        self.enter_field_response_sent = True
        return True

    async def run(self):
        logger.info("Game client connected: %s", self.peer)
        ACTIVE_GAME_SESSIONS.add(self)
        try:
            logger.info("Waiting for client game-agent packets from %s", self.peer)
            while True:
                data = await asyncio.wait_for(self.reader.read(4096), timeout=120.0)
                if not data:
                    break
                if env_enabled("RAYCITY_GAME_RAW_LOG", "0"):
                    logger.info(
                        "RAW game-agent data len=%d head=%s from %s",
                        len(data),
                        data[:64].hex(" "),
                        self.peer,
                    )
                self.buf.feed(data)
                for pkt_type, payload in self.buf.packets():
                    await self.handle(pkt_type, payload)
                await self.writer.drain()
        except asyncio.TimeoutError:
            logger.info("Game client timeout: %s", self.peer)
        except ConnectionResetError:
            pass
        except Exception as e:
            logger.exception("Game session error (%s): %s", self.peer, e)
        finally:
            logger.info("Game client disconnected: %s", self.peer)
            ACTIVE_GAME_SESSIONS.discard(self)
            self.writer.close()

    async def handle(self, pkt_type: int, payload: bytes):
        pkt_name = packet_name(pkt_type)
        logger.debug(
            "RECV %s class=0x%08X len=%d head=%s from %s",
            pkt_name,
            pkt_type,
            len(payload),
            payload[:32].hex(" "),
            self.peer,
        )

        if pkt_type == Packet.PqFirstPacket:
            self.on_first_packet(payload)
        elif pkt_type == Packet.PqLoginAgent:
            await self.on_login_agent(payload)
        elif pkt_type == Packet.PqEnterField:
            await self.on_enter_field(payload)
        elif pkt_type == Packet.PqLeaveField:
            logger.info("PqLeaveField from %s", self.peer)
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
        elif pkt_type == Packet.PqGetRaceList:
            self.on_get_race_list(payload)
        elif pkt_type == Packet.PqMakeRace:
            self.on_make_race(payload)
        elif pkt_type == Packet.PqJoinRace:
            self.on_join_race(payload)
        elif pkt_type == Packet.PqLeaveRace:
            logger.info("PqLeaveRace from %s", self.peer)
        elif pkt_type == Packet.PqTimeSync:
            self.on_time_sync(payload)
        elif pkt_type == Packet.PqKeepAlive:
            pass
        else:
            logger.warning(
                "Unhandled game packet class=0x%08X name=%s len=%d head=%s",
                pkt_type,
                pkt_name,
                len(payload),
                payload[:64].hex(" "),
            )

    def on_first_packet(self, payload: bytes):
        if len(payload) >= 5:
            base_flag = payload[0]
            field20 = int.from_bytes(payload[1:5], "little")
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
        response = build_pr_first_packet()
        self.send(response)
        logger.info(
            "SENT PrFirstPacket len=%d class=0x%08X status=0 version=0x052D to %s",
            len(response),
            Packet.PrFirstPacket,
            self.peer,
        )

    async def on_login_agent(self, payload: bytes):
        request_key = read_base_u32(payload)
        selected_char_id = read_base_u32_index(payload, 1)
        profile_key = read_base_u32_index(payload, 2)
        response_agent_id = get_game_agent_id()
        enter_key, enter_key_mode = choose_enter_field_key(
            request_key,
            selected_char_id,
            profile_key,
            response_agent_id,
        )
        logger.info(
            "PqLoginAgent from %s len=%d request_key=%d selected_char_id=%d profile_key=%d response_agent_id=%d enter_key=%d enter_key_mode=%s",
            self.peer,
            len(payload),
            request_key,
            selected_char_id,
            profile_key,
            response_agent_id,
            enter_key,
            enter_key_mode,
        )
        if self.writer.is_closing():
            logger.info("SKIP PrLoginAgent: connection already closing for %s", self.peer)
            return
        sent_login_agent = await self.send_login_agent_frame(
            "client_pq_login_agent",
            response_agent_id,
        )
        if not sent_login_agent:
            return

    async def on_enter_field(self, payload: bytes):
        self.client_enter_field_seen = True
        enter_key = read_base_u32(payload)
        self.char = db.get_character(enter_key) if enter_key else latest_character()
        if not self.char:
            self.char = latest_character()
        logger.info(
            "PqEnterField enter_key=%d selected_id=%s from %s",
            enter_key,
            self.char.char_id if self.char else None,
            self.peer,
        )
        await self.send_enter_field_accept("client_pq_enter_field", enter_key if enter_key else 1)
        self.send_exp_update("enter_field")
        self.send_skill_update("enter_field")
        self.send_inventory_update("enter_field")

    def on_get_race_list(self, payload: bytes):
        self.send(make_pr_get_race_list([]))

    def on_get_inventory(self, payload: bytes):
        owner_id = read_base_u32(payload)
        char = db.get_character(owner_id) if owner_id else self.char or latest_character()
        if not char:
            selected = self.char or latest_character()
            if selected and any(int(getattr(car, "car_id", 0) or 0) == owner_id for car in selected.cars):
                char = selected
        if char:
            self.char = char
        try:
            from src.network.login_server import make_pr_get_inventory

            response = make_pr_get_inventory(char, owner_id)
        except Exception as e:
            logger.exception("Failed to build PrGetInventory for %s: %s", self.peer, e)
            return
        self.send(response)
        logger.info(
            "PqGetInventory owner_id=%d selected_id=%s response_len=%d to %s",
            owner_id,
            char.char_id if char else None,
            len(response),
            self.peer,
        )

    def on_buy_stock(self, payload: bytes):
        char = self.char or latest_character()
        if char:
            self.char = char
        try:
            from src.network.login_server import (
                buy_stock_for_character,
                make_pc_update_inventory,
                make_pc_update_money,
                make_pr_buy_stock,
            )

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
        except Exception as e:
            logger.exception("Failed to handle PqBuyStock for %s: %s", self.peer, e)
            return
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
        char = self.char or latest_character()
        if char:
            self.char = char
        try:
            from src.network.login_server import (
                apply_move_inventory_item,
                make_pc_update_inventory,
                make_pr_move_inventory_item,
            )

            status, move, changed = apply_move_inventory_item(char, payload)
            ack = make_pr_move_inventory_item(status)
            self.send(ack)
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
            else:
                update_len = 0
        except Exception as e:
            logger.exception("Failed to handle PqMoveInventoryItem for %s: %s", self.peer, e)
            return
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
        char = self.char or latest_character()
        if char:
            self.char = char
        try:
            from src.network.login_server import save_character_position

            position = save_character_position(char, payload)
        except Exception as e:
            logger.exception("Failed to save PqMoveField for %s: %s", self.peer, e)
            return
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
        char = self.char or latest_character()
        if char:
            self.char = char
        try:
            from src.network.login_server import save_character_last_town

            town_id = save_character_last_town(char, payload)
        except Exception as e:
            logger.exception("Failed to save PqSetLastTown for %s: %s", self.peer, e)
            return
        logger.info(
            "PqSetLastTown selected_id=%s town_id=%d from %s",
            char.char_id if char else None,
            town_id,
            self.peer,
        )

    def on_update_max_combo(self, payload: bytes):
        char = self.char or latest_character()
        if char:
            self.char = char
        try:
            from src.network.login_server import apply_update_max_combo, make_pr_update_max_combo

            status, request_status, combo = apply_update_max_combo(char, payload)
            response = make_pr_update_max_combo(status, combo)
            self.send(response)
        except Exception as e:
            logger.exception("Failed to handle PqUpdateMaxCombo for %s: %s", self.peer, e)
            return
        logger.info(
            "PqUpdateMaxCombo request_status=%d status=%d combo=%d selected_id=%s response_len=%d to %s",
            request_status,
            status,
            combo,
            char.char_id if char else None,
            len(response),
            self.peer,
        )

    def send_exp_update(self, reason: str) -> None:
        char = self.char or latest_character()
        if char:
            self.char = char
        try:
            from src.network.login_server import make_pc_update_exp

            response = make_pc_update_exp(char)
        except Exception as e:
            logger.exception("Failed to build PcUpdateExp for %s: %s", self.peer, e)
            return
        self.send(response)
        logger.info(
            "SENT PcUpdateExp reason=%s selected_id=%s response_len=%d to %s",
            reason,
            char.char_id if char else None,
            len(response),
            self.peer,
        )

    def send_inventory_update(self, reason: str) -> None:
        char = self.char or latest_character()
        if char:
            self.char = char

        try:
            from src.network.login_server import make_pc_update_inventory

            owner_ids = []

            if char:
                owner_ids.append(char.char_id)

                selected_car_id = int(getattr(char, "selected_car_id", 0) or 0)
                if selected_car_id and selected_car_id not in owner_ids:
                    owner_ids.append(selected_car_id)

            if not owner_ids:
                owner_ids = [0]

            total_len = 0
            for owner_id in owner_ids:
                response = make_pc_update_inventory(char, owner_id)
                self.send(response)
                total_len += len(response)

        except Exception as e:
            logger.exception(
                "Failed to build PcUpdateInventory for %s: %s",
                self.peer,
                e,
            )
            return

        logger.info(
            "SENT PcUpdateInventory reason=%s selected_id=%s owners=%s total_len=%d to %s",
            reason,
            char.char_id if char else None,
            owner_ids,
            total_len,
            self.peer,
        )

    def send_skill_update(self, reason: str) -> None:
        try:
            from src.network.login_server import make_pc_update_skill

            response = make_pc_update_skill()
        except Exception as e:
            logger.exception("Failed to build PcUpdateSkill for %s: %s", self.peer, e)
            return
        self.send(response)
        logger.info(
            "SENT PcUpdateSkill reason=%s response_len=%d to %s",
            reason,
            len(response),
            self.peer,
        )

    def on_make_race(self, payload: bytes):
        r = PacketReader(payload)
        race_name = r.read_str_fixed(32) if r.remaining() >= 32 else "Unknown"
        logger.info("PqMakeRace name=%r from %s", race_name, self.peer)
        w = PacketWriter()
        w.write_u8(1)
        w.write_u32(1)  # room id
        self.send(build_packet(Packet.PrMakeRace, w.getvalue()))

    def on_join_race(self, payload: bytes):
        r = PacketReader(payload)
        room_id = r.read_u32() if r.remaining() >= 4 else 0
        logger.info("PqJoinRace room_id=%d from %s", room_id, self.peer)
        w = PacketWriter()
        w.write_u8(1)
        self.send(build_packet(Packet.PrJoinRace, w.getvalue()))

    def on_time_sync(self, payload: bytes):
        server_ms = int(_time.time() * 1000) & 0xFFFFFFFF
        self.send(make_pr_time_sync(server_ms))


# ─── Server entry point ───────────────────────────────────────────────────────

async def start_game_server(host: str = "0.0.0.0", port: int = 2181):
    server = await asyncio.start_server(
        lambda r, w: GameSession(r, w).run(), host, port
    )
    logger.info("Game server listening on %s:%d", host, port)
    return server

