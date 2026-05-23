from __future__ import annotations

from src.packets.protocol import raycity_class_id


def packet_id(name: str) -> int:
    return raycity_class_id(name)


class Packet:
    # Handshake
    PcFirstAccept = packet_id("PcFirstAccept")
    PqFirstPacket = packet_id("PqFirstPacket")
    PrFirstPacket = packet_id("PrFirstPacket")

    # Login / channel
    PqLoginAgent = packet_id("PqLoginAgent")
    PrLoginAgent = packet_id("PrLoginAgent")
    PqUserLogin = packet_id("PqUserLogin")
    PrUserLogin = packet_id("PrUserLogin")
    PqEnterChannel = packet_id("PqEnterChannel")
    PrEnterChannel = packet_id("PrEnterChannel")
    PcGameAgentList = packet_id("PcGameAgentList")

    # Character
    PqCheckExistCharacter = packet_id("PqCheckExistCharacter")
    PrCheckExistCharacter = packet_id("PrCheckExistCharacter")
    PqNewCharacter = packet_id("PqNewCharacter")
    PrNewCharacter = packet_id("PrNewCharacter")
    PqDelCharacter = packet_id("PqDelCharacter")
    PrDelCharacter = packet_id("PrDelCharacter")
    PqSelectCharacter = packet_id("PqSelectCharacter")
    PrSelectCharacter = packet_id("PrSelectCharacter")

    # Field / town
    PqEnterField = packet_id("PqEnterField")
    PrEnterField = packet_id("PrEnterField")
    PqLeaveField = packet_id("PqLeaveField")
    PqMoveField = packet_id("PqMoveField")
    PqSetLastTown = packet_id("PqSetLastTown")
    PqUpdateMaxCombo = packet_id("PqUpdateMaxCombo")
    PrUpdateMaxCombo = packet_id("PrUpdateMaxCombo")

    # Car / inventory / Shop
    PqGetCarInfo = packet_id("PqGetCarInfo")
    PrGetCarInfo = packet_id("PrGetCarInfo")
    PqGetCarList = packet_id("PqGetCarList")
    PrGetCarList = packet_id("PrGetCarList")
    PqSelectCar = packet_id("PqSelectCar")
    PrSelectCar = packet_id("PrSelectCar")
    PqGetInventory = packet_id("PqGetInventory")
    PrGetInventory = packet_id("PrGetInventory")
    PqBuyStock = packet_id("PqBuyStock")
    PrBuyStock = packet_id("PrBuyStock")
    PqMoveInventoryItem = packet_id("PqMoveInventoryItem")
    PrMoveInventoryItem = packet_id("PrMoveInventoryItem")

    # Race
    PqGetRaceList = packet_id("PqGetRaceList")
    PrGetRaceList = packet_id("PrGetRaceList")
    PqMakeRace = packet_id("PqMakeRace")
    PrMakeRace = packet_id("PrMakeRace")
    PqJoinRace = packet_id("PqJoinRace")
    PrJoinRace = packet_id("PrJoinRace")
    PqLeaveRace = packet_id("PqLeaveRace")
    PrLeaveRace = packet_id("PrLeaveRace")
    PqUpdateReady = packet_id("PqUpdateReady")

    # Keep-alive / sync
    PqKeepAlive = packet_id("PqKeepAlive")
    PqTimeSync = packet_id("PqTimeSync")
    PrTimeSync = packet_id("PrTimeSync")
    PqUdpEcho = packet_id("PqUdpEcho")
    PrUdpEcho = packet_id("PrUdpEcho")

    # Server push / object payloads
    PcUpdateMoney = packet_id("PcUpdateMoney")
    PcUpdateExp = packet_id("PcUpdateExp")
    PcUpdateInventory = packet_id("PcUpdateInventory")
    PcUpdateSkill = packet_id("PcUpdateSkill")
    PcFriendFirst = packet_id("PcFriendFirst")
    CharacterInfo = packet_id("CharacterInfo")
    SecCharacterInfo = packet_id("SecCharacterInfo")
    RaceDestNode = packet_id("RaceDestNode")
    FieldRaceDestNode = packet_id("FieldRaceDestNode")
    CarInfo = packet_id("CarInfo")
    SecCarInfo = packet_id("SecCarInfo")
    Inventory = packet_id("Inventory")


_PACKET_NAME_BY_ID = {
    value: name
    for name, value in vars(Packet).items()
    if not name.startswith("_") and isinstance(value, int)
}

PACKET_IDS = frozenset(_PACKET_NAME_BY_ID)


def packet_name(packet_id_value: int | None) -> str:
    if packet_id_value is None:
        return "unknown"
    packet_id_value = int(packet_id_value) & 0xFFFFFFFF
    return _PACKET_NAME_BY_ID.get(packet_id_value, f"unknown_0x{packet_id_value:08X}")
