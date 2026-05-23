from __future__ import annotations
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


DEFAULT_RP = 100
DEFAULT_COMBO = 0
DEFAULT_MAX_SP = 0
DEFAULT_UNKNOWN_VALUE = 0
DEFAULT_INVENTORY_SLOTS = 30
DEFAULT_TRUNK_SLOTS = 9
DEFAULT_CAR_FUEL = 100
DEFAULT_ITEM_EXPIRE_TIME = 73051


@dataclass
class Car:
    car_id: int
    model_id: int
    name: str
    level: int = 200
    unk: int = 0
    endurance: int = 1000
    max_endurance: int = 1000
    exp: int = 0
    fuel: int = DEFAULT_CAR_FUEL
    max_fuel: int = DEFAULT_CAR_FUEL
    mileage: int = 0


@dataclass
class InventoryItem:
    slot: int
    item_id: int
    count: int = 1
    expire_time: int = DEFAULT_ITEM_EXPIRE_TIME
    owner_id: int = 0


@dataclass
class Character:
    char_id: int
    account_id: int
    name: str
    gender: int = 0          
    combo: int = DEFAULT_COMBO  
    unk_value: int = DEFAULT_UNKNOWN_VALUE 
    level: int = 60
    exp: int = 0
    money: int = 2147483647      
    mileage: int = 0
    town_id: int = 4097     
    rp: int = DEFAULT_RP        
    max_sp: int = DEFAULT_MAX_SP
    inventory_slots: int = DEFAULT_INVENTORY_SLOTS
    cars: list[Car] = field(default_factory=list)
    inventory: list[InventoryItem] = field(default_factory=list)
    selected_car_id: int = 0
    last_x: float = 0.0
    last_y: float = 0.0
    last_z: float = 0.0
    last_heading: float = 0.0

    def add_default_car(self):
        car = Car(car_id=1, model_id=29, name="무르시엘라고")
        self.cars.append(car)
        self.selected_car_id = car.car_id


@dataclass
class Account:
    account_id: int
    username: str
    password: str            
    characters: list[Character] = field(default_factory=list)
    selected_char_id: int = 0


class Database:
    def __init__(self):
        self._accounts: dict[str, Account] = {}
        self._account_by_id: dict[int, Account] = {}
        self._char_by_id: dict[int, Character] = {}
        self._next_account_id = 1
        self._next_char_id = 1
        self._next_car_id = 100
        default_path = Path(__file__).resolve().parents[2] / "data" / "Raycity_db.json"
        self._path = Path(os.environ.get("RAYCITY_DB_PATH", default_path))
        self._mtime_ns = 0

        if not self._load():
            self._create_account("test", "test123", persist=False)
            self.save()
        elif "test" not in self._accounts:
            self._create_account("test", "test123", persist=False)
            self.save()

    # ─── Accounts ─────────────────────────────────────────────────────────────

    def _create_account(self, username: str, password: str, persist: bool = True) -> Account:
        acc = Account(
            account_id=self._next_account_id,
            username=username,
            password=password,
        )
        self._next_account_id += 1
        self._accounts[username.lower()] = acc
        self._account_by_id[acc.account_id] = acc
        if persist:
            self.save()
        return acc

    def authenticate(self, username: str, password: str) -> Optional[Account]:
        self.reload_if_changed()
        acc = self._accounts.get(username.lower())
        if acc:
            if acc.password != password:
                acc.password = password
                self.save()
            return acc
        acc = self._create_account(username, password)
        return acc

    def get_account(self, account_id: int) -> Optional[Account]:
        self.reload_if_changed()
        return self._account_by_id.get(account_id)

    def next_char_id_hint(self) -> int:
        return self._next_char_id

    # ─── Characters ───────────────────────────────────────────────────────────

    def check_name_exists(self, name: str) -> bool:
        self.reload_if_changed()
        return any(c.name.lower() == name.lower() for c in self._char_by_id.values())

    def create_character(self, account: Account, name: str, gender: int,
                         combo: int, unk_value: int) -> Character:
        self.reload_if_changed()
        account = self._account_by_id.get(account.account_id, account)
        char = Character(
            char_id=self._next_char_id,
            account_id=account.account_id,
            name=name,
            gender=gender,
            combo=combo,
            unk_value=unk_value,
        )
        char.add_default_car()
        char.cars[-1].car_id = self._next_car_id
        char.selected_car_id = self._next_car_id
        self._next_car_id += 1
        self._next_char_id += 1
        account.characters.append(char)
        self._char_by_id[char.char_id] = char
        self.save()
        return char

    def delete_character(self, account: Account, char_id: int) -> bool:
        self.reload_if_changed()
        account = self._account_by_id.get(account.account_id, account)
        char = self._char_by_id.get(char_id)
        if char and char.account_id == account.account_id:
            account.characters = [c for c in account.characters if c.char_id != char_id]
            if account.selected_char_id == char_id:
                account.selected_char_id = account.characters[-1].char_id if account.characters else 0
            del self._char_by_id[char_id]
            self.save()
            return True
        return False

    def get_character(self, char_id: int) -> Optional[Character]:
        self.reload_if_changed()
        return self._char_by_id.get(char_id)

    def latest_character(self) -> Optional[Character]:
        self.reload_if_changed()
        for account in self._account_by_id.values():
            if account.selected_char_id:
                char = self.get_character(account.selected_char_id)
                if char:
                    return char
            if account.characters:
                return account.characters[-1]
        return None

    def save(self):
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "next_account_id": self._next_account_id,
            "next_char_id": self._next_char_id,
            "next_car_id": self._next_car_id,
            "accounts": [self._account_to_dict(acc) for acc in self._account_by_id.values()],
        }
        self._path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        self._remember_mtime()

    def reload_if_changed(self) -> bool:
        try:
            mtime_ns = self._path.stat().st_mtime_ns
        except OSError:
            return False
        if self._mtime_ns and mtime_ns == self._mtime_ns:
            return False
        return self._load()

    def _load(self) -> bool:
        if not self._path.exists():
            return False
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            needs_upgrade = self._data_needs_upgrade(data)
            accounts = data.get("accounts", [])
            self._accounts.clear()
            self._account_by_id.clear()
            self._char_by_id.clear()
            for raw_acc in accounts:
                acc = self._account_from_dict(raw_acc)
                self._accounts[acc.username.lower()] = acc
                self._account_by_id[acc.account_id] = acc
                for char in acc.characters:
                    self._char_by_id[char.char_id] = char
            self._next_account_id = max(
                int(data.get("next_account_id", 1)),
                max(self._account_by_id.keys(), default=0) + 1,
            )
            self._next_char_id = max(
                int(data.get("next_char_id", 1)),
                max(self._char_by_id.keys(), default=0) + 1,
            )
            max_car_id = 0
            for acc in self._account_by_id.values():
                for char in acc.characters:
                    for car in char.cars:
                        max_car_id = max(max_car_id, car.car_id)
            self._next_car_id = max(int(data.get("next_car_id", 100)), max_car_id + 1, 100)
            if self._ensure_defaults() or needs_upgrade:
                self.save()
            else:
                self._remember_mtime()
            return True
        except Exception:
            self._accounts.clear()
            self._account_by_id.clear()
            self._char_by_id.clear()
            self._next_account_id = 1
            self._next_char_id = 1
            self._next_car_id = 100
            return False

    def _remember_mtime(self) -> None:
        try:
            self._mtime_ns = self._path.stat().st_mtime_ns
        except OSError:
            self._mtime_ns = 0

    def _account_to_dict(self, acc: Account) -> dict:
        return {
            "account_id": acc.account_id,
            "username": acc.username,
            "password": acc.password,
            "selected_char_id": acc.selected_char_id,
            "characters": [self._character_to_dict(char) for char in acc.characters],
        }

    def _character_to_dict(self, char: Character) -> dict:
        return {
            "char_id": char.char_id,
            "account_id": char.account_id,
            "name": char.name,
            "gender": char.gender,
            "combo": char.combo,
            "unk_value": char.unk_value,
            "level": char.level,
            "exp": char.exp,
            "money": char.money,
            "mileage": char.mileage,
            "town_id": char.town_id,
            "rp": char.rp,
            "max_sp": char.max_sp,
            "inventory_slots": char.inventory_slots,
            "selected_car_id": char.selected_car_id,
            "last_x": char.last_x,
            "last_y": char.last_y,
            "last_z": char.last_z,
            "last_heading": char.last_heading,
            "cars": [car.__dict__.copy() for car in char.cars],
            "inventory": [self._inventory_item_to_dict(item) for item in char.inventory],
        }

    def _inventory_item_to_dict(self, item: InventoryItem) -> dict:
        return item.__dict__.copy()

    def _account_from_dict(self, data: dict) -> Account:
        acc = Account(
            account_id=int(data.get("account_id", 0)),
            username=str(data.get("username", "")),
            password=str(data.get("password", "")),
            selected_char_id=int(data.get("selected_char_id", 0)),
        )
        acc.characters = [self._character_from_dict(raw) for raw in data.get("characters", [])]
        return acc

    def _character_from_dict(self, data: dict) -> Character:
        char = Character(
            char_id=int(data.get("char_id", 0)),
            account_id=int(data.get("account_id", 0)),
            name=str(data.get("name", "")),
            gender=int(data.get("gender", 0)),
            combo=int(data.get("combo", DEFAULT_COMBO)),
            unk_value=int(data.get("unk_value", DEFAULT_UNKNOWN_VALUE)),
            level=int(data.get("level", 60)),
            exp=int(data.get("exp", 0)),
            money=int(data.get("money", 12345678)),
            mileage=int(data.get("mileage", 0)),
            town_id=int(data.get("town_id", 4097)),
            rp=int(data.get("rp", DEFAULT_RP)),
            max_sp=int(data.get("max_sp", DEFAULT_MAX_SP)),
            inventory_slots=int(data.get("inventory_slots", DEFAULT_INVENTORY_SLOTS)),
            selected_car_id=int(data.get("selected_car_id", 0)),
            last_x=float(data.get("last_x", 0.0)),
            last_y=float(data.get("last_y", 0.0)),
            last_z=float(data.get("last_z", 0.0)),
            last_heading=float(data.get("last_heading", 0.0)),
        )
        char.cars = [self._car_from_dict(raw) for raw in data.get("cars", [])]
        char.inventory = [self._inventory_item_from_dict(raw) for raw in data.get("inventory", [])]
        return char

    def _inventory_item_from_dict(self, data: dict) -> InventoryItem:
        return InventoryItem(
            slot=int(data.get("slot", 0)),
            item_id=int(data.get("item_id", 0)),
            count=int(data.get("count", 1)),
            expire_time=int(data.get("expire_time", DEFAULT_ITEM_EXPIRE_TIME)),
            owner_id=int(data.get("owner_id", 0)),
        )

    def _car_from_dict(self, data: dict) -> Car:
        return Car(
            car_id=int(data.get("car_id", 0)),
            model_id=int(data.get("model_id", 1)),
            name=str(data.get("name", "")),
            level=int(data.get("level", 1)),
            unk=int(data.get("unk", 0)),
            endurance=int(data.get("endurance", 1000)),
            max_endurance=int(data.get("max_endurance", 1000)),
            exp=int(data.get("exp", 0)),
            fuel=int(data.get("fuel", DEFAULT_CAR_FUEL)),
            max_fuel=int(data.get("max_fuel", DEFAULT_CAR_FUEL)),
            mileage=int(data.get("mileage", 0)),
        )

    def _data_needs_upgrade(self, data: dict) -> bool:
        for raw_acc in data.get("accounts", []):
            for raw_char in raw_acc.get("characters", []):
                for key in (
                    "combo",
                    "unk_value",
                    "rp",
                    "max_sp",
                    "inventory_slots",
                    "last_x",
                    "last_y",
                    "last_z",
                    "last_heading",
                ):
                    if key not in raw_char:
                        return True
                for raw_item in raw_char.get("inventory", []):
                    if "expire_time" not in raw_item:
                        return True
                    if "owner_id" not in raw_item:
                        return True
                for raw_car in raw_char.get("cars", []):
                    for key in ("fuel", "max_fuel", "mileage"):
                        if key not in raw_car:
                            return True
        return False

    def _ensure_defaults(self) -> bool:
        changed = False
        for char in self._char_by_id.values():
            if int(getattr(char, "rp", 0) or 0) <= 0:
                char.rp = DEFAULT_RP
                changed = True
            if int(getattr(char, "inventory_slots", 0) or 0) <= 0:
                char.inventory_slots = DEFAULT_INVENTORY_SLOTS
                changed = True
            for attr in ("last_x", "last_y", "last_z", "last_heading"):
                if not hasattr(char, attr):
                    setattr(char, attr, 0.0)
                    changed = True
            for item in char.inventory:
                if not getattr(item, "owner_id", 0):
                    item.owner_id = char.char_id
                    changed = True
                if int(getattr(item, "expire_time", 0) or 0) <= 0:
                    item.expire_time = DEFAULT_ITEM_EXPIRE_TIME
                    changed = True
            for car in char.cars:
                if int(getattr(car, "fuel", 0) or 0) <= 0:
                    car.fuel = DEFAULT_CAR_FUEL
                    changed = True
                if int(getattr(car, "max_fuel", 0) or 0) <= 0:
                    car.max_fuel = DEFAULT_CAR_FUEL
                    changed = True
                if car.max_fuel < car.fuel:
                    car.max_fuel = car.fuel
                    changed = True
                if int(getattr(car, "mileage", 0) or 0) < 0:
                    car.mileage = 0
                    changed = True
        return changed
    
db = Database()
