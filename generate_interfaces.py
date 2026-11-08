#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Генератор Linux ifupdown /etc/network/interfaces.

Вход: bonds.csv и networks.csv; необязательный extra_interfaces.csv.
Выход: отдельный interfaces-файл для каждого сервера, rt_tables.additions, validation.txt.
Сетевые конфигурации только создаются в указанном каталоге и не применяются.
Только стандартная библиотека Python 3.9+.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


IFACE_RX = re.compile(r"^[a-zA-Z0-9_.:-]+$")


class InvalidInput(Exception):
    pass


def fail(message: str) -> None:
    raise InvalidInput(message)


def read_csv(path: Path, required: tuple[str, ...], optional: bool = False) -> list[dict[str, str]]:
    if not path.is_file():
        if optional:
            return []
        fail(f"Отсутствует входной файл: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        first = stream.read(4096)
        stream.seek(0)
        if not first.strip():
            if optional:
                return []
            fail(f"Пустой CSV: {path}")
        try:
            dialect = csv.Sniffer().sniff(first, delimiters=",;")
            delimiter = dialect.delimiter
        except csv.Error:
            delimiter = ","
        reader = csv.DictReader(stream, delimiter=delimiter)
        header = [x.strip() for x in (reader.fieldnames or [])]
        absent = set(required) - set(header)
        if absent:
            fail(f"{path}: отсутствуют столбцы: {', '.join(sorted(absent))}")
        if len(header) != len(set(header)):
            fail(f"{path}: повторяющиеся названия столбцов")
        records: list[dict[str, str]] = []
        for lineno, row in enumerate(reader, start=2):
            if None in row:
                fail(f"{path}:{lineno}: лишние поля (проверьте разделитель)")
            data = {str(k).strip(): (v or "").strip() for k, v in row.items()}
            if any(any(ord(ch) < 32 or ord(ch) == 127 for ch in value)
                   for value in data.values()):
                fail(f"{path}:{lineno}: запрещены переводы строк/управляющие символы в ячейках CSV")
            if not any(data.values()) or data.get(header[0], "").startswith("#"):
                continue
            data["_source"] = f"{path.name}:{lineno}"
            records.append(data)
        return records


def safe_host_name(value: str, where: str) -> str:
    """Идентификатор хоста одновременно является именем выходного файла.

    Разрешены IP, числа, Unicode-имена и пробелы. Не допускаем небезопасные
    символы пути, управляющие символы и имена служебных файлов.
    """
    if (not value or value in {".", ".."} or value.startswith(".")
            or value != value.strip() or any(ch in value for ch in "/\\")
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in value)
            or len(value.encode("utf-8")) > 200
            or value in {"rt_tables.additions", "validation.txt"}
            or value.endswith(".tmp")):
        fail(f"{where}: недопустимый идентификатор сервера/имя файла {value!r}. "
             "Запрещены /, \\, управляющие символы, начальная точка и служебные имена")
    return value


def default_route_value(value: str, where: str) -> bool:
    value = value.strip().casefold()
    if value in {"да", "yes", "true", "1", "y"}:
        return True
    if value in {"", "нет", "no", "false", "0", "n"}:
        return False
    fail(f"{where}: default_route должен быть да/нет, yes/no или 1/0: {value!r}")


def interface_name(value: str, what: str) -> str:
    if not IFACE_RX.fullmatch(value) or len(value.encode("utf-8")) > 15:
        fail(f"Некорректное имя {what}: {value!r} (максимум 15 байт)")
    return value


def mtu_value(value: str, where: str, fallback: int | None = None) -> int:
    if not value and fallback is not None:
        return fallback
    try:
        mtu = int(value)
    except (TypeError, ValueError):
        fail(f"{where}: MTU должен быть целым числом, получено: {value!r}")
    if not 576 <= mtu <= 65535:
        fail(f"{where}: недопустимый MTU {mtu} (ожидается 576–65535)")
    return mtu


def vlan_number(value: str, where: str) -> int:
    try:
        vlan = int(value)
    except ValueError:
        fail(f"{where}: VLAN должен быть числом: {value!r}")
    if not 1 <= vlan <= 4094:
        fail(f"{where}: номер VLAN {vlan} вне диапазона 1–4094")
    return vlan


def tagged_value(value: str, where: str) -> bool:
    value = value.lower().strip()
    if value in {"", "tagged", "yes", "true", "1", "да"}:
        return True
    if value in {"untagged", "native", "no", "false", "0", "нет"}:
        return False
    fail(f"{where}: tagging ожидает 'tagged' или 'untagged'; получено: {value!r}")


@dataclass(frozen=True)
class Host:
    name: str


@dataclass(frozen=True)
class Bond:
    name: str
    slaves: tuple[str, ...]
    mtu: int


@dataclass(frozen=True)
class Network:
    vlan: int
    bond: str
    ip: ipaddress.IPv4Address
    subnet: ipaddress.IPv4Network
    gateway: ipaddress.IPv4Address
    mtu: int
    tagged: bool
    default_route: bool
    description: str


@dataclass(frozen=True)
class Extra:
    name: str
    mtu: int


def parse_address(ip_raw: str, mask_raw: str, where: str):
    mask_raw = mask_raw.lstrip("/")
    if not ip_raw:
        fail(f"{where}: отсутствует IP-адрес")
    try:
        if "/" in ip_raw:
            address = ipaddress.IPv4Interface(ip_raw)
            if mask_raw and address.network.prefixlen != ipaddress.IPv4Network(
                f"0.0.0.0/{mask_raw}"
            ).prefixlen:
                fail(f"{where}: CIDR и маска не совпадают: {ip_raw}, {mask_raw}")
        else:
            if not mask_raw:
                fail(f"{where}: у IP {ip_raw} не указана маска или CIDR")
            address = ipaddress.IPv4Interface(f"{ip_raw}/{mask_raw}")
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as error:
        fail(f"{where}: некорректный адрес/маска: {ip_raw} {mask_raw} ({error})")
    return address.ip, address.network


def load_inputs(folder: Path):
    # Список хостов берётся только из networks.csv. hosts.csv больше не нужен.
    # CSV bonds читаем раньше сетей для проверки, что каждый используемый bond описан.
    bonds: dict[str, dict[str, Bond]] = defaultdict(dict)
    used_slaves: dict[str, set[str]] = defaultdict(set)
    for row in read_csv(folder / "bonds.csv", ("host", "bond", "slaves", "mtu")):
        where = row["_source"]
        host = safe_host_name(row["host"], where)
        bond_name = interface_name(row["bond"], "bond")
        if not bond_name.startswith("bond"):
            fail(f"{where}: имя агрегата должно начинаться с bond: {bond_name}")
        slaves = tuple(row["slaves"].replace("+", " ").split())
        if len(slaves) < 2 or len(slaves) != len(set(slaves)):
            fail(f"{where}: у {bond_name} должно быть как минимум два разных slave")
        for slave in slaves:
            interface_name(slave, "slave-интерфейса")
            if slave == bond_name or slave in used_slaves[host]:
                fail(f"{where}: интерфейс {slave} повторно используется в bond сервера {host}")
            used_slaves[host].add(slave)
        if bond_name in bonds[host]:
            fail(f"{where}: повторный bond {bond_name} на {host}")
        bonds[host][bond_name] = Bond(bond_name, slaves, mtu_value(row["mtu"], where))

    networks: dict[str, list[Network]] = defaultdict(list)
    hosts: dict[str, Host] = {}
    default_count: dict[str, int] = defaultdict(int)
    used_ips: dict[ipaddress.IPv4Address, str] = {}
    vlan_settings: dict[int, tuple[ipaddress.IPv4Network, ipaddress.IPv4Address, int, bool]] = {}
    untagged_bonds: dict[tuple[str, str], int] = {}
    seen_host_vlan: set[tuple[str, int]] = set()
    for row in read_csv(folder / "networks.csv", ("host", "bond", "vlan", "ip", "mask", "gateway", "mtu", "tagging", "default_route")):
        where = row["_source"]
        host = safe_host_name(row["host"], where)
        hosts[host] = Host(host)
        bond_name = row["bond"]
        if bond_name not in bonds[host]:
            fail(f"{where}: у {host} не описан {bond_name} в bonds.csv")
        vlan = vlan_number(row["vlan"], where)
        if (host, vlan) in seen_host_vlan:
            fail(f"{where}: VLAN {vlan} повторяется на сервере {host}")
        seen_host_vlan.add((host, vlan))
        ip, subnet = parse_address(row["ip"], row["mask"], where)
        if subnet.prefixlen >= 31 or ip in {subnet.network_address, subnet.broadcast_address}:
            fail(f"{where}: IP {ip} — адрес сети/broadcast или неподдерживаемая маска /{subnet.prefixlen}")
        try:
            gateway = ipaddress.IPv4Address(row["gateway"])
        except ValueError:
            fail(f"{where}: некорректный шлюз: {row['gateway']!r}")
        if gateway not in subnet or gateway in {ip, subnet.network_address, subnet.broadcast_address}:
            fail(f"{where}: шлюз {gateway} не является допустимым адресом в {subnet} для {ip}")
        if ip in used_ips:
            fail(f"{where}: IP {ip} повторяется (ранее: {used_ips[ip]})")
        used_ips[ip] = where
        mtu = mtu_value(row["mtu"], where, bonds[host][bond_name].mtu)
        if mtu > bonds[host][bond_name].mtu:
            fail(f"{where}: MTU {mtu} VLAN {vlan} больше MTU {bonds[host][bond_name].mtu} {bond_name}")
        is_default = default_route_value(row["default_route"], where)
        if is_default:
            default_count[host] += 1
        tagged = tagged_value(row["tagging"], where)
        if not tagged:
            key = (host, bond_name)
            if key in untagged_bonds:
                fail(f"{where}: на одном bond нельзя назначить два untagged VLAN: {untagged_bonds[key]} и {vlan}")
            untagged_bonds[key] = vlan
            if mtu != bonds[host][bond_name].mtu:
                fail(f"{where}: для untagged VLAN MTU моста должен совпадать с MTU {bond_name}")
        if tagged and len(f"{bond_name}.{vlan}".encode()) > 15:
            fail(f"{where}: имя VLAN-интерфейса {bond_name}.{vlan} слишком длинное")
        setting = (subnet, gateway, mtu, tagged)
        if vlan in vlan_settings and vlan_settings[vlan] != setting:
            fail(f"{where}: VLAN {vlan} имеет подсеть/шлюз/MTU/tagging, отличающиеся от других серверов: {setting} != {vlan_settings[vlan]}")
        vlan_settings[vlan] = setting
        networks[host].append(Network(vlan, bond_name, ip, subnet, gateway, mtu, tagged, is_default, row.get("description", "")))

    extras: dict[str, list[Extra]] = defaultdict(list)
    for row in read_csv(folder / "extra_interfaces.csv", ("host", "interface", "mtu"), optional=True):
        where = row["_source"]
        host = safe_host_name(row["host"], where)
        if host not in hosts:
            fail(f"{where}: неизвестный сервер {host}")
        iface = interface_name(row["interface"], "дополнительного интерфейса")
        allocated = {x for b in bonds[host].values() for x in b.slaves}
        allocated.update(bonds[host])
        allocated.update(x.name for x in extras[host])
        allocated.update({f"br{x.vlan}" for x in networks[host]})
        allocated.update({f"{x.bond}.{x.vlan}" for x in networks[host] if x.tagged})
        if iface in allocated:
            fail(f"{where}: имя интерфейса {iface} на {host} уже используется")
        extras[host].append(Extra(iface, mtu_value(row["mtu"], where)))

    # Не допускаем пересечения IPv4-подсетей между разными VLAN.
    for i, vlan in enumerate(sorted(vlan_settings)):
        subnet = vlan_settings[vlan][0]
        for other in sorted(vlan_settings)[i + 1:]:
            other_subnet = vlan_settings[other][0]
            if subnet.overlaps(other_subnet):
                fail(f"Подсети VLAN {vlan} ({subnet}) и VLAN {other} ({other_subnet}) пересекаются")

    if not hosts:
        fail("networks.csv не содержит серверов")
    for host in bonds:
        if host not in hosts:
            fail(f"bonds.csv: для {host!r} нет ни одной сети в networks.csv")
    for host in hosts:
        if default_count[host] != 1:
            fail(f"{host!r}: требуется ровно одна сеть с default_route=yes; найдено {default_count[host]}")
        if not bonds[host]:
            fail(f"{host}: нет ни одного bond в bonds.csv")
        if not networks[host]:
            fail(f"{host}: отсутствуют VLAN в networks.csv")
    return hosts, bonds, networks, extras, vlan_settings


def render_interfaces(host: Host, bonds: dict[str, Bond], networks: list[Network], extras: list[Extra], priority_base: int) -> str:
    default_network = next(net for net in networks if net.default_route)
    lines = [
        "# /etc/network/interfaces: создан generate_interfaces.py",
        f"# Сервер: {host.name}",
        "# Маршрутизация: IP источника -> tabel<VLAN>, прямой маршрут + шлюз VLAN.",
        f"# Основной default route: VLAN {default_network.vlan} ({default_network.gateway}).",
        "source /etc/network/interfaces.d/*",
        "",
        "auto lo",
        "iface lo inet loopback",
        "",
    ]
    for bond in sorted(bonds.values(), key=lambda b: b.name):
        lines.append(f"# ---------- {bond.name}: LACP ({', '.join(bond.slaves)}) ----------")
        for slave in bond.slaves:
            lines.extend([f"auto {slave}", f"iface {slave} inet manual", f"    mtu {bond.mtu}", ""])
        lines.extend([
            f"auto {bond.name}", f"iface {bond.name} inet manual",
            "    pre-up modprobe bonding", "    bond-mode 802.3ad", "    bond-miimon 100",
            "    bond-downdelay 200", "    bond-updelay 200",
            "    bond-xmit-hash-policy layer3+4",
            f"    bond-slaves {' '.join(bond.slaves)}", f"    mtu {bond.mtu}", "",
        ])
        for net in sorted((n for n in networks if n.bond == bond.name), key=lambda n: n.vlan):
            bridge = f"br{net.vlan}"
            nic = f"{bond.name}.{net.vlan}" if net.tagged else bond.name
            desc = f": {net.description}" if net.description else ""
            lines.append(f"# ---------- VLAN {net.vlan} ({'tagged' if net.tagged else 'untagged'}){desc} ----------")
            if net.tagged:
                lines.extend([
                    f"auto {nic}", f"iface {nic} inet manual",
                    f"    vlan-raw-device {bond.name}", f"    mtu {net.mtu}", "",
                ])
            lines.extend([
                f"auto {bridge}", f"iface {bridge} inet static",
                f"    bridge_ports {nic}", "    bridge_stp off", "    bridge_fd 0",
                f"    mtu {net.mtu}", f"    address {net.ip}",
                f"    netmask {net.subnet.netmask}",
            ])
            if net.default_route:
                lines.append(f"    gateway {net.gateway}")
            table = f"tabel{net.vlan}"
            priority = priority_base + net.vlan
            lines.extend([
                f"    post-up ip route replace {net.subnet} dev {bridge} scope link src {net.ip} table {table}",
                f"    post-up ip route replace default via {net.gateway} dev {bridge} table {table}",
                f"    post-up ip rule del pref {priority} from {net.ip}/32 lookup {table} 2>/dev/null || true",
                f"    post-up ip rule add pref {priority} from {net.ip}/32 lookup {table}",
                f"    pre-down ip rule del pref {priority} from {net.ip}/32 lookup {table} 2>/dev/null || true",
                f"    pre-down ip route del default via {net.gateway} dev {bridge} table {table} 2>/dev/null || true",
                f"    pre-down ip route del {net.subnet} dev {bridge} table {table} 2>/dev/null || true",
                "",
            ])
    if extras:
        lines.append("# ---------- Дополнительные физические интерфейсы ----------")
        for extra in sorted(extras, key=lambda e: e.name):
            lines.extend([f"auto {extra.name}", f"iface {extra.name} inet manual", f"    mtu {extra.mtu}", ""])
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    p = argparse.ArgumentParser(description="Генерация ifupdown конфигураций для группы серверов (CSV -> interfaces).")
    p.add_argument("--input", type=Path, default=Path("."), help="Каталог с входными CSV")
    p.add_argument("--output", type=Path, default=Path("./generated"), help="Каталог для готовых файлов")
    p.add_argument("--table-start", type=int, default=100, help="Первый ID в rt_tables (по умолчанию 100)")
    p.add_argument("--priority-base", type=int, default=10000, help="Базовый приоритет ip rule (по умолчанию 10000)")
    p.add_argument("--force", action="store_true", help="Разрешить замену существующих выходных файлов")
    args = p.parse_args()
    try:
        hosts, bonds, networks, extras, vlan_settings = load_inputs(args.input)
        vlans = sorted(vlan_settings)
        if not 1 <= args.table_start <= 2**32 - len(vlans):
            fail("Некорректное начало диапазона ID таблиц")
        if args.priority_base + max(vlans) >= 32766 or args.priority_base + min(vlans) <= 0:
            fail("Диапазон ip rule pref конфликтует с зарезервированными приоритетами")
        output = args.output.resolve()
        if output in {Path("/"), Path("/etc"), Path("/etc/network"), Path("/etc/iproute2")}:
            fail("Нельзя использовать системный каталог как --output")
        generated = {h.name: render_interfaces(h, bonds[h.name], networks[h.name], extras[h.name], args.priority_base) for h in hosts.values()}
        generated["rt_tables.additions"] = "# ID\tTable name\n" + "".join(f"{args.table_start + i}\ttabel{v}\n" for i, v in enumerate(vlans))
        generated["validation.txt"] = (
            "ПРОВЕРКА УСПЕШНА\n"
            f"Серверов: {len(hosts)}\nСетей/VLAN: {len(vlans)}\nНазначений IPv4: {sum(len(x) for x in networks.values())}\n"
            f"Названия таблиц: tabel<VLAN>; ID: {args.table_start}..{args.table_start + len(vlans)-1}\n"
            "Основная таблица main: шлюз задаётся флагом default_route для каждого сервера\n"
            "Подсети, шлюзы, broadcast/network, дубликаты и MTU проверены.\n"
            "Отдельно проверьте LACP, trunk/native VLAN и реальную доступность шлюзов.\n"
        )
        if output.exists() and not output.is_dir():
            fail(f"{output} существует и не является каталогом")
        existing = [output / name for name in generated if (output / name).exists()]
        if existing and not args.force:
            fail(f"В каталоге {output} уже есть {len(existing)} выходных файлов. Используйте новый каталог или --force")
        output.mkdir(parents=True, exist_ok=True)
        for name, content in generated.items():
            destination = output / name
            tmp = output / (name + ".tmp")
            if tmp.exists():
                fail(f"Временный файл уже существует: {tmp}")
            try:
                tmp.write_text(content, encoding="utf-8")
                tmp.replace(destination)
            finally:
                tmp.unlink(missing_ok=True)
        print(f"Готово: {len(hosts)} конфигураций, {sum(map(len, networks.values()))} IPv4, {len(vlans)} таблицы.")
        print(f"Каталог: {output}")
        print(f"Файл регистрации таблиц: {output / 'rt_tables.additions'}")
        return 0
    except (InvalidInput, OSError) as error:
        print(f"ОШИБКА: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
