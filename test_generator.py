#!/usr/bin/env python3
"""Проверки генератора на исключительно синтетических CSV (Python stdlib)."""
import csv
import ipaddress
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REQUIRED = ('bonds.csv', 'networks.csv')
OPTIONAL = 'extra_interfaces.csv'
HOSTS = {'demo-alpha', 'demo-beta', 'demo-gamma'}
VLANS = {171, 272, 373, 474}


def read_rows(path):
    with path.open('r', encoding='utf-8-sig', newline='') as stream:
        return list(csv.DictReader(stream))


def write_rows(path, data):
    with path.open('w', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(data[0]), lineterminator='\n')
        writer.writeheader()
        writer.writerows(data)


def generate(folder, output=None, *extra_args):
    return subprocess.run([sys.executable, str(ROOT / 'generate_interfaces.py'),
                           '--input', str(folder), '--output', str(output or folder/'out'),
                           *extra_args], capture_output=True, text=True)


def copy_fixture(folder, include_extra=True):
    for name in REQUIRED:
        shutil.copy(ROOT / name, folder / name)
    if include_extra:
        shutil.copy(ROOT / OPTIONAL, folder / OPTIONAL)


def check_ok(result, context):
    assert result.returncode == 0, f'{context}: {result.stderr}'


networks = read_rows(ROOT / 'networks.csv')
bonds = read_rows(ROOT / 'bonds.csv')
extras = read_rows(ROOT / OPTIONAL)
assert len(networks) == 12
assert len(bonds) == 6 and len(extras) == 1
assert {r['host'] for r in networks} == HOSTS
assert {int(r['vlan']) for r in networks} == VLANS
assert all(sum(r['default_route'] == 'yes' for r in networks if r['host'] == h) == 1 for h in HOSTS)
assert {r['bond'] for r in bonds} == {'bond7', 'bond8'}
assert all(ipaddress.IPv4Address(r['ip']) in ipaddress.IPv4Network('192.0.2.0/24')
           or ipaddress.IPv4Address(r['ip']) in ipaddress.IPv4Network('198.51.100.0/24')
           or ipaddress.IPv4Address(r['ip']) in ipaddress.IPv4Network('203.0.113.0/24')
           for r in networks)

# Проверка полного совпадения генерации с демонстрационным результатом.
with tempfile.TemporaryDirectory() as tmp:
    folder = Path(tmp)
    copy_fixture(folder)
    check_ok(generate(folder), 'basic generation')
    for host in HOSTS:
        config = (folder/'out'/host).read_text(encoding='utf-8')
        assert config == (ROOT/'generated'/host).read_text(encoding='utf-8')
        hostnets = [r for r in networks if r['host'] == host]
        assert config.count('iface br') == len(hostnets)
        assert config.count('    gateway ') == 1
        assert config.count('    post-up ip rule add ') == len(hostnets)
        assert config.count(' scope link src ') == len(hostnets)
        assert '    bridge_ports bond8\n' in config
        assert 'bond8.373' not in config
        assert '    bridge_ports bond7.272\n' in config
        assert '    mtu 9000\n' in config
        for n in hostnets:
            vlan, ip, gateway = n['vlan'], n['ip'], n['gateway']
            assert f'    address {ip}\n' in config
            assert f'    netmask {n["mask"]}\n' in config
            assert f'    post-up ip route replace default via {gateway} dev br{vlan} table tabel{vlan}\n' in config
            assert f'    post-up ip rule add pref {10000+int(vlan)} from {ip}/32 lookup tabel{vlan}\n' in config
        assert '    gateway 192.0.2.1\n' in config
    assert 'auto enp8s0' in (folder/'out'/'demo-gamma').read_text(encoding='utf-8')
    assert (folder/'out'/'rt_tables.additions').read_text() == (ROOT/'generated'/'rt_tables.additions').read_text()
    assert (folder/'out'/'validation.txt').read_text() == (ROOT/'generated'/'validation.txt').read_text()
    failed = generate(folder)
    assert failed.returncode != 0, 'must protect existing outputs without --force'
    check_ok(generate(folder, folder/'out', '--force'), 'overwrite')

# Отсутствие optional CSV не мешает запуску.
with tempfile.TemporaryDirectory() as tmp:
    folder = Path(tmp)
    copy_fixture(folder, include_extra=False)
    check_ok(generate(folder), 'without extra_interfaces.csv')
    assert 'auto enp8s0' not in (folder/'out'/'demo-gamma').read_text(encoding='utf-8')

# Числовое, Unicode и текстовое имя хоста, выбор другого default.
with tempfile.TemporaryDirectory() as tmp:
    folder = Path(tmp)
    copy_fixture(folder)
    rename = {'demo-alpha': '42', 'demo-beta': 'Пример узла', 'demo-gamma': 'Example node C'}
    for filename in (*REQUIRED, OPTIONAL):
        data = read_rows(folder/filename)
        for record in data:
            record['host'] = rename[record['host']]
            if filename == 'networks.csv' and record['host'] == '42':
                record['default_route'] = 'yes' if record['vlan'] == '272' else 'no'
        write_rows(folder/filename, data)
    check_ok(generate(folder), 'custom host labels and default route')
    for label in rename.values():
        assert (folder/'out'/label).is_file()
    config = (folder/'out'/'42').read_text(encoding='utf-8')
    assert '    gateway 198.51.100.65\n' in config
    assert '    gateway 192.0.2.1\n' not in config
    assert '# Основной default route: VLAN 272 (198.51.100.65).' in config

# Примеры ошибок входных CSV должны приводить к остановке без создания выходных файлов.
mutations = [
    ('multiple default routes', lambda data: data[1].update(default_route='yes')),
    ('missing default route', lambda data: data[0].update(default_route='no')),
    ('broadcast address', lambda data: data[0].update(ip='192.0.2.7')),
    ('gateway outside subnet', lambda data: data[0].update(gateway='203.0.113.5')),
    ('undefined bond', lambda data: data[0].update(bond='bond99')),
    ('unsafe filename', lambda data: data[0].update(host='../example')),
    ('too big mtu', lambda data: data[0].update(mtu='10000')),
    ('incorrect mask', lambda data: data[0].update(mask='255.255.255.0', ip='192.0.2.2/29')),
    ('duplicate host address', lambda data: data[4].update(ip='192.0.2.2')),
]
for name, modify in mutations:
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp)
        copy_fixture(folder)
        data = read_rows(folder/'networks.csv')
        modify(data)
        write_rows(folder/'networks.csv', data)
        result = generate(folder)
        assert result.returncode != 0, f'{name} unexpectedly passed'
        assert not (folder/'out').exists(), f'{name} wrote outputs'

print('PASS: synthetic example — 3 hosts, 6 bonds, 12 IPv4, 4 VLAN, optional input, defaults and invalid-input tests')
