import ctypes

import collections

import concurrent.futures

import csv

import datetime

import hashlib

import http.client

import json

import math

import os

import pathlib

import platform

import queue

import select

import socketserver

import http.server

import shutil

import re

import socket

import ssl

import struct

import subprocess

import tarfile

import sys

import threading

import time

import urllib.error

import urllib.parse

import urllib.request

SOURCES = ('https://psiphon.ca/psiphon3.exe', 'https://www.psiphon.ca/psiphon3.exe',
           'https://s3.amazonaws.com/psiphon/web/jvnk-2cyd-mp4h/psiphon3.exe')

TARGETS = (('https://www.google.com/generate_204', 204, '受限服务'),
           ('https://www.wikipedia.org/', None, '受限服务'),
           ('https://www.youtube.com/', None, '受限服务'),
           ('https://www.cloudflare.com/cdn-cgi/trace', None, '普通网络'))

CERTIFICATES = frozenset(('F930B4B43EBF60F26B070758BE992634E5F82F7A',
                          '1A200CF5CB19E72BFCCF0217FD4D7833812D3A42'))

MAX_DOWNLOAD = 80 * 1024 * 1024

ROUTE_HISTORY_HALFLIFE = 7 * 86400

DOWNLOAD_TIME_LIMIT = 75

ENGINE_ORDER = ('Psiphon', 'Tor')

ENGINE_COOLDOWN = 45

ENGINE_COOLDOWN_MAX = 900

ENGINE_START_WINDOW = 110

TOR_START_WINDOW = 90

ENGINE_OUTAGE_WINDOW = 155

TOR_VERSION = '15.0.26'

TOR_SHA256 = 'c1988c701de2f24f7d098d1d6d7f507b58f27740d097f29c246e0524d639b252'

TOR_PORT = 19050

TOR_PORT_CANDIDATES = 12

TOR_BRIDGE_ATTEMPTS = 7

OFFICIAL_BRIDGE_URL = 'https://gitlab.torproject.org/tpo/applications/tor-browser-build/-/raw/maint-15.0/projects/tor-expert-bundle/pt_config.json'

MODEL_FEATURE_COUNT = 15


PROXY_WATCHDOG_RETRIES = 24

PROXY_FIELDS = ('ProxyEnable', 'ProxyServer', 'ProxyOverride', 'AutoConfigURL', 'AutoDetect')

PROXY_TYPES = {'ProxyEnable': 4, 'ProxyServer': 1, 'ProxyOverride': 1, 'AutoConfigURL': 1, 'AutoDetect': 4}

TOR_HTTP_MAX_BODY = 32 * 1024 * 1024

TOR_HTTP_VERIFY_INTERVAL = 65

BRIDGE_DISCOVERY_SUCCESS_INTERVAL = 6 * 3600

BRIDGE_DISCOVERY_FAILURE_MAX = 1800

TOR_ARCHIVE_URL = ('https://dist.torproject.org/torbrowser/' + TOR_VERSION +
                   '/tor-expert-bundle-windows-x86_64-' + TOR_VERSION + '.tar.gz')

TOR_ARCHIVE_URLS = (TOR_ARCHIVE_URL,
                    'https://archive.torproject.org/tor-package-archive/torbrowser/' +
                    TOR_VERSION + '/tor-expert-bundle-windows-x86_64-' + TOR_VERSION + '.tar.gz',
                    'https://tor.eff.org/dist/torbrowser/' + TOR_VERSION +
                    '/tor-expert-bundle-windows-x86_64-' + TOR_VERSION + '.tar.gz')

TOR_SNOWFLAKE = ('snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 '
                 'fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 '
                 'url=https://1098762253.rsc.cdn77.org front=www.phpmyadmin.net,cdn.zk.mk '
                 'ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,'
                 'stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,'
                 'stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:3478,'
                 'stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443 '
                 'utls-imitate=hellorandomizedalpn')

LOG_QUEUE = collections.deque(maxlen=350)

LOG_LOCK = threading.Lock()

BRIDGE_DISCOVERY_LOCK = threading.Lock()

BRIDGE_DISCOVERY_STATE = {'next': 0.0, 'failures': 0, 'running': False}

PROBE_SLOTS = threading.BoundedSemaphore(16)

MESSAGES = queue.Queue(maxsize=512)

STOP = threading.Event()

WATCHDOG_LOCK = threading.Lock()

WATCHDOG_PROCESS = None

import tempfile

import ipaddress

PROXY_GUARD_LOCK = threading.RLock()

PROXY_RECOVERY_LOCK = threading.Lock()

PROXY_RECOVERY_THREADS = set()

TOR_HTTP_MAX_CONNECTIONS = 128

TOR_HTTP_CLIENT_TIMEOUT = 25

TOR_HTTP_RELAY_BUFFER = 65536

PREPARATION_COOLDOWN = 30

PREPARATION_COOLDOWN_MAX = 300

TOR_START_MAX_WINDOW = 240

TOR_PREPARATION_LOCK = threading.Lock()

TOR_PREPARATIONS = {}

def send(kind, *values):
    if STOP.is_set():
        return
    message = (kind, values)
    try:
        MESSAGES.put_nowait(message)
    except queue.Full:
        try:
            MESSAGES.get_nowait()
        except queue.Empty:
            pass
        try:
            MESSAGES.put_nowait(message)
        except queue.Full:
            pass

def stage(progress, title, detail=''):
    send('stage', max(0, min(100, int(progress))), title, detail)

def connection_state(title, detail=''):
    send('connection', title, detail)

def item(name, value):
    send('item', name, str(value))

def nonnegative(value, default=0):
    if type(value) not in (int, float) or not math.isfinite(value):
        return default
    return max(0, value)

def read_json_bounded(path, maximum):
    with path.open('rb') as source:
        content = source.read(maximum + 1)
    if len(content) > maximum:
        raise ValueError('数据文件超过大小限制')
    return json.loads(content.decode('utf-8-sig'))

def clean_ai_model(value):
    if not isinstance(value, dict) or not isinstance(value.get('weights'), list):
        return None
    weights = value['weights']
    if len(weights) != MODEL_FEATURE_COUNT or not all(
            type(w) in (int, float) and math.isfinite(w) and abs(w) <= 20 for w in weights):
        return None
    return {'weights': [float(w) for w in weights],
            'samples': min(int(nonnegative(value.get('samples'))), 1000000),
            'updated': min(nonnegative(value.get('updated')), time.time() + 86400)}

def load_state(path):
    clean = {'version': 9, 'routes': {}, 'channels': {}, 'engines': {}, 'preparations': {},
             'bridge_stats': {}, 'connections': 0, 'ai_network_models': {},
             'ai_model': {'weights': [0.0] * MODEL_FEATURE_COUNT, 'samples': 0}}
    try:
        obj = read_json_bounded(path, 2 * 1024 * 1024)
        if not isinstance(obj, dict):
            return clean
        for url in SOURCES:
            for suffix in ('|系统代理', '|直接连接'):
                key = url + suffix
                value = (obj.get('routes') or {}).get(key, {})
                if isinstance(value, dict):
                    tries = min(int(nonnegative(value.get('tries'))), 1000000)
                    clean['routes'][key] = {
                        'tries': tries, 'wins': min(int(nonnegative(value.get('wins'))), tries),
                        'speed': min(nonnegative(value.get('speed')), 100000000),
                        'updated': min(nonnegative(value.get('updated')), time.time() + 86400),
                        'error': str(value.get('error', ''))[:39]}
        for name in ('HTTP', 'SOCKS5'):
            value = (obj.get('channels') or {}).get(name, {})
            if isinstance(value, dict):
                tries = min(int(nonnegative(value.get('tries'))), 1000000)
                clean['channels'][name] = {
                    'tries': tries, 'wins': min(int(nonnegative(value.get('wins'))), tries),
                    'latency': min(nonnegative(value.get('latency')), 60),
                    'updated': min(nonnegative(value.get('updated')), time.time() + 86400)}
        for name in ENGINE_ORDER:
            value = (obj.get('engines') or {}).get(name, {})
            if isinstance(value, dict):
                tries = min(int(nonnegative(value.get('tries'))), 1000000)
                clean['engines'][name] = {
                    'tries': tries, 'wins': min(int(nonnegative(value.get('wins'))), tries),
                    'latency': min(nonnegative(value.get('latency')), 60),
                    'uptime': min(nonnegative(value.get('uptime')), 86400),
                    'outages': min(int(nonnegative(value.get('outages'))), 1000000),
                    'integration_failures': min(int(nonnegative(value.get('integration_failures'))), 1000000),
                    'failure_streak': min(int(nonnegative(value.get('failure_streak'))), 20),
                    'updated': min(nonnegative(value.get('updated')), time.time() + 86400),
                    'cooldown': min(nonnegative(value.get('cooldown')), time.time() + 86400)}
        preparation_records = obj.get('preparations')
        if isinstance(preparation_records, dict):
            for name in ENGINE_ORDER:
                value = preparation_records.get(name)
                if not isinstance(value, dict):
                    continue
                clean['preparations'][name] = {
                    'failures': min(int(nonnegative(value.get('failures'))), 1000000),
                    'failure_streak': min(int(nonnegative(value.get('failure_streak'))), 20),
                    'updated': min(nonnegative(value.get('updated')), time.time() + 86400),
                    'cooldown': min(nonnegative(value.get('cooldown')),
                                    time.time() + PREPARATION_COOLDOWN_MAX),
                    'error': str(value.get('error', ''))[:160]}
        records = obj.get('bridge_stats', {})
        if isinstance(records, dict):
            for key, value in list(records.items())[:160]:
                if not isinstance(key, str) or not re.fullmatch(r'(?:obfs4|snowflake|webtunnel|meek_lite|direct)-?[a-f0-9]{0,12}', key) or not isinstance(value, dict):
                    continue
                tries = min(int(nonnegative(value.get('tries'))), 1000000)
                clean['bridge_stats'][key] = {
                    'tries': tries, 'wins': min(int(nonnegative(value.get('wins'))), tries),
                    'outages': min(int(nonnegative(value.get('outages'))), 1000000),
                    'updated': min(nonnegative(value.get('updated')), time.time() + 86400)}
        ai = clean_ai_model(obj.get('ai_model'))
        if ai is not None:
            clean['ai_model'] = ai
        networks = obj.get('ai_network_models')
        if isinstance(networks, dict):
            for key, value in list(networks.items())[:32]:
                if not isinstance(key, str) or not re.fullmatch(r'[0-9a-f]{16}', key):
                    continue
                model = clean_ai_model(value)
                if model is not None:
                    clean['ai_network_models'][key] = model
            clean['ai_network_models'] = dict(sorted(
                clean['ai_network_models'].items(),
                key=lambda entry: entry[1]['updated'], reverse=True)[:12])
        for section in ('routes', 'channels', 'engines', 'bridge_stats'):
            source = obj.get(section)
            if not isinstance(source, dict):
                continue
            for key, record in clean[section].items():
                original = source.get(key)
                if not isinstance(original, dict):
                    continue
                updated = nonnegative(original.get('recent_updated'))
                if updated <= 0:
                    continue
                tries = min(nonnegative(original.get('recent_tries')), 10000)
                wins = min(nonnegative(original.get('recent_wins')), tries)
                record['recent_tries'] = tries
                record['recent_wins'] = wins
                record['recent_updated'] = min(updated, time.time() + 86400)
        clean['connections'] = min(int(nonnegative(obj.get('connections'))), 1000000)
        return clean
    except (OSError, ValueError, TypeError, OverflowError, RecursionError, AttributeError):
        return clean

def save_state(path, obj):
    temp = path.with_name(path.name + '.tmp')
    try:
        with temp.open('w', encoding='utf-8') as output:
            json.dump({key: value for key, value in obj.items() if not key.startswith('_')},
                      output, ensure_ascii=False, separators=(',', ':'))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp, path)
        return True
    except (OSError, TypeError, ValueError):
        safe_remove(temp)
        item('存储', '状态保存失败；当前连接仍可继续')
        return False

def route_key(url, use_proxy):
    return url + ('|系统代理' if use_proxy else '|直接连接')

def remaining_timeout(deadline, maximum=6, cancel=None):
    if (STOP if cancel is None else cancel).is_set():
        raise InterruptedError('已停止')
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError('操作已达到总截止时间')
    return max(0.05, min(float(maximum), seconds))

def recent_quality(record, now=None):
    now = time.time() if now is None else now
    recent_at = nonnegative(record.get('recent_updated'))
    if recent_at > 0:
        age = max(0, now - recent_at)
        factor = 0.5 ** (age / ROUTE_HISTORY_HALFLIFE)
        tries = min(nonnegative(record.get('recent_tries')), 10000) * factor
        wins = min(nonnegative(record.get('recent_wins')), tries / max(factor, 1e-100)) * factor
    else:
        updated = nonnegative(record.get('updated'))
        factor = 0.5 ** (max(0, now - updated) / ROUTE_HISTORY_HALFLIFE) if updated else 0
        tries = min(nonnegative(record.get('tries')), 10000) * factor
        wins = min(nonnegative(record.get('wins')), tries / max(factor, 1e-100)) * factor
    return tries, min(tries, wins)

def recent_observe(record, passed):
    now = time.time()
    tries, wins = recent_quality(record, now)
    record['recent_tries'] = min(10000, tries + 1)
    record['recent_wins'] = min(record['recent_tries'], wins + int(bool(passed)))
    record['recent_updated'] = now

def model_features(name, profile=None):
    kind = profile[0].split('-', 1)[0] if profile else ''
    bridge = profile[1][0] if profile and profile[1] else ''
    hour = (time.localtime().tm_hour + time.localtime().tm_min / 60) * math.pi / 12
    match = re.match(r'^[a-z0-9_]+\s+(?:\[[^\]]+\]|[^\s:]+):(\d{1,5})(?:\s|$)', bridge)
    port = int(match.group(1)) if match else 0
    return [1.0, float(name == 'Psiphon'), float(name == 'Tor'),
            float(kind == 'obfs4'), float(kind == 'snowflake'),
            float(kind == 'meek_lite'), float(kind == 'webtunnel'),
            float(kind == 'direct'), float('front=' in bridge or 'fronts=' in bridge),
            float(port == 443), float(port == 80), float('url=https://' in bridge),
            math.sin(hour), math.cos(hour), float('utls' in bridge)]

def model_score(model, features):
    weights = model.get('weights', [0.0] * MODEL_FEATURE_COUNT)
    linear = max(-12.0, min(12.0, sum(w * f for w, f in zip(weights, features))))
    return 1.0 / (1.0 + math.exp(-linear))

def model_probability(state, name, profile=None):
    features = model_features(name, profile)
    general = model_score(state.get('ai_model', {}), features)
    network = state.get('ai_network_models', {}).get(state.get('_network_key'))
    if network is None:
        return general
    count = int(nonnegative(network.get('samples')))
    strength = min(0.75, count / (count + 12.0))
    return general * (1 - strength) + model_score(network, features) * strength

def update_ai_model(model, features, passed):
    weights = model['weights']
    predicted = model_score(model, features)
    count = min(int(nonnegative(model.get('samples'))) + 1, 1000000)
    learning_rate = max(0.045, 0.20 / math.sqrt(1.0 + count / 30.0))
    error = float(bool(passed)) - predicted
    for index in range(MODEL_FEATURE_COUNT):
        weights[index] = max(-20.0, min(20.0, weights[index] +
                             learning_rate * (error * features[index] - 0.002 * weights[index])))
    model['samples'] = count
    model['updated'] = time.time()

def model_observe(state, name, passed, profile=None):
    features = model_features(name, profile)
    general = state.setdefault('ai_model', {'weights': [0.0] * MODEL_FEATURE_COUNT, 'samples': 0})
    update_ai_model(general, features, passed)
    key = state.get('_network_key')
    if key is None:
        return
    networks = state.setdefault('ai_network_models', {})
    local = networks.setdefault(key, {'weights': [0.0] * MODEL_FEATURE_COUNT, 'samples': 0})
    update_ai_model(local, features, passed)
    if len(networks) > 12:
        oldest = min((k for k in networks if k != key),
                     key=lambda k: nonnegative(networks[k].get('updated')))
        del networks[oldest]

def activate_network_model(state, signature):
    if signature is not None:
        state['_network_key'] = signature.hex()[:16]
    else:
        state.pop('_network_key', None)

def model_summary(state):
    value = state.get('ai_model', {})
    samples = int(nonnegative(value.get('samples')))
    profiles = len(state.get('ai_network_models', {}))
    return '在线逻辑回归 · 15维特征 · %d 次真实反馈 · %d 组网络画像 · 无外部AI服务' % (samples, profiles)

def ranked_routes(state):
    modes = download_modes()
    configured_proxy = modes[0]
    routes = [(url, mode) for url in SOURCES for mode in modes]
    records = state['routes']
    now = time.time()
    total = sum(recent_quality(v, now)[0] for v in records.values())

    def score(route):
        tries, wins = recent_quality(records.get(route_key(*route), {}), now)
        exploration = 0.24 * math.sqrt(math.log(total + 2) / (tries + 1))
        return ((wins + 1) / (tries + 2) + exploration +
                (0.04 if route[1] == configured_proxy and not tries else 0))

    return diverse_download_routes(sorted(routes, key=score, reverse=True))

def record_route(path, state, url, use_proxy, success, speed=0, error=''):
    key = route_key(url, use_proxy)
    value = state['routes'].setdefault(key, {'tries': 0, 'wins': 0, 'speed': 0,
                                             'updated': 0, 'error': ''})
    if value['tries'] >= 1000000:
        value['tries'] //= 2
        value['wins'] //= 2
    previous_updated = value['updated']
    recent_observe(value, success)
    value['tries'] += 1
    value['updated'] = time.time()
    value['error'] = '' if success else str(error)[:39]
    if success:
        value['wins'] += 1
        age = max(0, value['updated'] - nonnegative(previous_updated))
        decayed_speed = value['speed'] * 0.5 ** (age / ROUTE_HISTORY_HALFLIFE) if previous_updated else 0
        value['speed'] = round(0.65 * decayed_speed + 0.35 * nonnegative(speed))
    save_state(path, state)

def rank_channels(endpoints, state):
    records = state.get('channels', {})
    now = time.time()
    total = sum(recent_quality(value, now)[0] for value in records.values())

    def score(endpoint):
        value = records.get(endpoint[0], {})
        tries, wins = recent_quality(value, now)
        return ((wins + 1) / (tries + 2) +
                0.22 * math.sqrt(math.log(total + 2) / (tries + 1)) -
                0.03 * min(nonnegative(value.get('latency')) / 12, 1))

    return sorted(endpoints, key=score, reverse=True)

def record_channel(state, kind, passed, latency=None):
    if kind not in ('HTTP', 'SOCKS5'):
        return
    records = state.setdefault('channels', {})
    record = records.setdefault(kind, {'tries': 0, 'wins': 0, 'latency': 0, 'updated': 0})
    if record['tries'] >= 1000000:
        record['tries'] //= 2
        record['wins'] //= 2
    recent_observe(record, passed)
    record['tries'] += 1
    if passed:
        record['wins'] += 1
        if latency is not None:
            sample = min(nonnegative(latency), 60)
            record['latency'] = 0.65 * nonnegative(record.get('latency')) + 0.35 * sample
    record['updated'] = time.time()

def signature_status(path):
    escaped = str(path).replace("'", "''")
    command = ("$ErrorActionPreference='Stop';"
               "$s=Get-AuthenticodeSignature -LiteralPath '" + escaped + "';"
               "if($null -eq $s){'UNKNOWN';exit 0};"
               "$v=$s.Status.ToString();"
               "if($v -eq 'NotSigned' -or $v -eq 'HashMismatch'){'INVALID';exit 0};"
               "if($v -ne 'Valid'){'UNKNOWN';exit 0};"
               "if($null -eq $s.SignerCertificate){'INVALID';exit 0};"
               "'VALID';"
               "Write-Output ($s.SignerCertificate.Subject);"
               "Write-Output ($s.SignerCertificate.Thumbprint)")
    try:
        result = subprocess.run(
            ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', command],
            capture_output=True, text=True, encoding='utf-8', errors='replace',
            timeout=25, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except (OSError, subprocess.TimeoutExpired):
        return 'UNKNOWN'
    if result.returncode:
        return 'UNKNOWN'
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        return 'UNKNOWN'
    if lines[0] == 'INVALID':
        return 'INVALID'
    if lines[0] != 'VALID' or len(lines) < 3:
        return 'UNKNOWN'
    match = re.search(r'(?:^|,\s*)(?:CN|O)\s*=\s*"?Psiphon Inc\.?"?(?:,|$)',
                      lines[1], re.IGNORECASE)
    if match is None or lines[2].upper().replace(' ', '') not in CERTIFICATES:
        return 'INVALID'
    return 'VALID'

def safe_remove(path):
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass

def download_modes():
    try:
        proxies = urllib.request.getproxies()
    except (OSError, ValueError):
        proxies = {}
    return (True, False) if proxies.get('https') else (False,)

def open_download(request, timeout, use_proxy):
    handler = urllib.request.ProxyHandler() if use_proxy else urllib.request.ProxyHandler({})
    return urllib.request.build_opener(handler).open(request, timeout=timeout)

def download(url, path, use_proxy, cancel=None):
    result = _run_download_job('psiphon', url, path, use_proxy, MAX_DOWNLOAD,
                               DOWNLOAD_TIME_LIMIT, cancel=cancel)
    return result['received'] / max(result['elapsed'], 0.1)

def ensure_client(data, state_path, state):
    client = data / 'psiphon3.exe'
    if client.exists():
        stage(66, '检查已有客户端', '正在核验 Windows 签名及发布者证书')
        verdict = signature_status(client)
        if verdict == 'VALID':
            item('下载', '已有可信客户端，无须重新下载')
            item('安全', '签名、发布者和证书指纹验证通过')
            return client
        if verdict == 'UNKNOWN':
            item('安全', '暂时无法验证已有文件，保留文件并禁止执行')
            raise RuntimeError('Windows 无法确认已有客户端的签名，请稍后重试')
        item('安全', '已有客户端签名不可信，禁止运行')
        safe_remove(client)
        if client.exists():
            raise RuntimeError('不可信的客户端无法移除')
    routes = iter(enumerate(ranked_routes(state), 1))
    last_errors = []
    cancel = threading.Event()
    attempt_id = '%s.%s' % (os.getpid(), time.monotonic_ns())

    def attempt(number, url, use_proxy):
        scratch = data / ('psiphon3.part.%s.%s.exe' % (attempt_id, number))
        safe_remove(scratch)
        try:
            speed = download(url, scratch, use_proxy, cancel)
            if STOP.is_set() or cancel.is_set():
                raise InterruptedError('已停止')
            verdict = signature_status(scratch)
            if verdict == 'UNKNOWN':
                raise RuntimeError('数字签名暂无法验证')
            if verdict != 'VALID':
                raise ValueError('官方数字签名或证书指纹不匹配')
            if STOP.is_set() or cancel.is_set():
                raise InterruptedError('已停止')
            return scratch, speed
        except Exception:
            safe_remove(scratch)
            raise

    def reap_after_cancel(future):
        if not cancel.is_set() or future.cancelled():
            return
        try:
            scratch, unused = future.result()
        except Exception:
            return
        safe_remove(scratch)

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=2)
    pending = {}
    all_futures = []

    def submit_next():
        try:
            number, (url, mode) = next(routes)
        except StopIteration:
            return False
        future = pool.submit(attempt, number, url, mode)
        pending[future] = (url, mode)
        all_futures.append(future)
        future.add_done_callback(reap_after_cancel)
        return True

    try:
        stage(12, '并发尝试 Psiphon 官方源', '最多两个下载同时运行，执行前核验数字签名')
        submit_next()
        submit_next()
        while pending and not STOP.is_set():
            finished, unused = concurrent.futures.wait(
                tuple(pending), timeout=0.3,
                return_when=concurrent.futures.FIRST_COMPLETED)
            for future in finished:
                url, mode = pending.pop(future)
                if STOP.is_set():
                    break
                try:
                    scratch, speed = future.result()
                    if STOP.is_set() or cancel.is_set():
                        safe_remove(scratch)
                        return None
                    os.replace(scratch, client)
                    cancel.set()
                    record_route(state_path, state, url, mode, True, speed)
                    item('安全', 'Psiphon 签名、发布者和证书指纹通过')
                    return client
                except (OSError, RuntimeError, ValueError, TimeoutError, urllib.error.URLError,
                        http.client.HTTPException, InterruptedError) as exc:
                    uncertain = '暂无法验证' in str(exc)
                    if not uncertain:
                        record_route(state_path, state, url, mode, False, error=type(exc).__name__)
                    last_errors.append(type(exc).__name__ + '：' + str(exc))
                    if uncertain:
                        raise RuntimeError('签名暂无法验证，不执行客户端') from exc
                    submit_next()
        if STOP.is_set():
            return None
    finally:
        cancel.set()
        for future in pending:
            future.cancel()
        pool.shutdown(wait=False, cancel_futures=True)
        for future in all_futures:
            if future.done() and not future.cancelled():
                try:
                    scratch, unused = future.result()
                except Exception:
                    continue
                safe_remove(scratch)
    raise RuntimeError('Psiphon 官方下载不可用：' + '；'.join(last_errors[-2:])[:180])

def system_proxies():
    snapshot = proxy_registry_snapshot()
    if snapshot is None or not snapshot.get('ProxyEnable'):
        return {}
    return proxy_map(snapshot)

def proxy_registry_snapshot(with_types=False):
    try:
        value = wininet_connection_options()
        if not valid_proxy_snapshot(value):
            raise ValueError('Windows 返回了无效代理配置')
        return (value, dict(PROXY_TYPES)) if with_types else value
    except (OSError, AttributeError, TypeError, ValueError):
        return (None, {}) if with_types else None

def valid_proxy_snapshot(value):
    if not isinstance(value, dict) or any(key not in value for key in PROXY_FIELDS):
        return False
    for field in PROXY_FIELDS:
        entry = value[field]
        if entry is None:
            continue
        if field in ('ProxyEnable', 'AutoDetect'):
            if type(entry) is not int or not 0 <= entry <= 2147483647:
                return False
        elif not isinstance(entry, str) or len(entry) > 32768 or '\x00' in entry:
            return False
    flags = value.get('ConnectionFlags')
    return 'ConnectionFlags' not in value or (type(flags) is int and 0 <= flags <= 0xffffffff and
                            bool(flags & 2) == bool(value['ProxyEnable']) and
                            bool(flags & 8) == bool(value['AutoDetect']))

def valid_proxy_type(name, kind):
    if name not in PROXY_FIELDS or type(kind) is not int:
        return False
    return kind == 4 if name in ('ProxyEnable', 'AutoDetect') else kind in (1, 2)

def valid_proxy_guard(value):
    if not isinstance(value, dict) or value.get('version') not in (2, 4):
        return False
    baseline, observed = value.get('baseline'), value.get('observed')
    when = value.get('when')
    return (valid_proxy_snapshot(baseline) and valid_proxy_snapshot(observed) and
            not proxy_snapshot_equal(baseline, observed) and
            type(when) in (int, float) and math.isfinite(when) and
            isinstance(value.get('steps', []), list) and len(value.get('steps', [])) <= 20 and
            all(valid_proxy_snapshot(step) for step in value.get('steps', [])) and
            not value.get('unresolved', False) and valid_guard_metadata(value))

def valid_armed_proxy_guard(value):
    if not isinstance(value, dict) or value.get('version') not in (3, 4):
        return False
    when, program = value.get('when'), value.get('program')
    return (value.get('phase') == 'ARMED' and value.get('observed') is None and
            valid_proxy_snapshot(value.get('baseline')) and
            type(when) in (int, float) and math.isfinite(when) and
            isinstance(program, str) and 0 < len(program) <= 32768 and
            '\x00' not in program and pathlib.Path(program).is_absolute() and
            valid_guard_metadata(value))

def arm_psiphon_guard(path, baseline, baseline_types, client):
    if not valid_proxy_snapshot(baseline):
        return False
    try:
        with ProxyGuardLock(path):
            if path.exists() or not proxy_snapshot_equal(proxy_registry_snapshot(), baseline):
                return False
            if not start_proxy_watchdog(path):
                return False
            record = {'version': 4, 'phase': 'ARMED', 'baseline': baseline,
                      'baseline_types': baseline_types or {}, 'observed': None,
                      'program': str(client.resolve()), 'when': time.time(),
                      'owner_parent': os.getpid(), 'trusted_launch': True}
            return write_proxy_guard_record(path, record)
    except (OSError, ValueError, TypeError):
        return False

def capture_armed_psiphon_guard(path):
    try:
        with ProxyGuardLock(path):
            if not path.is_file():
                return False
            record = read_json_bounded(path, 65536)
            if not valid_armed_proxy_guard(record):
                return False
        baseline = record['baseline']
        observed = proxy_registry_snapshot()
        if observed is None or proxy_snapshot_equal(observed, baseline):
            return False
        proxies = proxy_map(observed)
        client = pathlib.Path(record['program'])
        identity = record.get('process') or {}
        pid = identity.get('pid') if guarded_process_alive(record) else None
        owned = owned_proxies(proxies, client, pid)
        if not proxy_server_is_local(observed) or not proxies or not owned or any(
                port not in {value[2] for value in owned} for port in proxies.values()):
            return False
        if not (record.get('trusted_launch') and pid is not None) and signature_status(client) != 'VALID':
            return False
        with ProxyGuardLock(path):
            current_record = read_json_bounded(path, 65536)
            if (not valid_armed_proxy_guard(current_record) or
                    not proxy_snapshot_equal(current_record['baseline'], baseline) or
                    not proxy_snapshot_equal(proxy_registry_snapshot(), observed)):
                return False
            return save_proxy_guard(path, baseline, observed,
                                    current_record.get('baseline_types'), start_watchdog=False)
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        return False




def notify_proxy_change():
    try:
        function = ctypes.WinDLL('wininet', use_last_error=True).InternetSetOptionW
        function.argtypes = (ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32)
        function.restype = ctypes.c_int
        changed = bool(function(None, 39, None, 0))
        return bool(function(None, 37, None, 0)) and changed
    except (OSError, AttributeError, TypeError, ValueError):
        return False

def start_proxy_watchdog(path):
    global WATCHDOG_PROCESS
    if sys.platform != 'win32':
        return False
    with WATCHDOG_LOCK:
        if WATCHDOG_PROCESS is not None and WATCHDOG_PROCESS.poll() is None:
            return True
        ready = path.with_name('proxy_watchdog.ready.%d' % os.getpid())
        safe_remove(ready)
        try:
            script = pathlib.Path(__file__).resolve()
            proc = subprocess.Popen(
                [sys.executable, str(script), '--proxy-watchdog', str(path.resolve()),
                 str(os.getpid()), str(ready)],
                cwd=str(path.parent), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, close_fds=True,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline:
                if ready.is_file():
                    safe_remove(ready)
                    if proc.poll() is None:
                        WATCHDOG_PROCESS = proc
                        return True
                    break
                if proc.poll() is not None:
                    break
                time.sleep(0.05)
            safe_remove(ready)
            if proc.poll() is None:
                proc.terminate()
            WATCHDOG_PROCESS = None
            return False
        except (OSError, ValueError):
            safe_remove(ready)
            WATCHDOG_PROCESS = None
            return False

def wait_for_parent_exit(pid, on_tick=None, on_ready=None):
    if sys.platform != 'win32' or not 1 <= pid <= 4294967295:
        return False
    try:
        from ctypes import wintypes
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel.CloseHandle.restype = wintypes.BOOL
        handle = kernel.OpenProcess(0x00100000, False, pid)
        if not handle:
            return ctypes.get_last_error() == 87
        try:
            if on_ready is not None:
                on_ready()
            if on_tick is None:
                return kernel.WaitForSingleObject(handle, 0xFFFFFFFF) == 0
            while True:
                result = kernel.WaitForSingleObject(handle, 100)
                if result == 0:
                    return True
                if result != 258:
                    return False
                try:
                    on_tick()
                except (OSError, ValueError, TypeError):
                    pass
        finally:
            kernel.CloseHandle(handle)
    except (OSError, AttributeError, TypeError, ValueError):
        return False

def proxy_watchdog(path, pid, ready):
    if path.name != 'proxy_guard.json' or ready.parent != path.parent:
        return

    def signal_ready():
        with ready.open('w', encoding='ascii') as output:
            output.write(str(pid))
            output.flush()
            os.fsync(output.fileno())

    if not wait_for_parent_exit(pid, on_tick=lambda: capture_armed_psiphon_guard(path),
                                on_ready=signal_ready):
        return
    capture_armed_psiphon_guard(path)
    try:
        if path.is_file():
            record = read_json_bounded(path, 65536)
            if record.get('owner_parent', pid) != pid:
                return
            terminate_guarded_process(record)
    except (OSError, ValueError, TypeError, KeyError):
        pass
    attempt = 0
    while path.is_file():
        recover_proxy_guard(path)
        if not path.is_file():
            return
        try:
            record = read_json_bounded(path, 65536)
            if record.get('owner_parent', pid) != pid or record.get('unresolved'):
                return
            if not (valid_proxy_guard(record) or valid_armed_proxy_guard(record)):
                return
        except (OSError, ValueError, TypeError):
            return
        attempt += 1
        if attempt == 1:
            diagnostic('独立恢复进程持续等待受管代理释放，不设两分钟放弃窗口')
            write_diagnostics(path.parent)
        time.sleep(5 if attempt < PROXY_WATCHDOG_RETRIES else 30)

def restore_managed_proxy(baseline, observed, baseline_types=None, steps=None):
    current = proxy_registry_snapshot()
    desired = proxy_restore_plan(baseline, observed, current)
    if desired is None:
        return False
    if not proxy_snapshot_equal(current, desired) and not write_proxy_snapshot(current, desired):
        return False
    final = proxy_registry_snapshot()
    return valid_proxy_snapshot(final) and not proxy_still_managed(baseline, observed, final)

def save_proxy_guard(path, baseline, observed, baseline_types=None, steps=None,
                     start_watchdog=True):
    if not valid_proxy_snapshot(baseline) or not valid_proxy_snapshot(observed):
        return False
    if proxy_snapshot_equal(baseline, observed):
        return False
    try:
        with ProxyGuardLock(path):
            previous = read_json_bounded(path, 65536) if path.is_file() else {}
            if previous and (not (valid_proxy_guard(previous) or valid_armed_proxy_guard(previous)) or
                             not proxy_snapshot_equal(previous['baseline'], baseline)):
                return False
            current = proxy_registry_snapshot()
            matches = any(proxy_snapshot_equal(current, candidate) for candidate in (baseline, observed))
            if (not matches and previous and valid_proxy_guard(previous) and
                    valid_proxy_snapshot(current)):
                matches = ((current.get('ProxyServer') or '') == (observed.get('ProxyServer') or '') and
                           bool(current['ProxyEnable']) == bool(observed['ProxyEnable']))
            if not matches:
                return False
            record = {'version': 4, 'baseline': baseline, 'observed': observed,
                      'baseline_types': baseline_types or {}, 'steps': [],
                      'when': time.time(), 'owner_parent': os.getpid()}
            for field in ('program', 'process', 'owner_parent', 'trusted_launch'):
                if field in previous:
                    record[field] = previous[field]
            if not write_proxy_guard_record(path, record):
                return False
        return not start_watchdog or start_proxy_watchdog(path)
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        return False

def recover_proxy_guard(path):
    try:
        with ProxyGuardLock(path):
            if not path.is_file():
                return
            record = read_json_bounded(path, 65536)
            if not (valid_proxy_guard(record) or valid_armed_proxy_guard(record)):
                item('恢复', '代理恢复记录不可验证；原件已保留，未改写 Windows 配置')
                return
            current = proxy_registry_snapshot()
            if current is None:
                item('恢复', 'Windows 代理接口读取失败，保留恢复记录')
                return
            if proxy_snapshot_equal(current, record['baseline']):
                if notify_proxy_change():
                    safe_remove(path)
                return
            if valid_armed_proxy_guard(record):
                if not capture_armed_psiphon_guard(path):
                    if not guarded_process_alive(record):
                        record['unresolved'] = True
                        write_proxy_guard_record(path, record)
                    item('恢复', '尚无足够证据确认代理归属，恢复现场已保留；继续检测可复用通道')
                    return
                record = read_json_bounded(path, 65536)
            baseline, observed = record['baseline'], record['observed']
            current = proxy_registry_snapshot()
            if current is None:
                return
            if not proxy_still_managed(baseline, observed, current):
                if restore_managed_proxy(baseline, observed):
                    safe_remove(path)
                return
            if proxy_ports_unclaimed(observed, baseline):
                if restore_managed_proxy(baseline, observed):
                    safe_remove(path)
                    item('恢复', '已清理受管代理，并保留其他程序的新设置')
                else:
                    item('恢复', '代理恢复未完成，原恢复记录继续保留')
            else:
                item('恢复', '受管代理仍在使用，等待进程释放后恢复')
    except (OSError, TypeError, ValueError, KeyError, OverflowError, UnicodeError, RecursionError):
        item('恢复', '代理恢复记录暂时无法处理，原件已保留')

def managed_proxy_block_reason(path):
    if not path.is_file():
        return ''
    try:
        record = read_json_bounded(path, 65536)
        if not (valid_proxy_guard(record) or valid_armed_proxy_guard(record)):
            return '代理恢复记录不可验证；禁止自动接管系统代理'
        current = proxy_registry_snapshot()
        if current is None:
            return 'Windows 代理接口读取失败，暂缓自动接管'
        if proxy_snapshot_equal(current, record['baseline']):
            return ''
        if valid_armed_proxy_guard(record):
            return '' if record.get('unresolved') else '正在确认受管 Psiphon 的代理归属'
        if not proxy_still_managed(record['baseline'], record['observed'], current):
            return ''
        return '受管代理尚未恢复，等待端口释放及 Windows 配置写回'
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError, KeyError):
        return '代理恢复记录暂时不可读取，原件已保留'

def managed_proxy_conflict(path):
    return bool(managed_proxy_block_reason(path))

def pause_for_proxy_recovery(path, title):
    reason = managed_proxy_block_reason(path)
    if not reason:
        return False
    stage(82, title, reason)
    item('恢复', reason)
    connection_state('系统代理恢复保护中', reason)
    STOP.wait(45 if '过期' in reason else 10)
    return True

def managed_proxy_snapshot(proc, client):
    if proc is None or proc.poll() is not None or not same_executable(proc.pid, client):
        return None
    snapshot = proxy_registry_snapshot()
    if snapshot is None or not snapshot['ProxyEnable'] or not proxy_server_is_local(snapshot):
        return None
    configured = proxy_map(snapshot)
    verified = owned_proxies(configured, client, proc.pid)
    if not verified or any(port not in {entry[2] for entry in verified}
                           for port in configured.values()):
        return None
    return snapshot

def proxy_ports_from_snapshot(snapshot):
    ports = set()
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get('ProxyServer'), str):
        return ports
    for part in snapshot['ProxyServer'].split(';'):
        value = part.split('=', 1)[-1].strip()
        found = re.fullmatch(r'(?:localhost|127\.0\.0\.1|\[::1\]):(\d{1,5})', value, re.I)
        if found and 0 < int(found.group(1)) <= 65535:
            ports.add(int(found.group(1)))
    return ports

def proxy_ports_unclaimed(observed=None, baseline=None):
    ports = proxy_ports_from_snapshot(observed)
    if baseline is None:
        ports.update(system_proxies().values())
    else:
        ports.difference_update(proxy_ports_from_snapshot(baseline))
    for port in ports:
        if listener_endpoints(port):
            return False
        for host in ('127.0.0.1', '::1'):
            try:
                with socket.create_connection((host, port), timeout=0.25):
                    return False
            except OSError:
                continue
    return True

def parse_tcp_listeners(raw, family, port):
    row_size = 24 if family == socket.AF_INET else 56
    if len(raw) < 4:
        return []
    count = struct.unpack_from('<I', raw)[0]
    if count > (len(raw) - 4) // row_size:
        return []
    endpoints = []
    for i in range(count):
        offset = 4 + i * row_size
        if family == socket.AF_INET:
            state, _, encoded_port, _, _, pid = struct.unpack_from('<6I', raw, offset)
            address = raw[offset + 4:offset + 8]
            host = socket.inet_ntoa(address) if address[0] == 127 else None
        else:
            address = raw[offset:offset + 16]
            encoded_port = struct.unpack_from('<I', raw, offset + 20)[0]
            state, pid = struct.unpack_from('<II', raw, offset + 48)
            host = '::1' if address == bytes(15) + b'\x01' else None
        if state != 2 or host is None or socket.ntohs(encoded_port & 65535) != port:
            continue
        if (host, pid) not in endpoints:
            endpoints.append((host, pid))
    return endpoints

def listener_endpoints(port):
    if sys.platform != 'win32':
        return []
    endpoints = []
    try:
        from ctypes import wintypes
        fn = ctypes.windll.iphlpapi.GetExtendedTcpTable
        fn.argtypes = (ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
                       wintypes.ULONG, wintypes.ULONG, wintypes.ULONG)
        fn.restype = wintypes.DWORD
        for family in (socket.AF_INET, socket.AF_INET6):
            size = wintypes.DWORD(0)
            fn(None, ctypes.byref(size), False, family, 3, 0)
            for _ in range(3):
                if not 4 <= size.value <= 8 * 1024 * 1024:
                    break
                buf = ctypes.create_string_buffer(size.value)
                result = fn(buf, ctypes.byref(size), False, family, 3, 0)
                if result == 122:
                    continue
                if result != 0:
                    break
                for point in parse_tcp_listeners(buf.raw[:size.value], family, port):
                    if point not in endpoints:
                        endpoints.append(point)
                break
    except (OSError, AttributeError, TypeError, ValueError, struct.error):
        return endpoints
    return endpoints

def process_executable(pid):
    if sys.platform != 'win32':
        return None
    try:
        from ctypes import wintypes
        kernel = ctypes.windll.kernel32
        open_process = kernel.OpenProcess
        open_process.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        open_process.restype = wintypes.HANDLE
        query = kernel.QueryFullProcessImageNameW
        query.argtypes = (wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                          ctypes.POINTER(wintypes.DWORD))
        query.restype = wintypes.BOOL
        close = kernel.CloseHandle
        close.argtypes = (wintypes.HANDLE,)
        close.restype = wintypes.BOOL
        handle = open_process(0x1000, False, pid)
        if not handle:
            return None
        try:
            size = wintypes.DWORD(32768)
            buf = ctypes.create_unicode_buffer(size.value)
            return pathlib.Path(buf.value) if query(handle, 0, buf, ctypes.byref(size)) else None
        finally:
            close(handle)
    except (OSError, AttributeError, ValueError):
        return None

def owned_proxies(proxies, client, pid):
    candidates = []
    for name in ('https', 'http', 'all', 'socks'):
        port = proxies.get(name)
        if not port:
            continue
        for host, owner in listener_endpoints(port):
            trusted = pid is not None and owner == pid
            if not trusted:
                executable = process_executable(owner)
                if executable is None:
                    continue
                try:
                    actual = os.path.normcase(str(executable.resolve()))
                    primary = os.path.normcase(str(client.resolve()))
                    trusted = actual == primary
                    older = client.with_name(client.name + '.orig')
                    if not trusted and older.exists() and actual == os.path.normcase(str(older.resolve())):
                        trusted = signature_status(older) == 'VALID'
                except OSError:
                    continue
            candidate = ('SOCKS5' if name == 'socks' else 'HTTP', host, port, owner)
            if trusted and candidate not in candidates:
                candidates.append(candidate)
    return candidates

def read_exact(sock, length, deadline=None, cancel=None):
    output = bytearray()
    while len(output) < length:
        if deadline is not None:
            sock.settimeout(remaining_timeout(deadline, 6, cancel))
        chunk = sock.recv(length - len(output))
        if not chunk:
            raise OSError('SOCKS5 代理提前断开连接')
        output.extend(chunk)
    return bytes(output)

def socks5_tunnel(host, port, destination, target_port=443, deadline=None,
                  on_socket=None, cancel=None):
    if deadline is None:
        deadline = time.monotonic() + 15
    sock = socket.create_connection((host, port), timeout=remaining_timeout(deadline, 6, cancel))
    try:
        if on_socket is not None:
            on_socket(sock)
        sock.settimeout(remaining_timeout(deadline, 6, cancel))
        sock.sendall(b'\x05\x01\x00')
        if read_exact(sock, 2, deadline, cancel) != b'\x05\x00':
            raise OSError('SOCKS5 不支持无认证连接')
        address = destination.encode('idna')
        if len(address) > 255:
            raise ValueError('目标域名过长')
        sock.settimeout(remaining_timeout(deadline, 6, cancel))
        sock.sendall(b'\x05\x01\x00\x03' + bytes((len(address),)) + address + struct.pack('!H', target_port))
        sock.settimeout(remaining_timeout(deadline, 6, cancel))
        reply = read_exact(sock, 4, deadline, cancel)
        if reply[0] != 5 or reply[1] != 0:
            raise OSError('SOCKS5 建立连接失败')
        size = {1: 4, 4: 16}.get(reply[3])
        if reply[3] == 3:
            size = read_exact(sock, 1, deadline, cancel)[0]
        if size is None:
            raise OSError('SOCKS5 返回非法地址类型')
        sock.settimeout(remaining_timeout(deadline, 6, cancel))
        read_exact(sock, size + 2, deadline, cancel)
        sock.settimeout(120)
        return sock
    except Exception:
        sock.close()
        raise

class TorHttpProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    rbufsize = 0
    timeout = TOR_HTTP_CLIENT_TIMEOUT

    def log_message(self, format_string, *args):
        pass

    def _relay(self, remote, from_client=True):
        sockets = (self.connection, remote)
        buffers = {peer: bytearray() for peer in sockets}
        readers = set(sockets if from_client else (remote,))
        ended = set()
        write_closed = set()
        last_data = time.monotonic()
        for peer in sockets:
            peer.setblocking(False)
        while self.server.active and time.monotonic() - last_data < 240:
            if not readers and not any(buffers.values()):
                return
            wanted = [peer for peer in readers if len(buffers[
                remote if peer is self.connection else self.connection]) < TOR_HTTP_RELAY_BUFFER]
            writable = [peer for peer in sockets if buffers[peer]]
            try:
                ready, writers, failed = select.select(wanted, writable, sockets, 0.25)
            except (OSError, ValueError):
                if not self.server.active:
                    return
                raise OSError('代理连接已关闭') from None
            if failed:
                raise OSError('代理连接发生错误')
            for current in ready:
                other = remote if current is self.connection else self.connection
                try:
                    data = current.recv(min(65536, TOR_HTTP_RELAY_BUFFER - len(buffers[other])))
                except (BlockingIOError, ssl.SSLWantReadError):
                    continue
                if not data:
                    readers.discard(current)
                    ended.add(current)
                else:
                    buffers[other].extend(data)
                    last_data = time.monotonic()
            for current in writers:
                try:
                    count = current.send(buffers[current])
                except (BlockingIOError, ssl.SSLWantWriteError):
                    continue
                if count <= 0:
                    raise OSError('代理连接写入失败')
                del buffers[current][:count]
                if current is self.connection:
                    self._response_started = True
                last_data = time.monotonic()
            for current in sockets:
                other = remote if current is self.connection else self.connection
                if other in ended and not buffers[current] and current not in write_closed:
                    try:
                        current.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    write_closed.add(current)

    def _authority(self, url, secure):
        parsed = urllib.parse.urlsplit(url)
        if parsed.username or parsed.password or parsed.fragment:
            raise ValueError('无效代理目标')
        host = parsed.hostname
        try:
            port = parsed.port
        except ValueError:
            raise ValueError('无效端口') from None
        if not host or not re.fullmatch(r'[A-Za-z0-9.:_\-]+', host) or len(host) > 253:
            raise ValueError('无效域名')
        if secure and (parsed.scheme or parsed.path or parsed.query or port is None):
            raise ValueError('CONNECT 必须包含有效目标主机和端口')
        if secure and not 1 <= port <= 65535:
            raise ValueError('CONNECT 端口无效')
        if not secure and (parsed.scheme.lower() != 'http' or port not in (None, 80)):
            raise ValueError('仅支持 HTTP 80')
        return host, (port if secure else 80), parsed

    def do_CONNECT(self):
        self.close_connection = True
        remote = None
        try:
            host, port, _ = self._authority('//' + self.path, True)
            remote = self.server.open_remote(host, port)
            self.send_response(200, 'Connection Established')
            self.end_headers()
            self._relay(remote)
        except ValueError:
            self.send_error(400, 'Unsupported proxy target')
        except (OSError, TimeoutError):
            if remote is None:
                self.send_error(502, 'Tor SOCKS5 unavailable')
        finally:
            if remote is not None:
                self.server.release_socket(remote)

    def _forward_http(self):
        self.close_connection = True
        remote = None
        self._response_started = False
        try:
            host, port, parsed = self._authority(self.path, False)
            if self.headers.get('Transfer-Encoding'):
                self.send_error(501, 'Chunked HTTP requests unsupported')
                return
            lengths = self.headers.get_all('Content-Length', [])
            if len(lengths) > 1:
                raise ValueError('重复的请求长度')
            size = int(lengths[0]) if lengths else 0
            if size < 0 or size > TOR_HTTP_MAX_BODY:
                raise ValueError('请求内容超过限制')
            host_header = host if port == 80 else '%s:%s' % (host, port)
            path = parsed.path or '/'
            if parsed.query:
                path += '?' + parsed.query
            path.encode('ascii')
            exclusions = {'host', 'connection', 'proxy-connection', 'proxy-authorization',
                          'keep-alive', 'te', 'trailer', 'upgrade', 'transfer-encoding'}
            exclusions.update(part.strip().casefold() for part in self.headers.get('Connection', '').split(','))
            headers = ['%s %s HTTP/1.1' % (self.command, path), 'Host: ' + host_header]
            for key, value in self.headers.items():
                if key.casefold() not in exclusions:
                    headers.append(key + ': ' + value)
            headers.append('Connection: close')
            remote = self.server.open_remote(host, port)
            remote.settimeout(TOR_HTTP_CLIENT_TIMEOUT)
            remote.sendall(('\r\n'.join(headers) + '\r\n\r\n').encode('latin-1'))
            while size:
                chunk = self.rfile.read(min(size, 65536))
                if not chunk:
                    raise OSError('请求体未完整接收')
                remote.sendall(chunk)
                size -= len(chunk)
            self._relay(remote, from_client=False)
        except (ValueError, UnicodeError):
            if not self._response_started:
                self.send_error(400, 'Invalid HTTP proxy request')
        except (OSError, TimeoutError):
            if not self._response_started:
                try:
                    self.send_error(502, 'Tor SOCKS5 unavailable')
                except OSError:
                    pass
        finally:
            if remote is not None:
                self.server.release_socket(remote)

    def do_GET(self):
        self._forward_http()

    def do_HEAD(self):
        self._forward_http()

    def do_POST(self):
        self._forward_http()

    def do_PUT(self):
        self._forward_http()

    def do_PATCH(self):
        self._forward_http()

    def do_DELETE(self):
        self._forward_http()

    def do_OPTIONS(self):
        self._forward_http()

class TorHttpProxyServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, port):
        self.tor_port = port
        self.active = True
        self.cancel_event = threading.Event()
        self.connection_lock = threading.Lock()
        self.connections = set()
        self.request_slots = threading.BoundedSemaphore(TOR_HTTP_MAX_CONNECTIONS)
        super().__init__(('127.0.0.1', 0), TorHttpProxyHandler)

    def track_socket(self, peer):
        with self.connection_lock:
            if not self.active:
                peer.close()
                raise OSError('本地 HTTP 代理已停止')
            self.connections.add(peer)
        return peer

    def release_socket(self, peer):
        with self.connection_lock:
            self.connections.discard(peer)
        try:
            peer.close()
        except OSError:
            pass

    def process_request(self, request, client_address):
        if not self.request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            self.track_socket(request)
            super().process_request(request, client_address)
        except Exception:
            self.release_socket(request)
            self.request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.release_socket(request)
            self.request_slots.release()

    def close_connections(self):
        with self.connection_lock:
            self.active = False
            self.cancel_event.set()
            peers = tuple(self.connections)
            self.connections.clear()
        for peer in peers:
            try:
                peer.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                peer.close()
            except OSError:
                pass

    def server_close(self):
        self.close_connections()
        super().server_close()

    def open_remote(self, host, port):
        opened = []

        def track(peer):
            self.track_socket(peer)
            opened.append(peer)

        try:
            return socks5_tunnel('127.0.0.1', self.tor_port, host, port,
                                 on_socket=track, cancel=self.cancel_event)
        except Exception:
            for peer in opened:
                self.release_socket(peer)
            raise

def start_tor_http_proxy(session):
    server = session.get('http_server')
    if server is not None and session.get('http_thread') and session['http_thread'].is_alive():
        return server.server_address[1]
    server = TorHttpProxyServer(session['tor_port'])
    session['http_server'] = server
    session.pop('http_probe', None)
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.2},
                              name='TorLocalHTTP', daemon=True)
    session['http_thread'] = thread
    try:
        thread.start()
    except Exception:
        session.pop('http_server', None)
        session.pop('http_thread', None)
        server.server_close()
        raise
    return server.server_address[1]

def stop_tor_http_proxy(session):
    server = session.pop('http_server', None)
    thread = session.pop('http_thread', None)
    session.pop('http_probe', None)
    if server is not None:
        server.close_connections()
        if thread is not None and thread.is_alive():
            server.shutdown()
        server.server_close()
    if thread is not None and thread.is_alive():
        thread.join(timeout=1)

def open_tunnel(method, endpoint, target, deadline=None):
    deadline = deadline if deadline is not None else time.monotonic() + 15
    if method == 'DIRECT':
        return socket.create_connection((target, 443), timeout=remaining_timeout(deadline, 6))
    _, host, port, _ = endpoint
    if method == 'SOCKS5':
        return socks5_tunnel(host, port, target, deadline=deadline)
    conn = http.client.HTTPConnection(host, port, timeout=remaining_timeout(deadline, 6))
    try:
        conn.set_tunnel(target, 443)
        conn.connect()
        sock = conn.sock
        conn.sock = None
        return sock
    finally:
        conn.close()

def psiphon_vpn_present():
    try:
        result = subprocess.run(['rasdial.exe'], capture_output=True, text=True,
                                errors='replace', timeout=5,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        return result.returncode == 0 and 'psiphon' in result.stdout.casefold()
    except (OSError, subprocess.TimeoutExpired):
        return False

def same_executable(pid, client):
    path = process_executable(pid)
    if path is None:
        return False
    try:
        actual = os.path.normcase(str(path.resolve()))
        if actual == os.path.normcase(str(client.resolve())):
            return True
        prior = client.with_name(client.name + '.orig')
        return (prior.is_file() and actual == os.path.normcase(str(prior.resolve()))
                and signature_status(prior) == 'VALID')
    except OSError:
        return False


def request_graceful_close(pid):
    if sys.platform != 'win32' or pid is None:
        return False
    try:
        from ctypes import wintypes
        user32 = ctypes.windll.user32
        callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        user32.EnumWindows.argtypes = (callback_type, wintypes.LPARAM)
        user32.EnumWindows.restype = wintypes.BOOL
        user32.GetWindowThreadProcessId.argtypes = (wintypes.HWND, ctypes.POINTER(wintypes.DWORD))
        user32.GetWindowThreadProcessId.restype = wintypes.DWORD
        user32.IsWindowVisible.argtypes = (wintypes.HWND,)
        user32.IsWindowVisible.restype = wintypes.BOOL
        user32.PostMessageW.argtypes = (wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)
        user32.PostMessageW.restype = wintypes.BOOL
        posted = [False]

        @callback_type
        def callback(hwnd, unused):
            owner = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
            if owner.value == pid and user32.IsWindowVisible(hwnd):
                posted[0] = bool(user32.PostMessageW(hwnd, 0x0010, 0, 0)) or posted[0]
            return True

        user32.EnumWindows(callback, 0)
        return posted[0]
    except (OSError, AttributeError, TypeError, ValueError):
        return False

def validate_windows():
    if sys.version_info < (3, 9):
        raise RuntimeError('本程序要求 Python 3.9 或更高版本')
    if sys.platform != 'win32' or platform.machine().lower() not in ('amd64', 'x86_64'):
        raise RuntimeError('本程序仅支持 Windows 11 x64')
    version = sys.getwindowsversion()
    if version.major < 10 or version.build < 22000:
        raise RuntimeError('本程序要求 Windows 11')

def running_verified_psiphon():
    try:
        result = subprocess.run(['tasklist.exe', '/FI', 'IMAGENAME eq psiphon3.exe',
                                 '/FO', 'CSV', '/NH'], capture_output=True, text=True,
                                errors='replace', timeout=6,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        for line in csv.reader(result.stdout.splitlines()):
            if len(line) < 2 or line[0].casefold() != 'psiphon3.exe':
                continue
            try:
                pid = int(line[1].replace(',', ''))
            except ValueError:
                continue
            path = process_executable(pid)
            if path is not None and signature_status(path) == 'VALID':
                return path
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None

def safe_asset_download(url, target, expected_sha256, maximum=65 * 1024 * 1024,
                        cancel=None, use_proxy=False):
    _run_download_job('tor', url, target, use_proxy, maximum, 110,
                      expected_sha256=expected_sha256, cancel=cancel)

def fetch_tor_archive(bundle):
    cancel = threading.Event()
    routes = iter(enumerate(diverse_download_routes(
        [(url, mode) for url in TOR_ARCHIVE_URLS for mode in download_modes()]), 1))
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=2)
    pending = {}
    all_futures = []
    failures = []
    attempt_id = '%s.%s' % (os.getpid(), time.monotonic_ns())

    def reap_after_cancel(future, scratch):
        if cancel.is_set():
            safe_remove(scratch)

    def submit_next():
        try:
            number, (url, mode) = next(routes)
        except StopIteration:
            return
        scratch = bundle.with_name(bundle.name + '.part.%s.%s' % (attempt_id, number))
        future = pool.submit(safe_asset_download, url, scratch, TOR_SHA256,
                             65 * 1024 * 1024, cancel, mode)
        pending[future] = (url, scratch, mode)
        all_futures.append((future, scratch))
        future.add_done_callback(lambda finished, path=scratch: reap_after_cancel(finished, path))

    try:
        submit_next()
        submit_next()
        while pending and not STOP.is_set():
            finished, _ = concurrent.futures.wait(
                tuple(pending), timeout=0.25,
                return_when=concurrent.futures.FIRST_COMPLETED)
            for future in finished:
                url, scratch, mode = pending.pop(future)
                try:
                    future.result()
                    if STOP.is_set() or cancel.is_set():
                        raise InterruptedError('已停止')
                    os.replace(scratch, bundle)
                    cancel.set()
                    item('Tor', '已通过 SHA-256 校验并保存可信官方组件')
                    return
                except (OSError, ValueError, TimeoutError, InterruptedError,
                        urllib.error.URLError, http.client.HTTPException) as exc:
                    failures.append(type(exc).__name__)
                    diagnostic('Tor 官方分发尝试失败：' +
                               str(urllib.parse.urlsplit(url).hostname) +
                               (' 系统代理 ' if mode else ' 直连 ') + type(exc).__name__)
                    submit_next()
        if STOP.is_set():
            raise InterruptedError('已停止')
        raise RuntimeError('Tor 官方分发源均不可用：' + ', '.join(failures[-3:]))
    finally:
        cancel.set()
        for future in pending:
            future.cancel()
        pool.shutdown(wait=False, cancel_futures=True)
        for future, scratch in all_futures:
            if future.done():
                safe_remove(scratch)

def sha256_stream(stream):
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        if STOP.is_set():
            raise InterruptedError('已停止')
        digest.update(chunk)
    return digest.hexdigest()

def sha256_file(path):
    with path.open('rb') as source:
        return sha256_stream(source)

def tor_cached_executables(root, bundle):
    try:
        marker = json.loads((root / 'trusted-cache.json').read_text(encoding='utf-8'))
        if marker.get('archive') != TOR_SHA256 or marker.get('version') != TOR_VERSION:
            return None
        paths = []
        with tarfile.open(bundle, 'r:gz') as archive:
            members = archive.getmembers()
            if len(members) > 2000:
                return None
            names = set()
            total = 0
            for member in members:
                relative = pathlib.PurePosixPath(member.name)
                if (relative.is_absolute() or '..' in relative.parts or ':' in member.name
                        or '\\' in member.name or member.issym() or member.islnk()
                        or not (member.isfile() or member.isdir())):
                    return None
                if member.isdir():
                    continue
                total += member.size
                if (member.size < 0 or member.size > 90 * 1024 * 1024
                        or total > 230 * 1024 * 1024):
                    return None
                names.add(relative.as_posix())
                path = root.joinpath(*relative.parts)
                if (not path.is_file() or path.stat().st_size != member.size
                        or not path.resolve().is_relative_to(root.resolve())):
                    return None
                with archive.extractfile(member) as source:
                    expected_hash = sha256_stream(source)
                if sha256_file(path) != expected_hash:
                    return None
            for file in root.rglob('*'):
                if (file.is_symlink() or (file.is_file() and file.relative_to(root).as_posix()
                                          not in names | {'trusted-cache.json'})):
                    return None
            for name, executable in (('tor', 'tor.exe'), ('lyrebird', 'lyrebird.exe')):
                description = marker[name]
                relative = pathlib.PurePosixPath(description['path'])
                if (relative.as_posix() not in names or relative.name.casefold() != executable
                        or len(relative.parts) > 12):
                    return None
                paths.append(root.joinpath(*relative.parts))
        return tuple(paths)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, tarfile.TarError):
        return None

def trusted_tor_files(data):
    if STOP.is_set():
        raise InterruptedError('已停止')
    bundle = data / ('tor-expert-' + TOR_VERSION + '.tar.gz')
    if bundle.is_file() and sha256_file(bundle) != TOR_SHA256:
        safe_remove(bundle)
    if not bundle.is_file():
        item('Tor', '并发尝试可信分发源（固定版本 SHA-256 校验）')
        fetch_tor_archive(bundle)
    root = data / ('tor-' + TOR_VERSION)
    reused = tor_cached_executables(root, bundle)
    if reused is not None:
        item('Tor', '已复用经过散列验证的 Tor 本地文件')
        return reused
    temporary = data / ('tor-' + TOR_VERSION + '.partial')
    if temporary.exists():
        shutil.rmtree(temporary)
    temporary.mkdir(parents=True)
    total = 0
    try:
        with tarfile.open(bundle, 'r:gz') as archive:
            entries = archive.getmembers()
            if len(entries) > 2000:
                raise ValueError('Tor 压缩包文件数量超限')
            for entry in entries:
                if STOP.is_set():
                    raise InterruptedError('已停止')
                posix = pathlib.PurePosixPath(entry.name)
                if (posix.is_absolute() or '..' in posix.parts or ':' in entry.name
                        or '\\' in entry.name or entry.issym() or entry.islnk()
                        or not (entry.isfile() or entry.isdir())):
                    raise ValueError('Tor 压缩包存在不安全路径或链接')
                dest = temporary.joinpath(*posix.parts)
                if entry.isdir():
                    dest.mkdir(parents=True, exist_ok=True)
                    continue
                total += entry.size
                if entry.size < 0 or entry.size > 90 * 1024 * 1024 or total > 230 * 1024 * 1024:
                    raise ValueError('Tor 解压内容超过安全限制')
                dest.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(entry) as source, dest.open('wb') as output:
                    while True:
                        if STOP.is_set():
                            raise InterruptedError('已停止')
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        output.write(chunk)
        binaries = list(temporary.rglob('tor.exe'))
        transports = list(temporary.rglob('lyrebird.exe'))
        if len(binaries) != 1 or len(transports) != 1:
            raise ValueError('官方 Tor Bundle 缺少必要的 tor/lyrebird 可执行文件')
        marker = {'version': TOR_VERSION, 'archive': TOR_SHA256}
        for name, executable in (('tor', binaries[0]), ('lyrebird', transports[0])):
            marker[name] = {'path': executable.relative_to(temporary).as_posix(),
                            'sha256': sha256_file(executable)}
        (temporary / 'trusted-cache.json').write_text(json.dumps(marker), encoding='utf-8')
        if root.exists():
            shutil.rmtree(root)
        os.replace(temporary, root)
        result = tor_cached_executables(root, bundle)
        if result is None:
            raise RuntimeError('Tor 解压后完整性检查失败')
        return result
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise

def validated_bridge_catalog(value):
    if not isinstance(value, dict) or not isinstance(value.get('bridges'), dict):
        return {}
    groups = {}
    for name, lines in value['bridges'].items():
        kind = 'meek_lite' if name in ('meek-azure', 'meek') else name
        if kind not in ('obfs4', 'snowflake', 'webtunnel', 'meek_lite') or not isinstance(lines, list):
            continue
        good = []
        for line in lines[:32]:
            if not isinstance(line, str) or len(line) > 1800 or len(line) < 20:
                continue
            if not re.fullmatch(r'[\x21-\x7e ]+', line) or any(c in line for c in '\r\n\\"'):
                continue
            tokens = line.split()
            if len(tokens) < 3 or tokens[0] != kind or len(tokens) > 45:
                continue
            found = re.fullmatch(r'(?:[A-Za-z0-9.\-]+|\[[0-9a-fA-F:]+\]):(\d{1,5})', tokens[1])
            if not found or not 1 <= int(found.group(1)) <= 65535:
                continue
            if line not in good:
                good.append(line)
        if good:
            groups.setdefault(kind, []).extend(good)
    return groups

def refresh_official_bridges(data):
    if STOP.is_set():
        return False
    failures = []
    suffix = '%s.%s' % (os.getpid(), threading.get_ident())
    scratch = data / ('official_bridges.download.' + suffix + '.json')
    destination = data / 'official_bridges.json'
    temporary = data / ('official_bridges.tmp.' + suffix + '.json')
    for mode in download_modes():
        if STOP.is_set():
            return False
        try:
            _run_download_job('bridges', OFFICIAL_BRIDGE_URL, scratch, mode,
                              128 * 1024, 20)
            groups = validated_bridge_catalog(read_json_bounded(scratch, 128 * 1024))
            if not groups:
                raise ValueError('官方候选数据没有有效网桥')
            record = {'fetched_at': time.time(), 'bridges': groups}
            with temporary.open('w', encoding='utf-8') as output:
                json.dump(record, output, ensure_ascii=False, separators=(',', ':'))
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, destination)
            item('通道发现', '已更新官方 HTTPS 候选：%s 条' % sum(map(len, groups.values())))
            return True
        except (OSError, ValueError, TypeError, UnicodeError, urllib.error.URLError,
                http.client.HTTPException, TimeoutError, RuntimeError) as exc:
            failures.append(type(exc).__name__)
        finally:
            safe_remove(scratch)
            safe_remove(temporary)
    diagnostic('获取官方候选失败，使用本地可信候选：' + ', '.join(failures[-2:]))
    return False

def start_bridge_discovery(data):
    if STOP.is_set():
        return
    with BRIDGE_DISCOVERY_LOCK:
        now = time.monotonic()
        if BRIDGE_DISCOVERY_STATE['running'] or now < BRIDGE_DISCOVERY_STATE['next']:
            return
        BRIDGE_DISCOVERY_STATE['running'] = True

    def discover():
        succeeded = False
        try:
            succeeded = refresh_official_bridges(data)
        except (OSError, ValueError, TypeError, RuntimeError, RecursionError, AttributeError) as exc:
            diagnostic('官方候选发现线程异常：' + type(exc).__name__)
        finally:
            with BRIDGE_DISCOVERY_LOCK:
                BRIDGE_DISCOVERY_STATE['running'] = False
                if succeeded:
                    BRIDGE_DISCOVERY_STATE['failures'] = 0
                    BRIDGE_DISCOVERY_STATE['next'] = time.monotonic() + BRIDGE_DISCOVERY_SUCCESS_INTERVAL
                else:
                    failures = min(7, BRIDGE_DISCOVERY_STATE['failures'] + 1)
                    BRIDGE_DISCOVERY_STATE['failures'] = failures
                    BRIDGE_DISCOVERY_STATE['next'] = time.monotonic() + min(
                        BRIDGE_DISCOVERY_FAILURE_MAX, 30 * 2 ** (failures - 1))

    try:
        threading.Thread(target=discover, name='OfficialBridgeDiscovery', daemon=True).start()
    except RuntimeError:
        with BRIDGE_DISCOVERY_LOCK:
            BRIDGE_DISCOVERY_STATE['running'] = False
            BRIDGE_DISCOVERY_STATE['next'] = time.monotonic() + 60

def reset_bridge_discovery():
    with BRIDGE_DISCOVERY_LOCK:
        BRIDGE_DISCOVERY_STATE['next'] = 0.0
        BRIDGE_DISCOVERY_STATE['failures'] = 0

def tor_bridge_profiles(data):
    groups = {}
    root = data / ('tor-' + TOR_VERSION)
    for path in root.rglob('pt_config.json') if root.is_dir() else ():
        try:
            if path.is_symlink():
                continue
            found = validated_bridge_catalog(read_json_bounded(path, 128 * 1024))
            for kind, lines in found.items():
                groups.setdefault(kind, []).extend(lines)
        except (OSError, ValueError, TypeError, UnicodeError):
            continue
    cached = data / 'official_bridges.json'
    if cached.is_file():
        try:
            remote = read_json_bounded(cached, 128 * 1024)
            fetched_at = remote.get('fetched_at') if isinstance(remote, dict) else None
            if (type(fetched_at) in (int, float) and math.isfinite(fetched_at)
                    and 0 <= time.time() - fetched_at <= 30 * 86400):
                for kind, lines in validated_bridge_catalog(remote).items():
                    groups.setdefault(kind, []).extend(lines)
        except (OSError, ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
            pass
    if not groups.get('snowflake'):
        groups['snowflake'] = [TOR_SNOWFLAKE]
    profiles = []
    for kind, lines in groups.items():
        for line in dict.fromkeys(lines):
            digest = hashlib.sha256(line.encode('ascii')).hexdigest()[:10]
            profiles.append(('%s-%s' % (kind, digest), [line]))
    profiles.append(('direct', []))
    item('通道发现', '可独立验证 %s 种传输，%s 条官方候选通道' %
         (len(groups) + 1, len(profiles)))
    return profiles

def ranked_tor_bridges(profiles, state):
    records = state.get('bridge_stats', {})
    now = time.time()
    total = sum(recent_quality(v, now)[0] for v in records.values())

    def score(profile):
        name = profile[0]
        record = records.get(name, {})
        tries, wins = recent_quality(record, now)
        prob = model_probability(state, 'Tor', profile)
        confidence = (wins + 1) / (tries + 2)
        exploration = 0.30 * math.sqrt(math.log(total + 2) / (tries + 1))
        age = max(0, now - nonnegative(record.get('updated')))
        outages = nonnegative(record.get('outages')) * 0.5 ** (age / ROUTE_HISTORY_HALFLIFE)
        return 0.55 * prob + 0.45 * confidence + exploration - 0.12 * min(outages / (wins + 1), 1)

    ordered = sorted(profiles, key=score, reverse=True)
    seen = set()
    varied = []
    for profile in ordered:
        kind = profile[0].split('-', 1)[0]
        if kind not in seen:
            varied.append(profile)
            seen.add(kind)
    varied.extend(p for p in ordered if p not in varied)
    return varied[:TOR_BRIDGE_ATTEMPTS]

def record_bridge(state, profile, success):
    if not profile:
        return
    name = profile[0]
    records = state.setdefault('bridge_stats', {})
    value = records.setdefault(name, {'tries': 0, 'wins': 0, 'outages': 0, 'updated': 0})
    if value['tries'] >= 1000000:
        value['tries'] //= 2
        value['wins'] //= 2
    recent_observe(value, success)
    value['tries'] += 1
    if success:
        value['wins'] += 1
    value['updated'] = time.time()
    model_observe(state, 'Tor', success, profile)

def record_bridge_outage(state, profile):
    if not profile:
        return
    record = state.setdefault('bridge_stats', {}).setdefault(
        profile[0], {'tries': 0, 'wins': 0, 'outages': 0, 'updated': 0})
    recent_observe(record, False)
    record['outages'] = min(int(nonnegative(record.get('outages'))) + 1, 1000000)
    record['updated'] = time.time()
    model_observe(state, 'Tor', False, profile)

def tor_configuration(data, tor, transport, profile, port=TOR_PORT):
    kind, bridges = profile
    tor_data = data / 'tor-private'
    tor_data.mkdir(exist_ok=True)
    rc = data / ('torrc-%s-%s.generated' % (os.getpid(), port))
    lines = ['SocksPort 127.0.0.1:%s' % port,
             'DataDirectory "%s"' % str(tor_data).replace('\\', '/'),
             'ClientOnly 1', 'SafeLogging 1', 'AvoidDiskWrites 1',
             'Log notice stdout']
    if bridges:
        pt = str(transport).replace('\\', '/')
        lines.extend(['UseBridges 1',
                      'ClientTransportPlugin obfs4,snowflake,webtunnel,meek_lite exec "%s"' % pt])
        lines.extend('Bridge ' + bridge for bridge in bridges)
    else:
        lines.append('UseBridges 0')
    tmp = rc.with_suffix('.tmp')
    tmp.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    os.replace(tmp, rc)
    return rc

def start_tor_status_reader(session):
    proc = session['proc']

    def read_status():
        try:
            for line in proc.stdout:
                if STOP.is_set():
                    continue
                line = line.strip()
                found = re.search(r'\bBootstrapped\s+(\d{1,3})%'
                                  r'(?:\s+\([^)]{1,64}\))?:\s*(.{0,140})', line)
                if found:
                    percent = min(100, int(found.group(1)))
                    previous = session.get('tor_bootstrap', -1)
                    if percent > previous:
                        session['tor_progress_at'] = time.monotonic()
                    if percent >= previous:
                        session['tor_bootstrap'] = percent
                        session['tor_bootstrap_detail'] = found.group(2)
                    last = session.get('tor_reported', -1)
                    if percent == 100 or percent - last >= 5:
                        item('Tor', '引导进度 %s%%：%s' % (percent, found.group(2)[:100]))
                        session['tor_reported'] = percent
                elif '[warn]' in line.casefold() or '[err]' in line.casefold():
                    summary = re.sub(r'[\r\n\t]', ' ', line)[-180:]
                    session['tor_warning'] = summary
                    diagnostic('Tor ' + summary)
        except (OSError, ValueError, UnicodeError):
            pass
        finally:
            if proc.stdout is not None:
                proc.stdout.close()

    thread = threading.Thread(target=read_status, name='TorBootstrap', daemon=True)
    session['tor_status_thread'] = thread
    try:
        thread.start()
    except RuntimeError as exc:
        try:
            proc.terminate()
            proc.wait(timeout=4)
        except (OSError, subprocess.TimeoutExpired):
            try:
                proc.kill()
            except OSError:
                pass
        raise OSError('无法启动 Tor 引导状态读取线程') from exc

def tor_port_claimed(pid, port=TOR_PORT):
    return any(owner == pid for _, owner in listener_endpoints(port))

def free_tor_port():
    for port in range(TOR_PORT, TOR_PORT + TOR_PORT_CANDIDATES):
        if listener_endpoints(port):
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(('127.0.0.1', port))
            return port
        except OSError:
            continue
    raise RuntimeError('Tor 候选本地端口均被占用，无法安全启动')

def background_command(args, timeout=10):
    try:
        result = subprocess.run([str(piece) for piece in args], input='', capture_output=True,
                                text=True, encoding='utf-8', errors='replace', timeout=timeout,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        return result.returncode, (result.stdout + ' ' + result.stderr)[:2048]
    except (OSError, subprocess.TimeoutExpired) as exc:
        return -1, type(exc).__name__

def network_signature():
    if sys.platform != 'win32':
        return None
    script = ("$ErrorActionPreference='Stop';"
              "[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);"
              "$adapters=@{};"
              "foreach($a in @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue)){"
              "$adapters[[int]$a.InterfaceIndex]=$a};"
              "$profiles=@{};"
              "foreach($p in @(Get-NetConnectionProfile -ErrorAction SilentlyContinue)){"
              "$i=[int]$p.InterfaceIndex;"
              "if(-not $profiles.ContainsKey($i)){$profiles[$i]=@()};"
              "$profiles[$i]+=[string]$p.Name};"
              "$rows=@(foreach($r in @(Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' "
              "-PolicyStore ActiveStore -ErrorAction SilentlyContinue)){"
              "$a=$adapters[[int]$r.InterfaceIndex];if($null -eq $a){continue};"
              "[PSCustomObject]@{guid=[string]$a.InterfaceGuid;gateway=[string]$r.NextHop;"
              "metric=([long]$r.RouteMetric+[long]$r.InterfaceMetric);"
              "hardware=[bool]$a.HardwareInterface;type=[int]$a.InterfaceType;"
              "up=[int]$a.InterfaceOperationalStatus;"
              "network=@($profiles[[int]$r.InterfaceIndex] | Sort-Object -Unique);"
              "description=[string]$a.InterfaceDescription;name=[string]$a.Name}});"
              "ConvertTo-Json -Compress -Depth 4 -InputObject @{routes=$rows}")
    try:
        result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive',
                                 '-Command', script], capture_output=True, text=True,
                                encoding='utf-8-sig', errors='strict', timeout=6,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        if result.returncode != 0 or not result.stdout or len(result.stdout) > 65536:
            return None
        return network_signature_from_routes(json.loads(result.stdout))
    except (OSError, ValueError, TypeError, OverflowError, RecursionError,
            subprocess.TimeoutExpired):
        return None

def route_interface(remote_ip):
    if sys.platform != 'win32' or not remote_ip:
        return None
    try:
        from ctypes import wintypes
        family = socket.AF_INET6 if ':' in remote_ip else socket.AF_INET
        address = socket.inet_pton(family, remote_ip.split('%', 1)[0])
        if family == socket.AF_INET:
            packed = struct.pack('<HH', family, 0) + address + bytes(8)
        else:
            packed = struct.pack('<HHI', family, 0, 0) + address + bytes(4)
        sockaddr = ctypes.create_string_buffer(packed)
        index = wintypes.DWORD()
        func = ctypes.windll.iphlpapi.GetBestInterfaceEx
        func.argtypes = (ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD))
        func.restype = wintypes.DWORD
        if func(sockaddr, ctypes.byref(index)) != 0 or not index.value:
            return None
        script = ("$ErrorActionPreference='Stop';" +
                  '$n=Get-NetIPInterface -InterfaceIndex ' + str(index.value) +
                  ' | Select-Object -ExpandProperty InterfaceAlias -Unique;' +
                  '$d=Get-NetAdapter -InterfaceIndex ' + str(index.value) +
                  ' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty InterfaceDescription -First 1;' +
                  '@{Name=($n -join " " );InterfaceDescription=[string]$d} | ConvertTo-Json -Compress')
        code, output = background_command(['powershell.exe', '-NoProfile', '-NonInteractive',
                                           '-Command', script], timeout=8)
        if code != 0:
            return None
        obj = json.loads(output.strip().splitlines()[0])
        return (str(obj.get('Name', '')) + ' ' + str(obj.get('InterfaceDescription', ''))).casefold()
    except (OSError, AttributeError, ValueError, TypeError, subprocess.TimeoutExpired):
        return None

def verified_vpn_route(remote_ip, name):
    description = route_interface(remote_ip)
    if not description:
        return False
    return name == 'Psiphon' and 'psiphon' in description

def probe_single(method, endpoint, target, deadline=None, cancel=None):
    url, expected, level = target
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname
    path = urllib.parse.urlunsplit(('', '', parsed.path or '/', parsed.query, ''))
    raw = None
    deadline = deadline if deadline is not None else time.monotonic() + 16
    try:
        if STOP.is_set() or (cancel is not None and cancel.is_set()):
            return level, None, None
        begin = time.monotonic()
        raw = open_tunnel(method, endpoint, host, deadline)
        if cancel is not None and cancel.is_set():
            return level, None, None
        remote = raw.getpeername()[0] if method == 'DIRECT' else None
        raw.settimeout(remaining_timeout(deadline, 5))
        context = ssl.create_default_context()
        with context.wrap_socket(raw, server_hostname=host) as secure:
            raw = None
            secure.settimeout(remaining_timeout(deadline, 5))
            request = ('GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n'
                       'Connection: close\r\n\r\n') % (path, host)
            secure.sendall(request.encode('ascii'))
            secure.settimeout(remaining_timeout(deadline, 5))
            reply = http.client.HTTPResponse(secure)
            try:
                reply.begin()
                code = reply.status
                try:
                    secure.settimeout(remaining_timeout(deadline, 3))
                    reply.read(128)
                except (OSError, http.client.HTTPException, TimeoutError):
                    return level, None, code
                accepted = code == expected if expected is not None else 200 <= code < 400
                if accepted and (cancel is None or not cancel.is_set()):
                    return level, (host, time.monotonic() - begin, remote), code
                return level, None, code
            finally:
                reply.close()
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError,
            TimeoutError, InterruptedError):
        pass
    finally:
        if raw is not None:
            raw.close()
    return level, None, None

def probe_quorum(method, endpoint=None, include_completed=False, include_reachable=False):
    good = []
    normal = None
    completed_hosts = set()
    reachable = {}

    def result():
        output = [good, normal]
        if include_completed:
            output.append(completed_hosts)
        if include_reachable:
            output.append(reachable)
        return tuple(output)

    if STOP.is_set():
        return result()
    deadline = time.monotonic() + 17
    cancel = threading.Event()
    answers = queue.Queue()
    jobs = 0

    def run(target):
        host = urllib.parse.urlsplit(target[0]).hostname
        try:
            found = probe_single(method, endpoint, target, deadline, cancel)
        except Exception as exc:
            diagnostic('探测线程异常：' + type(exc).__name__)
            found = (target[2], None, None)
        finally:
            if not cancel.is_set():
                answers.put((host, found))
            PROBE_SLOTS.release()

    for target in TARGETS:
        if not PROBE_SLOTS.acquire(blocking=False):
            continue
        jobs += 1
        try:
            threading.Thread(target=run, args=(target,), daemon=True,
                             name='BoundedNetworkProbe').start()
        except RuntimeError:
            PROBE_SLOTS.release()
            jobs -= 1
    received = 0
    try:
        while received < jobs and not STOP.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                host, (level, found, status) = answers.get(timeout=min(0.4, remaining))
            except queue.Empty:
                continue
            received += 1
            completed_hosts.add(host)
            if isinstance(status, int) and 100 <= status <= 599:
                reachable[host] = status
            if found is not None:
                if level == '受限服务':
                    good.append(found)
                else:
                    normal = found
            if len(good) >= 2:
                break
        return result()
    finally:
        cancel.set()

def update_engine_cooldown(record, failed):
    if not failed:
        record['cooldown'] = 0
        record['failure_streak'] = 0
        return
    streak = min(int(nonnegative(record.get('failure_streak'))) + 1, 20)
    record['failure_streak'] = streak
    record['cooldown'] = time.time() + min(
        ENGINE_COOLDOWN_MAX, ENGINE_COOLDOWN * 2 ** min(streak - 1, 6))

def engine_stats(state, name, passed, latency=None, uptime=None):
    records = state.setdefault('engines', {})
    record = records.setdefault(name, {'tries': 0, 'wins': 0, 'updated': 0,
                                       'cooldown': 0, 'latency': 0, 'uptime': 0, 'outages': 0,
                                       'integration_failures': 0})
    if record['tries'] >= 1000000:
        record['tries'] //= 2
        record['wins'] //= 2
    recent_observe(record, passed)
    record['tries'] += 1
    if passed:
        record['wins'] += 1
        if latency is not None:
            sample = min(nonnegative(latency), 60)
            record['latency'] = 0.65 * nonnegative(record.get('latency')) + 0.35 * sample
        update_engine_cooldown(record, False)
    else:
        update_engine_cooldown(record, True)
    if uptime is not None:
        record_engine_uptime(state, name, uptime)
    record['updated'] = time.time()
    model_observe(state, name, passed)

def record_engine_uptime(state, name, uptime):
    record = state.setdefault('engines', {}).get(name)
    if record is None:
        return
    sample = min(nonnegative(uptime), 86400)
    old = nonnegative(record.get('uptime'))
    record['uptime'] = sample if not old else 0.75 * old + 0.25 * sample

def record_engine_outage(state, name, uptime=None):
    record = state.setdefault('engines', {}).setdefault(
        name, {'tries': 0, 'wins': 0, 'updated': 0,
               'cooldown': 0, 'latency': 0, 'uptime': 0, 'outages': 0,
               'integration_failures': 0})
    recent_observe(record, False)
    record['outages'] = min(int(nonnegative(record.get('outages'))) + 1, 1000000)
    update_engine_cooldown(record, True)
    if uptime is not None:
        record_engine_uptime(state, name, uptime)
    record['updated'] = time.time()
    model_observe(state, name, False)

def record_engine_integration_failure(state, name):
    record = state.setdefault('engines', {}).setdefault(
        name, {'tries': 0, 'wins': 0, 'updated': 0, 'cooldown': 0,
               'latency': 0, 'uptime': 0, 'outages': 0, 'integration_failures': 0})
    record['integration_failures'] = min(int(nonnegative(record.get('integration_failures'))) + 1, 1000000)
    record['updated'] = time.time()
    record_preparation_failure(state, name, '系统代理自动接入未完成')

def record_session_failure(session, state, state_path, uptime=None):
    if session.get('failure_recorded'):
        return
    name = session['name']
    if session.get('local_failure'):
        record_preparation_failure(state, name, session['local_failure'])
        if uptime is not None:
            record_engine_uptime(state, name, uptime)
    elif session.get('integration_failure'):
        record_engine_integration_failure(state, name)
        session['attempt_recorded'] = True
    else:
        if name == 'Tor':
            if not session.get('bridge_recorded'):
                record_bridge(state, session.get('bridge'), False)
                session['bridge_recorded'] = True
            elif session.get('bridge_success'):
                record_bridge_outage(state, session.get('bridge'))
        if session.get('attempt_recorded'):
            record_engine_outage(state, name, uptime)
        else:
            engine_stats(state, name, False)
            session['attempt_recorded'] = True
    session['failure_recorded'] = True
    save_state(state_path, state)

def engines_ranked(state, available):
    now = time.time()
    records = state.get('engines', {})
    total = sum(recent_quality(v, now)[0] for v in records.values())

    def score(name):
        record = records.get(name, {})
        tries, wins = recent_quality(record, now)
        learning = model_probability(state, name)
        quality = (wins + 1) / (tries + 2)
        exploration = 0.2 * math.sqrt(math.log(total + 2) / (tries + 1))
        cooldown = 2.0 if nonnegative(record.get('cooldown')) > now else 0.0
        speed_bonus = 0.04 if name == 'Psiphon' else 0.0
        stability = 0.08 * min(1.0, math.log1p(nonnegative(record.get('uptime'))) /
                               math.log1p(3600))
        age = max(0, now - nonnegative(record.get('updated')))
        integration = nonnegative(record.get('integration_failures')) * (
            0.5 ** (age / ROUTE_HISTORY_HALFLIFE))
        return (0.55 * learning + 0.45 * quality + exploration + speed_bonus + stability
                - min(0.15, 0.03 * integration) - cooldown)

    return sorted(available, key=score, reverse=True)

def write_diagnostics(data):
    with LOG_LOCK:
        if not LOG_QUEUE:
            return
        entries = list(LOG_QUEUE)
        LOG_QUEUE.clear()
    path = data / 'events.log'
    try:
        if path.is_file() and path.stat().st_size > 400000:
            backup = data / 'events.prev.log'
            os.replace(path, backup)
        with path.open('a', encoding='utf-8') as output:
            for entry in entries:
                output.write(entry + '\n')
    except OSError:
        with LOG_LOCK:
            latest = list(LOG_QUEUE)
            LOG_QUEUE.clear()
            LOG_QUEUE.extend((entries + latest)[-LOG_QUEUE.maxlen:])

def diagnostic(message):
    stamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    line = stamp + ' ' + re.sub(r'[\r\n\t]', ' ', str(message))[:225]
    with LOG_LOCK:
        LOG_QUEUE.append(line)

def routes_match_provider(samples, name):
    hits = 0
    for host, latency, address in samples:
        if verified_vpn_route(address, name):
            hits += 1
        if hits >= 2:
            return True
    return False

def existing_vpn_session(binaries):
    program = binaries.get('Psiphon')
    if program is None:
        return None
    good, unused = probe_quorum('DIRECT')
    if len(good) >= 2 and routes_match_provider(good, 'Psiphon'):
        diagnostic('复用现有 Psiphon VPN 路由')
        return {'name': 'Psiphon', 'program': program, 'proc': None,
                'started': time.monotonic(), 'baseline': None, 'observed': None,
                'bridge': None, 'owned': False, 'connected_by_us': False,
                'attempt_recorded': False, 'bridge_recorded': False}
    return None

def create_session(name, data, state, state_path, bridge=None, tor_files=None):
    session = {'name': name, 'proc': None, 'program': None, 'started': time.monotonic(),
               'baseline': None, 'observed': None, 'bridge': bridge, 'owned': False,
               'attempt_recorded': False, 'bridge_recorded': False}
    if name == 'Psiphon':
        already = running_verified_psiphon()
        if already is not None:
            session['program'] = already
            return session
        client = ensure_client(data, state_path, state)
        if client is None:
            return None
        if signature_status(client) != 'VALID':
            raise RuntimeError('Psiphon 可执行文件签名未通过')
        if STOP.is_set():
            return None
        session['program'] = client
        session['baseline'], session['baseline_types'] = proxy_registry_snapshot(with_types=True)
        guard_path = data / 'proxy_guard.json'
        if session['baseline'] is None or not arm_psiphon_guard(
                guard_path, session['baseline'], session['baseline_types'], client):
            raise RuntimeError('无法在启动 Psiphon 前建立代理恢复保护')
        try:
            launch_owned_process(
                session, [str(client)],
                on_started=lambda process: bind_proxy_guard_process(guard_path, process, client),
                cwd=str(data), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            capture_armed_psiphon_guard(guard_path)
        except Exception:
            cleanup_session(session, guard_path)
            raise
    elif name == 'Tor':
        tor, lyrebird = tor_files if tor_files is not None else trusted_tor_files(data)
        session['program'] = tor
        port = free_tor_port()
        session['tor_port'] = port
        if bridge is None:
            bridge = ranked_tor_bridges(tor_bridge_profiles(data), state)[0]
        session['bridge'] = bridge
        rc = tor_configuration(data, tor, lyrebird, bridge, port)
        session['torrc'] = rc
        try:
            launch_owned_process(
                session, [str(tor), '-f', str(rc)], cwd=str(tor.parent),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace',
                bufsize=1, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            start_tor_status_reader(session)
        except Exception:
            cleanup_session(session, data / 'proxy_guard.json')
            raise
    else:
        raise ValueError('不支持的引擎')
    diagnostic(name + ' 启动/接管')
    return session

def health_session(session, state=None):
    name = session['name']
    if name == 'Psiphon':
        session.pop('integration_failure', None)
    proc = session.get('proc')
    program = session['program']
    if proc is not None and proc.poll() is not None:
        return 'DOWN', '客户端进程已退出', None
    if name == 'Tor':
        port = session.get('tor_port', TOR_PORT)
        if proc is None or not tor_port_claimed(proc.pid, port):
            progress = session.get('tor_bootstrap')
            if progress is not None:
                return 'DOWN', 'Tor 引导 %s%%：%s' % (
                    progress, session.get('tor_bootstrap_detail', '')[:100]), None
            return 'DOWN', '等待 Tor SOCKS5 端口（尚未确认归属）', None
        endpoint = ('SOCKS5', '127.0.0.1', port, proc.pid)
        good, normal, reachable = probe_quorum('SOCKS5', endpoint, include_reachable=True)
        if len(good) >= 2:
            return 'PROXY', 'Tor SOCKS5：至少两个受限站点通过验证', good[0][1]
        if len(reachable) >= 2:
            return 'PARTIAL', 'Tor 已取得多个 HTTP 回应，但服务验证未达标', None
        return ('PARTIAL' if good or normal else 'DOWN',
                'Tor 多站点测试 %d/3' % len(good), None)
    direct_allowed = psiphon_vpn_present() or not system_proxies()
    direct_good, direct_normal, direct_reachable = [], None, {}
    if direct_allowed:
        direct_good, direct_normal, direct_reachable = probe_quorum(
            'DIRECT', include_reachable=True)
        if len(direct_good) >= 2 and routes_match_provider(direct_good, 'Psiphon'):
            return 'VPN', 'Psiphon 的 VPN 出口路由经两个受限站点验证', direct_good[0][1]
    endpoints = owned_proxies(system_proxies(), program, proc.pid if proc else None)
    proxy_reachable = {}
    for endpoint in rank_channels(endpoints, state or {'channels': {}}):
        good, unused, reachable = probe_quorum(endpoint[0], endpoint, include_reachable=True)
        if len(reachable) > len(proxy_reachable):
            proxy_reachable = reachable
        passed = len(good) >= 2
        if state is not None:
            record_channel(state, endpoint[0], passed, good[0][1] if passed else None)
        if passed:
            if verify_windows_proxy(session):
                return 'PROXY', 'Psiphon 本地代理与 Windows 默认代理访问均通过验证', good[0][1]
            session['integration_failure'] = True
            return 'PARTIAL', 'Psiphon 本地代理可用，但 Windows 默认代理访问未通过验证', None
    if direct_allowed:
        if len(direct_good) >= 2:
            return 'UNCONFIRMED', '站点可达，但未证明属于 Psiphon 路由', None
        if direct_good or direct_normal:
            return 'PARTIAL', '仅 %d/3 个受限站点通过' % len(direct_good), None
    if len(proxy_reachable) >= 2:
        return 'PARTIAL', 'Psiphon 代理收到多站点回应，业务验证未达标', None
    if len(direct_reachable) >= 2:
        return 'UNCONFIRMED', '直接连接有回应但路由归属未确认', None
    return 'DOWN', '未发现可验证的 Psiphon 通道', None

def refresh_proxy_guard(session, guard_path):
    proc = session.get('proc')
    if session['name'] != 'Psiphon' or proc is None or proc.poll() is not None:
        return
    snapshot = managed_proxy_snapshot(proc, session['program'])
    if snapshot is None or not session.get('baseline'):
        return
    previous = session.get('observed')
    if previous is None:
        try:
            record = read_json_bounded(guard_path, 65536)
            if valid_proxy_guard(record) and proxy_snapshot_equal(record['baseline'], session['baseline']):
                previous = record['observed']
                session['observed'] = previous
        except (OSError, ValueError, TypeError, KeyError):
            pass
    if previous is not None:
        if (previous.get('ProxyServer') or '') == (snapshot.get('ProxyServer') or ''):
            return
        candidate = dict(previous)
        candidate['ProxyServer'] = snapshot['ProxyServer']
        candidate = proxy_with_flags(candidate, (proxy_flags(previous) & ~2) | (proxy_flags(snapshot) & 2))
    else:
        candidate = snapshot
    if not proxy_snapshot_equal(session['baseline'], candidate):
        if save_proxy_guard(guard_path, session['baseline'], candidate, session.get('baseline_types')):
            session['observed'] = candidate
        else:
            item('恢复', '无法保存 Psiphon 代理恢复记录，正在重试')

def system_integration(session, code, detail):
    value = (code, detail)
    if session.get('integration_state') != value:
        session['integration_state'] = value
        item('系统接入', code + '：' + detail)

def verify_tor_http_proxy(session, force=False):
    thread = session.get('http_thread')
    server = session.get('http_server')
    if server is None or thread is None or not thread.is_alive() or not server.active:
        return False
    cache = session.get('http_probe')
    now = time.monotonic()
    if cache is not None and not force:
        interval = TOR_HTTP_VERIFY_INTERVAL if cache[1] else 12
        if now - cache[0] < interval:
            return cache[1]
    endpoint = ('HTTP', '127.0.0.1', server.server_address[1], os.getpid())
    verified, _ = probe_quorum('HTTP', endpoint)
    passed = len(verified) >= 2
    session['http_probe'] = (time.monotonic(), passed)
    return passed

def apply_tor_proxy(session, guard_path):
    if session['name'] != 'Tor' or session.get('integration_problem'):
        return False
    if session.get('observed') is not None:
        current = proxy_registry_snapshot()
        same_routing = (valid_proxy_snapshot(current) and
                        proxy_flags(current) == proxy_flags(session['observed']) and all(
                            (current.get(field) or '') == (session['observed'].get(field) or '')
                            for field in ('ProxyServer', 'AutoConfigURL')))
        if not same_routing:
            system_integration(session, 'CONFLICT', 'Windows 代理设置已变化，停止自动接管')
            return False
        passed = verify_tor_http_proxy(session) and verify_windows_proxy(session)
        system_integration(session, 'PROXY_APPLIED' if passed else 'CHANNEL_READY',
                           '本地转接与 Windows 默认代理访问均已验证' if passed else
                           '本地通道存在，但 Windows 默认代理访问未通过验证')
        return passed
    original, types = proxy_registry_snapshot(with_types=True)
    if original is None:
        system_integration(session, 'CHANNEL_READY', 'Windows 代理接口读取失败，未修改系统')
        return False
    if proxy_flags(original) & (2 | 4):
        system_integration(session, 'CONFLICT', '保留已有显式代理或 PAC，不覆盖')
        return False
    try:
        port = start_tor_http_proxy(session)
        if not verify_tor_http_proxy(session, force=True):
            raise RuntimeError('本地 HTTP 转接未通过验证')
    except (OSError, RuntimeError, ValueError):
        stop_tor_http_proxy(session)
        system_integration(session, 'CHANNEL_READY', 'Tor 本地转接尚未通过验证')
        return False
    expected = dict(original)
    expected['ProxyServer'] = 'http=127.0.0.1:%s;https=127.0.0.1:%s' % (port, port)
    expected['ProxyOverride'] = '<local>'
    expected = proxy_with_flags(expected, (proxy_flags(original) & ~12) | 3)
    if not start_proxy_watchdog(guard_path) or not save_proxy_guard(guard_path, original, expected, types):
        stop_tor_http_proxy(session)
        system_integration(session, 'CONFLICT', '代理恢复保护未就绪，未修改系统')
        return False
    session.update(baseline=original, baseline_types=types, observed=expected, proxy_steps=[])
    if write_proxy_snapshot(original, expected) and verify_windows_proxy(session, force=True):
        system_integration(session, 'PROXY_APPLIED', '本地转接与 Windows 默认代理访问均已验证')
        return True
    if restore_managed_proxy(original, expected):
        safe_remove(guard_path)
        session.update(baseline=None, observed=None, proxy_steps=[])
        stop_tor_http_proxy(session)
        system_integration(session, 'CHANNEL_READY', 'Windows 默认代理验证失败，已回滚接入')
    else:
        session['integration_problem'] = True
        system_integration(session, 'CONFLICT', '系统接入未完成，转接与恢复记录继续保留')
    return False

def cleanup_session(session, guard_path, exiting=False):
    if not session or session.get('deferred_cleanup'):
        return
    name, proc = session['name'], session.get('proc')
    if name == 'Psiphon' and session.get('owned') and guard_path.is_file():
        capture_armed_psiphon_guard(guard_path)
        try:
            record = read_json_bounded(guard_path, 65536)
            if valid_proxy_guard(record) and proxy_snapshot_equal(record['baseline'], session['baseline']):
                session['observed'] = record['observed']
        except (OSError, ValueError, TypeError, KeyError):
            pass
    if name == 'Tor' and session.get('observed') and session.get('baseline'):
        if not restore_managed_proxy(session['baseline'], session['observed']):
            session['deferred_cleanup'] = True
            thread = threading.Thread(target=deferred_proxy_cleanup,
                                      args=(session, guard_path, exiting), daemon=False,
                                      name='PendingProxyRecovery')
            try:
                with PROXY_RECOVERY_LOCK:
                    PROXY_RECOVERY_THREADS.add(thread)
                    thread.start()
            except RuntimeError:
                with PROXY_RECOVERY_LOCK:
                    PROXY_RECOVERY_THREADS.discard(thread)
                session['deferred_cleanup'] = False
                deferred_proxy_cleanup(session, guard_path, exiting)
            diagnostic('Windows 代理暂未恢复，继续保留转接服务并在后台重试')
            return
        remove_session_guard(guard_path, session)
        item('恢复', '已清理受管代理，并保留其他程序的新设置')
    if name == 'Tor':
        stop_tor_http_proxy(session)
    if proc is not None and proc.poll() is None and session.get('owned'):
        if name == 'Psiphon' and same_executable(proc.pid, session['program']):
            request_graceful_close(proc.pid)
            try:
                proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
        job = session.pop('job', None)
        if job is not None:
            close_windows_handle(job)
        if proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass
        try:
            proc.wait(timeout=4)
        except (OSError, subprocess.TimeoutExpired):
            diagnostic(name + ' 受管进程尚未退出，独立监护继续处理')
    job = session.pop('job', None)
    if job is not None:
        close_windows_handle(job)
    if name == 'Tor':
        reader = session.get('tor_status_thread')
        if reader is not None and reader.is_alive():
            reader.join(timeout=1)
        rc = session.get('torrc')
        if rc is not None and (proc is None or proc.poll() is not None):
            safe_remove(rc)
    if name == 'Psiphon' and session.get('observed') and session.get('baseline'):
        if proxy_ports_unclaimed(session['observed'], session['baseline']):
            if restore_managed_proxy(session['baseline'], session['observed']):
                remove_session_guard(guard_path, session)
    if name == 'Psiphon' and session.get('owned') and guard_path.is_file():
        recover_proxy_guard(guard_path)
    diagnostic(name + (' 监控退出' if exiting else ' 切换引擎'))

def run_engine(session, data, guard_path, state, state_path):
    name = session['name']
    since = time.monotonic()
    unavailable_since = None
    ever_healthy = False
    last_saved = since
    last_network_check = since
    failed_streak = 0
    healthy_since = None
    healthy_seconds = 0.0
    integration_failures = 0
    try:
        while not STOP.is_set():
            proc = session.get('proc')
            if name in ('Tor', 'Psiphon') and proc is not None and proc.poll() is not None:
                now = time.monotonic()
                if healthy_since is not None:
                    healthy_seconds += max(0, now - healthy_since)
                    healthy_since = None
                diagnostic(name + ' 进程提前结束，立即尝试其他连接方案')
                if name == 'Tor' and session.get('tor_warning'):
                    item('Tor', '退出原因线索：' + session['tor_warning'][:150])
                session['local_failure'] = name + ' 客户端进程提前退出'
                if name == 'Tor':
                    session['candidate_failure'] = True
                record_session_failure(session, state, state_path,
                                       healthy_seconds if ever_healthy else None)
                item('恢复', name + ' 已退出，不等待启动超时')
                return
            refresh_proxy_guard(session, guard_path)
            if time.monotonic() - last_network_check >= 75:
                signature = network_signature()
                if signature is not None:
                    if signature.hex()[:16] != state.get('_network_key'):
                        reset_bridge_discovery()
                        item('恢复', '网络配置变化，在线学习已切换到相应网络画像')
                activate_network_model(state, signature)
                last_network_check = time.monotonic()
            start_bridge_discovery(data)
            kind, message, latency = health_session(session, state)
            if STOP.is_set():
                return
            now = time.monotonic()
            if name == 'Tor' and kind == 'PROXY':
                if name == 'Tor' and not session.get('bridge_recorded'):
                    record_bridge(state, session.get('bridge'), True)
                    session['bridge_recorded'] = True
                    session['bridge_success'] = True
                    save_state(state_path, state)
                if not apply_tor_proxy(session, guard_path):
                    integration_failures += 1
                    detail = session.get('integration_state', ('TOR_READY', ''))
                    message += '；本地通道已验证，但 Windows 系统代理尚未接入'
                    kind = 'PARTIAL'
                    if detail[0] == 'CONFLICT' or integration_failures >= 3:
                        session['integration_failure'] = True
                        item('访问测试', kind + '：' + message)
                        connection_state(name + ' 通道可用，但自动接入未完成', message)
                        record_session_failure(session, state, state_path)
                        diagnostic(name + ' 未能安全接入 Windows 系统代理，尝试其他引擎')
                        return
                else:
                    integration_failures = 0
            item('连接状态', message)
            item('最近检查', datetime.datetime.now().strftime('%H:%M:%S'))
            item('运行引擎', name + (' / ' + session['bridge'][0] if session.get('bridge') else ''))
            item('访问测试', kind + '：' + message)
            if kind in ('VPN', 'PROXY'):
                if name != 'Tor':
                    start_tor_preparation(data, state)
                clear_preparation_failure(state, name)
                if healthy_since is None:
                    healthy_since = now
                failed_streak = 0
                unavailable_since = None
                if not session.get('attempt_recorded'):
                    engine_stats(state, name, True, latency)
                    if name == 'Tor' and not session.get('bridge_recorded'):
                        record_bridge(state, session.get('bridge'), True)
                        session['bridge_recorded'] = True
                        session['bridge_success'] = True
                    session['attempt_recorded'] = True
                    session['recorded_success'] = True
                    state['connections'] = min(state.get('connections', 0) + 1, 1000000)
                    item('AI 学习', model_summary(state))
                    save_state(state_path, state)
                ever_healthy = True
                if kind == 'VPN':
                    system_integration(session, 'VPN_VERIFIED', '已验证抽样网站的 TCP/443 路由，不涵盖全部协议')
                    title = 'VPN 路由已验证：' + name
                    detail = message + '；DNS、UDP、IPv6 等完整覆盖范围尚未验证'
                else:
                    if name != 'Tor':
                        system_integration(session, 'PROXY_VERIFIED', 'Windows 代理端口归属与网站访问已验证')
                    title = '代理通道已验证：' + name
                    detail = message + '；只有使用该代理的应用受益'
                connection_state(title, detail)
                stage(100, '已通过多站点连通性验证', detail)
                item('恢复', '持续监测通道；故障时有限频切换')
                interval = max(18, min(55, int(20 + 6 * (latency or 0))))
            else:
                if healthy_since is not None:
                    healthy_seconds += max(0, now - healthy_since)
                    healthy_since = None
                failed_streak += 1
                if unavailable_since is None:
                    unavailable_since = now
                elapsed = now - (unavailable_since if ever_healthy else since)
                connection_state('正在验证/恢复：' + name, message)
                if kind == 'UNCONFIRMED':
                    system_integration(session, 'UNCONFIRMED', '目标网站可达，但无法证明属于当前受管通道')
                    item('恢复', '网站可达，但尚未证明受管通道；暂不冒进重启')
                else:
                    if kind != 'PARTIAL' or name != 'Tor':
                        system_integration(session, 'RECOVERING', '本次复测未达到受管通道的验证标准')
                    item('恢复', '连续 %s 次未验证，通过限频策略考虑切换' % failed_streak)
                stage(82 if ever_healthy else 87, '正在验证/恢复：' + name, message)
                if ((not ever_healthy and startup_expired(session, since, now))
                        or (ever_healthy and failed_streak >= 5 and elapsed >= ENGINE_OUTAGE_WINDOW)):
                    record_session_failure(session, state, state_path,
                                           healthy_seconds if ever_healthy else None)
                    diagnostic(name + ' 连续故障，进入冷却后尝试其他引擎')
                    return
                interval = 16 if kind == 'UNCONFIRMED' else 10 if not ever_healthy else 28
            if now - last_saved >= 125:
                save_state(state_path, state)
                write_diagnostics(data)
                last_saved = now
            item('自适应', '历史验证 %s 次；%s 秒后复测' % (state.get('connections', 0), interval))
            if STOP.wait(interval):
                return
    finally:
        if healthy_since is not None:
            healthy_seconds += max(0, time.monotonic() - healthy_since)
        session['healthy_seconds'] = healthy_seconds
        if STOP.is_set() and session.get('recorded_success') and not session.get('failure_recorded'):
            record_engine_uptime(state, name, healthy_seconds)
            save_state(state_path, state)

def connect(data):
    validate_windows()
    stage(5, 'Windows 11 x64 已验证', '将在选择的目录内保存运行数据')
    item('系统', 'Windows 11 x64 / Python %s.%s' % sys.version_info[:2])
    for scratch in data.glob('psiphon3.part.*.exe'):
        safe_remove(scratch)
    for scratch in data.glob('tor-expert-*.tar.gz.part.*'):
        try:
            if time.time() - scratch.stat().st_mtime > 1800:
                safe_remove(scratch)
        except OSError:
            pass
    item('数据目录', str(data))
    state_path = data / 'state.json'
    guard_path = data / 'proxy_guard.json'
    recover_proxy_guard(guard_path)
    state = load_state(state_path)
    start_tor_preparation(data, state)
    item('AI 学习', model_summary(state))
    item('调度算法', '使用在线逻辑回归及探索-利用策略；只试经官方发布的候选')
    start_bridge_discovery(data)
    for name in ENGINE_ORDER:
        item(name, '免账户、自动准备；能否连通取决于当前网络的实测结果')
    last_network = None
    while not STOP.is_set():
        current_network = network_signature()
        if current_network is not None and last_network is not None and current_network != last_network:
            for entry in state.get('engines', {}).values():
                entry['cooldown'] = 0
                entry['failure_streak'] = 0
            diagnostic('Windows 网络配置已变化，重置引擎冷却时间')
            item('恢复', '检测到网络配置变化，立即重新评估连接方案')
            reset_bridge_discovery()
            for entry in state.get('preparations', {}).values():
                entry['cooldown'] = 0
                entry['failure_streak'] = 0
        if current_network is not None:
            last_network = current_network
        activate_network_model(state, current_network)
        recover_proxy_guard(guard_path)
        if pause_for_proxy_recovery(guard_path, '等待上次网络代理安全恢复'):
            continue
        start_bridge_discovery(data)
        stage(17, '检测已有可信 Psiphon', '优先复用已验证的连接')
        existing_psiphon = running_verified_psiphon()
        if existing_psiphon is not None:
            existing = existing_vpn_session({'Psiphon': existing_psiphon})
            if existing is not None:
                stage(100, '复用当前 VPN', '已确认已有 Psiphon 路由')
                try:
                    run_engine(existing, data, guard_path, state, state_path)
                finally:
                    cleanup_session(existing, guard_path, exiting=STOP.is_set())
                if STOP.is_set():
                    return
        if pause_for_proxy_recovery(guard_path, '检查现有代理恢复状态'):
            continue
        for name in engines_ranked(state, ENGINE_ORDER):
            if STOP.is_set():
                return
            if managed_proxy_conflict(guard_path):
                break
            record = state.get('engines', {}).get(name, {})
            preparation = state.get('preparations', {}).get(name, {})
            if max(nonnegative(record.get('cooldown')),
                   nonnegative(preparation.get('cooldown'))) > time.time():
                continue
            tor_files = None
            if name == 'Tor':
                try:
                    stage(12, '自动获取 Tor 官方程序', '校验固定版本 SHA-256，读取官方网桥集合')
                    tor_files = prepared_tor_files(data)
                except (OSError, RuntimeError, ValueError, KeyError, tarfile.TarError,
                        urllib.error.URLError, http.client.HTTPException, TimeoutError) as exc:
                    if STOP.is_set():
                        return
                    diagnostic('Tor 准备失败：' + type(exc).__name__ + ' ' + str(exc)[:125])
                    item('Tor', '官方组件尚无法获取：' + str(exc)[:110])
                    record_preparation_failure(state, name, exc)
                    save_state(state_path, state)
                    continue
            profiles = ranked_tor_bridges(tor_bridge_profiles(data), state) if name == 'Tor' else [None]
            for bridge in profiles:
                if STOP.is_set():
                    return
                if bridge is not None:
                    item('Tor 网桥', bridge[0] + '（官方内置/发现）')
                item('运行引擎', '正在尝试 ' + name)
                item('AI 学习', model_summary(state))
                stage(15, '正在准备：' + name, '自动启动并验证真实访问结果')
                session = None
                try:
                    session = create_session(name, data, state, state_path, bridge, tor_files)
                    if session is None:
                        continue
                    run_engine(session, data, guard_path, state, state_path)
                except (OSError, RuntimeError, ValueError, KeyError, tarfile.TarError,
                        urllib.error.URLError, http.client.HTTPException, TimeoutError) as exc:
                    if STOP.is_set():
                        return
                    diagnostic(name + '：' + type(exc).__name__ + ' ' + str(exc)[:125])
                    item(name, '暂不可用：' + str(exc)[:115])
                    if session is None:
                        record_preparation_failure(state, name, exc)
                        save_state(state_path, state)
                    else:
                        session['local_failure'] = type(exc).__name__ + '：' + str(exc)
                        record_session_failure(session, state, state_path, session.get('healthy_seconds'))
                    connection_state('正在尝试其他可用通道', name + '：' + str(exc)[:120])
                finally:
                    cleanup_session(session, guard_path, exiting=STOP.is_set())
                    write_diagnostics(data)
                if STOP.is_set():
                    return
                if managed_proxy_conflict(guard_path):
                    break
                if (name == 'Tor' and (session is None or session.get('integration_failure')
                                      or (session.get('local_failure')
                                          and not session.get('candidate_failure')))):
                    break
        if pause_for_proxy_recovery(guard_path, '切换引擎前需要恢复系统代理'):
            continue
        stage(15, '候选通道暂不可用', '未伪报成功；30秒后重新发现及尝试')
        connection_state('等待重新检测', '官方引擎无账号要求，但下载和连通性受当前网络限制')
        item('恢复', '等待 30 秒，之后自动重新检查')
        item('AI 学习', model_summary(state))
        save_state(state_path, state)
        write_diagnostics(data)
        if STOP.wait(30):
            return

def worker(data):
    try:
        errors = 0
        while not STOP.is_set():
            try:
                connect(data)
                return
            except Exception as exc:
                if STOP.is_set():
                    return
                errors += 1
                message = type(exc).__name__ + '：' + str(exc)[:150]
                diagnostic('监控程序异常：' + message)
                write_diagnostics(data)
                stage(0, '监控发生错误，正在受控重试', message)
                item('连接状态', '监控异常，自动重试中')
                connection_state('监控异常', message)
                if STOP.wait(min(120, 8 * 2 ** min(errors - 1, 4))):
                    return
    finally:
        if STOP.is_set():
            finish_tor_preparations()

def acquire_mutex():
    from ctypes import wintypes
    digest = 'AccessMonitor_AllEngines_PerWindowsSession_v1'
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateMutexW.argtypes = (ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR)
    kernel.CreateMutexW.restype = wintypes.HANDLE
    mutex = kernel.CreateMutexW(None, False, 'Local\\PsiphonMonitor_' + digest)
    if not mutex:
        raise OSError('无法创建运行实例互斥锁')
    if ctypes.get_last_error() == 183:
        kernel.CloseHandle(ctypes.c_void_p(mutex))
        raise RuntimeError('本 Windows 会话已运行一个网络监控实例')
    return mutex

def enable_high_dpi():
    if sys.platform != 'win32':
        return
    try:
        user32 = ctypes.windll.user32
        user32.SetProcessDpiAwarenessContext.argtypes = (ctypes.c_void_p,)
        user32.SetProcessDpiAwarenessContext.restype = ctypes.c_bool
        if user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4)):
            return
    except (OSError, AttributeError, TypeError, ValueError):
        pass
    try:
        if ctypes.windll.shcore.SetProcessDpiAwareness(2) == 0:
            return
    except (OSError, AttributeError, TypeError, ValueError):
        pass
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except (OSError, AttributeError, TypeError, ValueError):
        pass

def window_dpi(app):
    if sys.platform == 'win32':
        try:
            get_dpi = ctypes.windll.user32.GetDpiForWindow
            get_dpi.argtypes = (ctypes.c_void_p,)
            get_dpi.restype = ctypes.c_uint
            result = int(get_dpi(app.winfo_id()))
            if 72 <= result <= 600:
                return result
        except (OSError, AttributeError, TypeError, ValueError, tk.TclError):
            pass
    try:
        return max(96, min(384, round(app.winfo_fpixels('1i'))))
    except tk.TclError:
        return 96

def main():
    global tk, filedialog, ttk, tkfont
    import tkinter as tk
    from tkinter import filedialog, ttk, font as tkfont
    enable_high_dpi()
    app = tk.Tk()
    app.withdraw()
    app.title('AETHER · 官方多通道自适应网络控制台')
    folder = filedialog.askdirectory(parent=app, title='选择客户端与运行数据保存文件夹', mustexist=True)
    if not folder:
        app.destroy()
        return
    selected_folder = pathlib.Path(folder).resolve()
    data = selected_folder / 'connection_data'
    BG = '#0A1220'
    SURFACE = '#111E30'
    CARD = '#16243A'
    CARD_ALT = '#192B41'
    BORDER = '#293B52'
    WHITE = '#F1F6FC'
    SOFT = '#D9E5F2'
    MUTED = '#AABACD'
    ACCENT = '#75D8D0'
    TEAL = '#46C9AD'
    WARNING = '#FFD08A'
    app.configure(bg=BG)
    dpi = [0]

    def apply_dpi():
        value = window_dpi(app)
        if value == dpi[0]:
            return False
        dpi[0] = value
        try:
            app.tk.call('tk', 'scaling', value / 72)
        except tk.TclError:
            pass
        return True

    apply_dpi()
    screen_width = app.winfo_screenwidth()
    screen_height = app.winfo_screenheight()
    screen_scale = min(3.0, max(1.0, dpi[0] / 96))
    width = min(round(1120 * screen_scale),
                max(330, screen_width - round(48 * screen_scale)))
    height = min(round(815 * screen_scale),
                 max(360, screen_height - round(68 * screen_scale)))
    app.geometry('%sx%s+%s+%s' % (width, height, max(0, (screen_width-width)//2),
                                  max(0, (screen_height-height)//2)))
    app.minsize(min(round(350 * screen_scale), screen_width),
                min(round(410 * screen_scale), screen_height))
    app.configure(highlightthickness=0)
    main_font = 'Microsoft YaHei UI'
    latin_font = 'Segoe UI'
    typefaces = {
        'brand': tkfont.Font(root=app, family=latin_font, size=13, weight='bold'),
        'eyebrow': tkfont.Font(root=app, family=main_font, size=11, weight='bold'),
        'hero': tkfont.Font(root=app, family=main_font, size=21, weight='bold'),
        'body': tkfont.Font(root=app, family=main_font, size=12),
        'small': tkfont.Font(root=app, family=main_font, size=11),
        'title': tkfont.Font(root=app, family=main_font, size=14, weight='bold'),
        'value': tkfont.Font(root=app, family=main_font, size=17, weight='bold'),
        'metric': tkfont.Font(root=app, family=main_font, size=16, weight='bold')
    }

    def label(parent, text=None, variable=None, role='body', fg=SOFT, bg=None, **options):
        args = {'font': typefaces[role], 'fg': fg,
                'bg': bg or parent.cget('bg'), 'anchor': 'w', 'justify': 'left'}
        args.update(options)
        if variable is not None:
            args['textvariable'] = variable
        else:
            args['text'] = text
        return tk.Label(parent, **args)

    shell = tk.Frame(app, bg=BG)
    shell.pack(fill='both', expand=True)
    topbar = tk.Frame(shell, bg=BG)
    topbar.pack(fill='x', padx=24, pady=(18, 13))
    identity = tk.Frame(topbar, bg=BG)
    identity.pack(side='left', fill='x', expand=True)
    label(identity, text='AETHER  /  NETWORK', role='brand', fg=WHITE).pack(anchor='w')
    label(identity, text='WINDOWS 11  ·  在线学习 / 官方通道容灾',
          role='small', fg=MUTED).pack(anchor='w', pady=(2, 0))
    badge = tk.Frame(topbar, bg=SURFACE, padx=13, pady=8,
                     highlightbackground=BORDER, highlightthickness=1)
    badge.pack(side='right', padx=(8, 0))
    badge_value = tk.StringVar(value='●  准备就绪')
    badge_label = label(badge, variable=badge_value, role='eyebrow', fg=WARNING, bg=SURFACE)
    badge_label.pack()
    hero = tk.Frame(shell, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
    hero.pack(fill='x', padx=24, pady=(0, 11))
    hero_inner = tk.Frame(hero, bg=SURFACE)
    hero_inner.pack(fill='x', padx=20, pady=16)
    hero_eyebrow = label(hero_inner, text='LIVE CONNECTION STATUS', role='brand', fg=ACCENT, bg=SURFACE)
    hero_eyebrow.pack(anchor='w', pady=(0, 5))
    status = tk.StringVar(value='正在初始化网络调度')
    hero_title = label(hero_inner, variable=status, role='hero', fg=WHITE, bg=SURFACE,
                       wraplength=650)
    hero_title.pack(fill='x', anchor='w')
    detail = tk.StringVar(value='选择目录已完成。正在准备连接、验证网络和加载历史学习状态。')
    hero_detail = label(hero_inner, variable=detail, role='body', fg=SOFT, bg=SURFACE,
                        wraplength=650)
    hero_detail.pack(fill='x', anchor='w', pady=(6, 12))
    progress_line = tk.Frame(hero_inner, bg=SURFACE)
    progress_line.pack(fill='x')
    progress_title = tk.StringVar(value='启动准备')
    label(progress_line, variable=progress_title, role='small', fg=MUTED, bg=SURFACE).pack(side='left')
    percent = tk.StringVar(value='0%')
    label(progress_line, variable=percent, role='small', fg=WHITE, bg=SURFACE).pack(side='right')
    style = ttk.Style(app)
    style.theme_use('clam')
    style.configure('Aether.Horizontal.TProgressbar', background=TEAL,
                    troughcolor='#283A51', bordercolor=SURFACE,
                    lightcolor=TEAL, darkcolor=TEAL, thickness=8)
    style.configure('Aether.Vertical.TScrollbar', gripcount=0, background='#38506A',
                    troughcolor=BG, bordercolor=BG, arrowsize=11, lightcolor='#38506A',
                    darkcolor='#38506A')
    bar = ttk.Progressbar(hero_inner, maximum=100, value=0,
                          style='Aether.Horizontal.TProgressbar')
    bar.pack(fill='x', pady=(7, 0))

    region = tk.Frame(shell, bg=BG)
    region.pack(fill='both', expand=True, padx=19, pady=(0, 5))
    canvas = tk.Canvas(region, bg=BG, highlightthickness=0, borderwidth=0,
                       takefocus=0)
    scroll = ttk.Scrollbar(region, orient='vertical', command=canvas.yview,
                           style='Aether.Vertical.TScrollbar')
    scroll.pack(side='right', fill='y')
    canvas.pack(side='left', fill='both', expand=True)
    canvas.configure(yscrollcommand=scroll.set)
    body = tk.Frame(canvas, bg=BG)
    body_id = canvas.create_window((0, 0), window=body, anchor='nw')
    canvas.bind('<Configure>', lambda e: canvas.itemconfigure(body_id, width=e.width))
    body.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox('all')))

    section_subtitles = []

    def section_title(text, subtitle):
        row = tk.Frame(body, bg=BG)
        row.pack(fill='x', padx=5, pady=(19, 10))
        label(row, text=text, role='title', fg=WHITE).pack(anchor='w')
        sub_label = label(row, text=subtitle, role='small', fg=MUTED, wraplength=500)
        sub_label.pack(anchor='w', pady=(3, 0))
        section_subtitles.append(sub_label)
        return row

    section_title('运行概览', '真实连接与验证结果，区分自建代理、系统代理及整机 VPN')
    metric_grid = tk.Frame(body, bg=BG)
    metric_grid.pack(fill='x')
    metric_values = {
        '运行引擎': tk.StringVar(value='等待调度'),
        '通道等级': tk.StringVar(value='尚未验证'),
        '最近检查': tk.StringVar(value='—'),
        '历史验证': tk.StringVar(value='0 次')
    }
    metric_items = []
    for caption, sub in (('运行引擎', '当前尝试的实际传输'),
                         ('通道等级', '基于外部网站探测'),
                         ('最近检查', '实时连通性复测'),
                         ('历史验证', '保存的成功连接次数')):
        metric_card = tk.Frame(metric_grid, bg=CARD, highlightthickness=1,
                               highlightbackground=BORDER)
        inner = tk.Frame(metric_card, bg=CARD)
        inner.pack(fill='both', expand=True, padx=16, pady=13)
        label(inner, text=caption, role='small', fg=MUTED, bg=CARD).pack(anchor='w')
        label(inner, variable=metric_values[caption], role='metric', fg=WHITE,
              bg=CARD, wraplength=220).pack(anchor='w', fill='x', pady=(5, 4))
        label(inner, text=sub, role='small', fg=MUTED, bg=CARD,
              wraplength=220).pack(anchor='w')
        metric_items.append(metric_card)

    section_title('可自动准备的引擎', '只保留无需登录或手工配置的官方引擎；连通性以实时验证为准')
    engines_grid = tk.Frame(body, bg=BG)
    engines_grid.pack(fill='x')
    engine_info = {}
    engine_items = []
    engine_subtitles = {'Psiphon': '官方免账户 Windows 客户端，自动下载及验证',
                        'Tor': '官方 Expert Bundle / 多传输网桥自动发现'}
    for engine_name in ENGINE_ORDER:
        engine_card = tk.Frame(engines_grid, bg=CARD,
                               highlightbackground=BORDER, highlightthickness=1)
        content = tk.Frame(engine_card, bg=CARD)
        content.pack(fill='both', expand=True, padx=16, pady=13)
        hdr = tk.Frame(content, bg=CARD)
        hdr.pack(fill='x')
        label(hdr, text=engine_name, role='title', fg=ACCENT if engine_name == 'Psiphon' else WHITE,
              bg=CARD).pack(side='left')
        pill_text = '免账户' if engine_name == 'Psiphon' else '自发现'
        label(hdr, text=pill_text, role='small', fg=TEAL if engine_name == 'Psiphon' else MUTED,
              bg=CARD).pack(side='right')
        label(content, text=engine_subtitles[engine_name], role='small', fg=MUTED,
              bg=CARD).pack(anchor='w', pady=(5, 6))
        text_var = tk.StringVar(value='正在检测')
        text_label = label(content, variable=text_var, role='body', fg=SOFT, bg=CARD,
                           wraplength=250)
        text_label.pack(fill='x', anchor='w')
        engine_info[engine_name] = (text_var, text_label)
        engine_items.append(engine_card)

    section_title('智能路由与网络诊断', '详细检测状态随网络变化更新；下方信息将自动缓慢轮播')
    detail_grid = tk.Frame(body, bg=BG)
    detail_grid.pack(fill='x')
    diagnostic_names = ('调度算法', 'AI 学习', '通道发现', '连接状态', '系统接入',
                        '访问测试', '自适应', '恢复', 'Tor 网桥',
                        '安全', '下载', '系统', '数据目录', '存储')
    diagnostic_items = []
    diagnostics = {}
    for name in diagnostic_names:
        card = tk.Frame(detail_grid, bg=CARD_ALT,
                        highlightbackground=BORDER, highlightthickness=1)
        inner = tk.Frame(card, bg=CARD_ALT)
        inner.pack(fill='both', expand=True, padx=15, pady=12)
        label(inner, text=name, role='eyebrow', fg=MUTED, bg=CARD_ALT).pack(anchor='w')
        value = tk.StringVar(value='—')
        field = label(inner, variable=value, role='body', fg=SOFT, bg=CARD_ALT,
                      wraplength=260)
        field.pack(fill='x', anchor='w', pady=(5, 0))
        diagnostics[name] = (value, field)
        diagnostic_items.append(card)

    footer = tk.Frame(shell, bg=BG)
    footer.pack(fill='x', padx=24, pady=(1, 10))
    footer_text = label(footer, text='●  自动发现官方通道  ·  实测连通性  ·  在线学习  ·  退出后恢复受管系统代理',
                        role='small', fg=MUTED, wraplength=800)
    footer_text.pack(anchor='w', fill='x')
    app.deiconify()
    app.update_idletasks()

    layout_key = [None]
    badge_compact = [False]

    def grid_cards(frame, cards, count, width_pixels, gap=10):
        card_width = max(160, (width_pixels - gap * (count - 1) - 12) // count)
        for index, card in enumerate(cards):
            card.grid(row=index // count, column=index % count,
                      sticky='nsew', padx=(0, gap if index % count < count - 1 else 0),
                      pady=(0, gap))
        for column in range(4):
            frame.grid_columnconfigure(column, weight=1 if column < count else 0,
                                       minsize=0)
        return card_width

    def reflow(event=None):
        available_width = max(280, canvas.winfo_width() - 3)
        logical_width = available_width * 96 / max(96, window_dpi(app))
        compact = logical_width < 610
        large = logical_width >= 950
        metrics = 1 if logical_width < 355 else 2 if logical_width < 870 else 4
        engines = 1 if logical_width < 615 else 2
        details = 1 if logical_width < 740 else 2
        signature = (metrics, engines, details, available_width // 12,
                     window_dpi(app))
        if signature != layout_key[0]:
            layout_key[0] = signature
            cell_metric = grid_cards(metric_grid, metric_items, metrics, available_width)
            cell_engine = grid_cards(engines_grid, engine_items, engines, available_width)
            cell_detail = grid_cards(detail_grid, diagnostic_items, details, available_width)
            for card in metric_items:
                for field in card.winfo_children()[0].winfo_children():
                    if isinstance(field, tk.Label):
                        field.configure(wraplength=max(140, cell_metric - 38))
            for key, (_, field) in engine_info.items():
                field.configure(wraplength=max(160, cell_engine - 38))
            for key, (_, field) in diagnostics.items():
                field.configure(wraplength=max(160, cell_detail - 38))
        root_width = max(300, app.winfo_width())
        hero_title.configure(wraplength=max(190, root_width - 100))
        hero_detail.configure(wraplength=max(190, root_width - 100))
        footer_text.configure(wraplength=max(220, root_width - 48))
        for subtitle in section_subtitles:
            subtitle.configure(wraplength=max(180, available_width - 20))
        if compact != badge_compact[0]:
            badge_compact[0] = compact
            badge.pack_forget()
            identity.pack_forget()
            if compact:
                identity.pack(in_=topbar, side='top', fill='x')
                badge.pack(in_=topbar, side='top', anchor='w', pady=(10, 0))
            else:
                identity.pack(in_=topbar, side='left', fill='x', expand=True)
                badge.pack(in_=topbar, side='right', anchor='n', padx=(8, 0))
        target_size = 18 if compact else 21 if not large else 23
        if typefaces['hero'].cget('size') != target_size:
            typefaces['hero'].configure(size=target_size)

    canvas.bind('<Configure>', lambda e: (canvas.itemconfigure(body_id, width=e.width), reflow()))
    app.bind('<Configure>', lambda e: reflow() if e.widget is app else None)
    app.after(80, reflow)

    scroll_state = {'manual_until': 0.0, 'direction': 1, 'pause_until': 0.0}

    def user_scroll(event):
        scroll_state['manual_until'] = time.monotonic() + 30
        if getattr(event, 'delta', 0):
            delta = event.delta
            canvas.yview_scroll((-1 if delta > 0 else 1) *
                                max(1, round(abs(delta) / 120)) * 3, 'units')
        elif getattr(event, 'num', 0) == 4:
            canvas.yview_scroll(-3, 'units')
        elif getattr(event, 'num', 0) == 5:
            canvas.yview_scroll(3, 'units')
        return 'break'

    def bind_wheel(widget):
        widget.bind('<MouseWheel>', user_scroll)
        widget.bind('<Button-4>', user_scroll)
        widget.bind('<Button-5>', user_scroll)
        for child in widget.winfo_children():
            bind_wheel(child)

    bind_wheel(canvas)
    bind_wheel(body)
    scroll.bind('<ButtonPress-1>', lambda e: scroll_state.update(manual_until=time.monotonic() + 30))

    def auto_scroll():
        if STOP.is_set():
            return
        try:
            if time.monotonic() >= scroll_state['manual_until']:
                lo, hi = canvas.yview()
                if hi - lo < 0.997 and time.monotonic() >= scroll_state['pause_until']:
                    if scroll_state['direction'] > 0 and hi >= 0.991:
                        scroll_state['direction'] = -1
                        scroll_state['pause_until'] = time.monotonic() + 3
                    elif scroll_state['direction'] < 0 and lo <= 0.009:
                        scroll_state['direction'] = 1
                        scroll_state['pause_until'] = time.monotonic() + 3
                    else:
                        canvas.yview_moveto(max(0, min(1, lo + 0.075 * (hi - lo) * scroll_state['direction'])))
        except tk.TclError:
            return
        app.after(520, auto_scroll)

    app.after(2800, auto_scroll)
    diagnostics['数据目录'][0].set(str(data))
    diagnostics['存储'][0].set('状态、日志与 Tor 资源存放所选目录；官方客户端可能自行保存系统数据')

    def set_badge(text, color):
        badge_value.set('●  ' + text)
        badge_label.configure(fg=color)

    def poll_ui():
        if STOP.is_set():
            return
        for _ in range(160):
            try:
                kind, values = MESSAGES.get_nowait()
            except queue.Empty:
                break
            if kind == 'stage':
                amount, title, message = values
                if amount in (82, 87):
                    if str(bar['mode']) != 'indeterminate':
                        bar.configure(mode='indeterminate')
                        bar.start(20)
                    progress_title.set('正在检测 / 恢复')
                    percent.set('检测中')
                else:
                    if str(bar['mode']) != 'determinate':
                        bar.stop()
                        bar.configure(mode='determinate')
                    bar['value'] = amount
                    progress_title.set('多站点验证已通过' if amount == 100 else '自动准备中')
                    percent.set('已通过' if amount == 100 else '%s%%' % amount)
                if amount < 100:
                    status.set(title)
                    detail.set(message)
                    set_badge('准备 / 恢复', WARNING)
                else:
                    set_badge('已通过验证', TEAL)
            elif kind == 'connection':
                title, message = values
                status.set(title)
                detail.set(message)
                if ('已验证' in title or 'VPN 路由已验证' in title) and '未完成' not in title:
                    set_badge('连接已验证', TEAL)
                elif '异常' in title or '未完成' in title:
                    set_badge('需要恢复', WARNING)
                else:
                    set_badge('自动连接中', WARNING)
            elif kind == 'item':
                name, value = values
                if name in engine_info:
                    engine_info[name][0].set(value)
                if name in diagnostics:
                    diagnostics[name][0].set(value)
                if name == '运行引擎':
                    metric_values['运行引擎'].set(value)
                elif name == '最近检查':
                    metric_values['最近检查'].set(value)
                elif name == '访问测试':
                    kind_value = value.split('：', 1)[0]
                    levels = {'VPN': 'VPN 已验证', 'PROXY': '代理已验证',
                              'PARTIAL': '部分可达', 'UNCONFIRMED': '归属未确认',
                              'DOWN': '暂不可用'}
                    metric_values['通道等级'].set(levels.get(kind_value, '正在检测'))
                elif name == '自适应':
                    found = re.search(r'历史验证\s*(\d+)\s*次', value)
                    if found:
                        metric_values['历史验证'].set(found.group(1) + ' 次')
        app.after(130, poll_ui)

    working_thread = [None]

    def close_app():
        if STOP.is_set():
            return
        STOP.set()
        bar.stop()
        status.set('正在安全关闭连接与恢复受管代理')
        detail.set('已停止发起新连接；正在等待现有任务完成清理。')
        set_badge('正在关闭', WARNING)
        def finish():
            thread = working_thread[0]
            recovering = managed_recovery_pending()
            if recovering:
                status.set('Windows 代理恢复尚未完成，正在自动重试')
                detail.set('为避免留下失效代理，当前转接暂时保留；恢复完成后自动关闭。')
            if (thread is None or not thread.is_alive()) and not recovering:
                app.destroy()
                return
            app.after(250, finish)
        finish()

    app.protocol('WM_DELETE_WINDOW', close_app)

    def check_dpi():
        if STOP.is_set():
            return
        if apply_dpi():
            layout_key[0] = None
            reflow()
            style.configure('Aether.Horizontal.TProgressbar', thickness=max(8, round(dpi[0] / 12)))
        app.after(1600, check_dpi)

    app.after(1700, check_dpi)
    try:
        validate_windows()
        data.mkdir(parents=True, exist_ok=True)
        if data.is_symlink() or not data.resolve().is_relative_to(selected_folder):
            raise RuntimeError('运行数据目录不得通过链接写入所选文件夹之外')
        for leftover in data.glob('proxy_guard.json.tmp.*'):
            try:
                if time.time() - leftover.stat().st_mtime > 1800:
                    safe_remove(leftover)
            except OSError:
                pass
        mutex = acquire_mutex()
    except (OSError, RuntimeError) as exc:
        status.set('无法启动自动连接')
        detail.set(str(exc))
        set_badge('启动失败', WARNING)
        diagnostics['连接状态'][0].set('后台监测未启动')
    else:
        app.after(60, poll_ui)
        working_thread[0] = threading.Thread(target=worker, args=(data,), daemon=False,
                                              name='AdaptiveNetworkEngine')
        working_thread[0].start()
    app.mainloop()
    if 'mutex' in locals():
        ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(mutex))

def proxy_flags(snapshot):
    if 'ConnectionFlags' in snapshot:
        return int(snapshot['ConnectionFlags'])
    return (1 | (2 if snapshot.get('ProxyEnable') else 0) |
            (4 if snapshot.get('AutoConfigURL') else 0) |
            (8 if snapshot.get('AutoDetect') else 0))

def proxy_with_flags(snapshot, flags):
    result = dict(snapshot)
    result['ConnectionFlags'] = int(flags)
    result['ProxyEnable'] = int(bool(flags & 2))
    result['AutoDetect'] = int(bool(flags & 8))
    return result

def proxy_snapshot_equal(first, second):
    if not valid_proxy_snapshot(first) or not valid_proxy_snapshot(second):
        return False
    return (proxy_flags(first) == proxy_flags(second) and all(
        (first.get(field) or '') == (second.get(field) or '')
        for field in ('ProxyServer', 'ProxyOverride', 'AutoConfigURL')))

def wininet_connection_options(snapshot=None):
    if sys.platform != 'win32':
        raise OSError('Windows Internet 配置接口不可用')

    class FileTime(ctypes.Structure):
        _fields_ = [('low', ctypes.c_uint32), ('high', ctypes.c_uint32)]

    class Value(ctypes.Union):
        _fields_ = [('number', ctypes.c_uint32), ('text', ctypes.c_void_p),
                    ('when', FileTime)]

    class Option(ctypes.Structure):
        _fields_ = [('option', ctypes.c_uint32), ('value', Value)]

    class OptionList(ctypes.Structure):
        _fields_ = [('size', ctypes.c_uint32), ('connection', ctypes.c_wchar_p),
                    ('count', ctypes.c_uint32), ('error', ctypes.c_uint32),
                    ('options', ctypes.POINTER(Option))]

    library = ctypes.WinDLL('wininet', use_last_error=True)
    query = library.InternetQueryOptionW
    query.argtypes = (ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
                      ctypes.POINTER(ctypes.c_uint32))
    query.restype = ctypes.c_int
    setter = library.InternetSetOptionW
    setter.argtypes = (ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32)
    setter.restype = ctypes.c_int
    release = ctypes.WinDLL('kernel32', use_last_error=True).GlobalFree
    release.argtypes = (ctypes.c_void_p,)
    release.restype = ctypes.c_void_p
    options = (Option * 4)()
    listing = OptionList(ctypes.sizeof(OptionList), None, 4, 0, options)
    if snapshot is not None:
        if not valid_proxy_snapshot(snapshot):
            raise ValueError('代理配置无效')
        buffers = [ctypes.create_unicode_buffer(snapshot.get(field) or '')
                   for field in ('ProxyServer', 'ProxyOverride', 'AutoConfigURL')]
        groups = ((2, 3, 4), (1,)) if proxy_flags(snapshot) & 2 else ((1,), (2, 3, 4))
        for group in groups:
            updates = (Option * len(group))()
            for index, number in enumerate(group):
                updates[index].option = number
                if number == 1:
                    updates[index].value.number = proxy_flags(snapshot)
                else:
                    updates[index].value.text = ctypes.cast(buffers[number - 2], ctypes.c_void_p).value
            listing.count = len(group)
            listing.options = updates
            if not setter(None, 75, ctypes.byref(listing), ctypes.sizeof(listing)):
                raise ctypes.WinError(ctypes.get_last_error())
        return True
    for flags_option in (10, 1):
        options[0].option = flags_option
        for index in range(1, 4):
            options[index].option = index + 1
            options[index].value.text = None
        size = ctypes.c_uint32(ctypes.sizeof(listing))
        try:
            if query(None, 75, ctypes.byref(listing), ctypes.byref(size)):
                result = {field: ctypes.wstring_at(options[index].value.text)
                          if options[index].value.text else ''
                          for index, field in enumerate(
                              ('ProxyServer', 'ProxyOverride', 'AutoConfigURL'), 1)}
                return proxy_with_flags(result, options[0].value.number)
            error = ctypes.get_last_error()
        finally:
            for index in range(1, 4):
                if options[index].value.text:
                    release(options[index].value.text)
                    options[index].value.text = None
    raise ctypes.WinError(error)

def proxy_map(snapshot):
    candidates = {}
    for entry in (snapshot.get('ProxyServer') or '').split(';'):
        if '=' in entry:
            name, value = entry.split('=', 1)
            name = name.strip().lower()
            if name not in ('http', 'https', 'socks'):
                continue
        else:
            name, value = 'all', entry
        found = re.fullmatch(r'(?:localhost|127\.0\.0\.1|\[::1\]):(\d{1,5})', value.strip(), re.I)
        if found and 0 < int(found.group(1)) < 65536:
            candidates[name] = int(found.group(1))
    return candidates

def proxy_server_is_local(snapshot):
    parts = [part.strip() for part in (snapshot.get('ProxyServer') or '').split(';') if part.strip()]
    if not parts:
        return False
    for part in parts:
        if '=' in part:
            name, address = part.split('=', 1)
            if name.strip().lower() not in ('http', 'https', 'socks'):
                return False
        else:
            address = part
        match = re.fullmatch(r'(?:localhost|127\.0\.0\.1|\[::1\]):(\d{1,5})', address.strip(), re.I)
        if match is None or not 0 < int(match.group(1)) < 65536:
            return False
    return True

def write_proxy_snapshot(expected, desired):
    if not proxy_snapshot_equal(proxy_registry_snapshot(), expected):
        return False
    try:
        wininet_connection_options(desired)
        notified = notify_proxy_change()
        return proxy_snapshot_equal(proxy_registry_snapshot(), desired) and notified
    except (OSError, AttributeError, TypeError, ValueError):
        return False

def proxy_restore_plan(baseline, observed, current):
    if not all(valid_proxy_snapshot(value) for value in (baseline, observed, current)):
        return None
    managed_address = (current.get('ProxyServer') or '') == (observed.get('ProxyServer') or '')
    partially_restored = ((current.get('ProxyServer') or '') == (baseline.get('ProxyServer') or '') and
                          proxy_flags(current) == proxy_flags(baseline))
    if not managed_address and not partially_restored:
        return dict(current)
    desired = dict(current)
    for field in ('ProxyServer', 'ProxyOverride', 'AutoConfigURL'):
        if (current.get(field) or '') == (observed.get(field) or ''):
            desired[field] = baseline.get(field) or ''
    before, ours, live = proxy_flags(baseline), proxy_flags(observed), proxy_flags(current)
    result = live
    for bit in (1, 2, 4, 8):
        if bit == 4 and (current.get('AutoConfigURL') or '') != (observed.get('AutoConfigURL') or ''):
            continue
        if (before & bit) != (ours & bit) and (live & bit) == (ours & bit):
            result = (result & ~bit) | (before & bit)
    return proxy_with_flags(desired, result)

def proxy_still_managed(baseline, observed, current):
    if not all(valid_proxy_snapshot(value) for value in (baseline, observed, current)):
        return True
    return (bool(proxy_flags(current) & 2) and
            (current.get('ProxyServer') or '') == (observed.get('ProxyServer') or '') and
            (not (proxy_flags(baseline) & 2) or
             (baseline.get('ProxyServer') or '') != (observed.get('ProxyServer') or '')))

class ProxyGuardLock:
    def __init__(self, path):
        self.path = path
        self.handle = None

    def __enter__(self):
        if sys.platform != 'win32':
            PROXY_GUARD_LOCK.acquire()
            return self
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateMutexW.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p)
        kernel.CreateMutexW.restype = ctypes.c_void_p
        kernel.WaitForSingleObject.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
        kernel.WaitForSingleObject.restype = ctypes.c_uint32
        name = hashlib.sha256(str(self.path.resolve()).casefold().encode('utf-8')).hexdigest()[:24]
        self.handle = kernel.CreateMutexW(None, False, 'Local\\AetherProxyGuard_' + name)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        if kernel.WaitForSingleObject(self.handle, 2500) not in (0, 128):
            close_windows_handle(self.handle)
            self.handle = None
            raise OSError('代理恢复记录正在更新')
        return self

    def __exit__(self, *unused):
        if sys.platform != 'win32':
            PROXY_GUARD_LOCK.release()
        elif self.handle:
            release = ctypes.WinDLL('kernel32', use_last_error=True).ReleaseMutex
            release.argtypes = (ctypes.c_void_p,)
            release.restype = ctypes.c_int
            release(self.handle)
            close_windows_handle(self.handle)

def close_windows_handle(handle):
    if handle:
        function = ctypes.WinDLL('kernel32', use_last_error=True).CloseHandle
        function.argtypes = (ctypes.c_void_p,)
        function.restype = ctypes.c_int
        function(handle)

def write_proxy_guard_record(path, record):
    payload = json.dumps(record, ensure_ascii=False, separators=(',', ':'))
    if len(payload.encode('utf-8')) > 65536:
        return False
    temporary = path.with_name(path.name + '.tmp.%s.%s' % (os.getpid(), threading.get_ident()))
    try:
        with temporary.open('w', encoding='utf-8') as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        return True
    except (OSError, ValueError, TypeError):
        safe_remove(temporary)
        return False

def process_birth_time(pid):
    if sys.platform != 'win32' or type(pid) is not int or not 0 < pid <= 0xffffffff:
        return None
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = (ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32)
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.GetProcessTimes.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.c_void_p, ctypes.c_void_p)
    kernel.GetProcessTimes.restype = ctypes.c_int
    kernel.WaitForSingleObject.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
    kernel.WaitForSingleObject.restype = ctypes.c_uint32
    handle = kernel.OpenProcess(0x00101000, False, pid)
    if not handle:
        return None
    try:
        if kernel.WaitForSingleObject(handle, 0) != 258:
            return None
        values = [ctypes.c_uint64() for unused in range(4)]
        if kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in values)):
            return values[0].value
        return None
    finally:
        close_windows_handle(handle)

def bind_proxy_guard_process(path, proc, client):
    try:
        birth = process_birth_handle(int(proc._handle))
        if birth is None:
            return False
        with ProxyGuardLock(path):
            record = read_json_bounded(path, 65536)
            if not (valid_armed_proxy_guard(record) or valid_proxy_guard(record)):
                return False
            record['process'] = {'pid': proc.pid, 'created': birth}
            record['program'] = str(client.resolve())
            record['owner_parent'] = os.getpid()
            return write_proxy_guard_record(path, record)
    except (OSError, ValueError, TypeError, KeyError):
        return False

def process_birth_handle(handle):
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetProcessTimes.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.c_void_p, ctypes.c_void_p)
    kernel.GetProcessTimes.restype = ctypes.c_int
    values = [ctypes.c_uint64() for unused in range(4)]
    if kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in values)):
        return values[0].value
    return None

def guarded_process_alive(record):
    identity = record.get('process')
    if not isinstance(identity, dict) or not isinstance(record.get('program'), str):
        return False
    pid, created = identity.get('pid'), identity.get('created')
    if type(pid) is not int or type(created) is not int or created <= 0:
        return False
    return (process_birth_time(pid) == created and
            same_executable(pid, pathlib.Path(record['program'])))

def create_managed_job():
    class BasicLimits(ctypes.Structure):
        _fields_ = [('process_time', ctypes.c_int64), ('job_time', ctypes.c_int64),
                    ('flags', ctypes.c_uint32), ('minimum', ctypes.c_size_t),
                    ('maximum', ctypes.c_size_t), ('count', ctypes.c_uint32),
                    ('affinity', ctypes.c_size_t), ('priority', ctypes.c_uint32),
                    ('scheduling', ctypes.c_uint32)]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [('basic', BasicLimits), ('io', ctypes.c_uint64 * 6),
                    ('process_memory', ctypes.c_size_t), ('job_memory', ctypes.c_size_t),
                    ('peak_process', ctypes.c_size_t), ('peak_job', ctypes.c_size_t)]

    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateJobObjectW.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p)
    kernel.CreateJobObjectW.restype = ctypes.c_void_p
    kernel.SetInformationJobObject.argtypes = (ctypes.c_void_p, ctypes.c_int,
                                             ctypes.c_void_p, ctypes.c_uint32)
    kernel.SetInformationJobObject.restype = ctypes.c_int
    handle = kernel.CreateJobObjectW(None, None)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    limits = ExtendedLimits()
    limits.basic.flags = 0x2000
    if not kernel.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
        error = ctypes.get_last_error()
        close_windows_handle(handle)
        raise ctypes.WinError(error)
    return handle

def attach_managed_job(job, proc):
    function = ctypes.WinDLL('kernel32', use_last_error=True).AssignProcessToJobObject
    function.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    function.restype = ctypes.c_int
    if not function(job, int(proc._handle)):
        raise ctypes.WinError(ctypes.get_last_error())

def terminate_guarded_process(record):
    if not guarded_process_alive(record):
        return
    identity = record['process']
    request_graceful_close(identity['pid'])
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and guarded_process_alive(record):
        time.sleep(0.1)
    if not guarded_process_alive(record):
        return
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = (ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32)
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.GetProcessTimes.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.c_void_p, ctypes.c_void_p)
    kernel.GetProcessTimes.restype = ctypes.c_int
    kernel.TerminateProcess.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
    kernel.TerminateProcess.restype = ctypes.c_int
    handle = kernel.OpenProcess(0x1001, False, identity['pid'])
    if handle:
        try:
            values = [ctypes.c_uint64() for unused in range(4)]
            if (kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in values)) and
                    values[0].value == identity['created']):
                kernel.TerminateProcess(handle, 1)
        finally:
            close_windows_handle(handle)

def windows_system_probe(url):
    if sys.platform != 'win32' or url not in {entry[0] for entry in TARGETS}:
        return {'passed': False}
    library = ctypes.WinDLL('wininet', use_last_error=True)
    library.InternetOpenW.argtypes = (ctypes.c_wchar_p, ctypes.c_uint32,
                                     ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32)
    library.InternetOpenW.restype = ctypes.c_void_p
    library.InternetSetOptionW.argtypes = (ctypes.c_void_p, ctypes.c_uint32,
                                         ctypes.c_void_p, ctypes.c_uint32)
    library.InternetSetOptionW.restype = ctypes.c_int
    library.InternetOpenUrlW.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p,
                                       ctypes.c_wchar_p, ctypes.c_uint32,
                                       ctypes.c_uint32, ctypes.c_size_t)
    library.InternetOpenUrlW.restype = ctypes.c_void_p
    library.HttpQueryInfoW.argtypes = (ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
                                      ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p)
    library.HttpQueryInfoW.restype = ctypes.c_int
    library.InternetReadFile.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                                        ctypes.POINTER(ctypes.c_uint32))
    library.InternetReadFile.restype = ctypes.c_int
    library.InternetCloseHandle.argtypes = (ctypes.c_void_p,)
    library.InternetCloseHandle.restype = ctypes.c_int
    root = library.InternetOpenW('AetherSystemProbe/1.0', 0, None, None, 0)
    if not root:
        return {'passed': False}
    request = None
    try:
        timeout = ctypes.c_uint32(6000)
        for option in (2, 5, 6):
            if not library.InternetSetOptionW(root, option, ctypes.byref(timeout), ctypes.sizeof(timeout)):
                return {'passed': False}
        request = library.InternetOpenUrlW(root, url, None, 0,
                                          0x80000000 | 0x04000000 | 0x00000200, 0)
        if not request:
            return {'passed': False}
        status = ctypes.c_uint32()
        size = ctypes.c_uint32(ctypes.sizeof(status))
        if not library.HttpQueryInfoW(request, 19 | 0x20000000, ctypes.byref(status),
                                      ctypes.byref(size), None):
            return {'passed': False}
        expected = next(value[1] for value in TARGETS if value[0] == url)
        accepted = status.value == expected if expected is not None else 200 <= status.value < 400
        buffer = ctypes.create_string_buffer(128)
        size = ctypes.c_uint32()
        read = library.InternetReadFile(request, buffer, 128, ctypes.byref(size))
        return {'passed': bool(accepted and read), 'status': status.value}
    finally:
        if request:
            library.InternetCloseHandle(request)
        library.InternetCloseHandle(root)

def stop_probe_process(proc):
    if proc.poll() is None:
        try:
            proc.kill()
        except OSError:
            pass
    try:
        proc.communicate(timeout=1)
    except (OSError, subprocess.TimeoutExpired):
        pass

def probe_windows_default(timeout=18):
    jobs = []
    passed = 0
    deadline = time.monotonic() + timeout
    try:
        for url, expected, level in TARGETS:
            if level != '受限服务' or STOP.is_set():
                continue
            process = subprocess.Popen(
                [sys.executable, str(pathlib.Path(__file__).resolve()), '--system-probe', url],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            jobs.append(process)
        pending = list(jobs)
        while pending and not STOP.is_set() and time.monotonic() < deadline:
            for process in list(pending):
                if process.poll() is None:
                    continue
                pending.remove(process)
                output, unused = process.communicate(timeout=0.5)
                if process.returncode == 0 and len(output) <= 4096:
                    try:
                        passed += int(json.loads(output.decode('utf-8')).get('passed') is True)
                    except (ValueError, TypeError, AttributeError, UnicodeError):
                        pass
                if passed >= 2:
                    return True
            STOP.wait(min(0.08, max(0, deadline - time.monotonic())))
        return False
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return False
    finally:
        for process in jobs:
            stop_probe_process(process)

def verify_windows_proxy(session, force=False):
    cache = session.get('system_probe')
    if cache and not force and time.monotonic() - cache[0] < (65 if cache[1] else 12):
        return cache[1]
    passed = probe_windows_default()
    session['system_probe'] = (time.monotonic(), passed)
    return passed

def launch_owned_process(session, args, on_started=None, **options):
    job = create_managed_job()
    process = None
    try:
        options['creationflags'] = options.get('creationflags', 0) | 0x00000004
        process = subprocess.Popen(args, **options)
        attach_managed_job(job, process)
        if on_started is not None and on_started(process) is False:
            raise RuntimeError('无法持久化受管进程身份，已停止本次启动')
        resume_owned_process(process)
    except Exception:
        if process is not None:
            try:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                pass
        close_windows_handle(job)
        raise
    session.update(proc=process, owned=True, job=job)
    return process

def remove_session_guard(path, session):
    try:
        with ProxyGuardLock(path):
            if not path.is_file():
                return
            record = read_json_bounded(path, 65536)
            if (proxy_snapshot_equal(record.get('baseline'), session.get('baseline')) and
                    proxy_snapshot_equal(record.get('observed'), session.get('observed'))):
                safe_remove(path)
    except (OSError, ValueError, TypeError, KeyError):
        pass

def deferred_proxy_cleanup(session, guard_path, exiting):
    try:
        while True:
            try:
                restored = restore_managed_proxy(session['baseline'], session['observed'])
            except (OSError, ValueError, TypeError, RuntimeError):
                restored = False
            if restored:
                remove_session_guard(guard_path, session)
                session['observed'] = None
                session['deferred_cleanup'] = False
                cleanup_session(session, guard_path, exiting)
                return
            time.sleep(2)
    finally:
        with PROXY_RECOVERY_LOCK:
            PROXY_RECOVERY_THREADS.discard(threading.current_thread())

def managed_recovery_pending():
    with PROXY_RECOVERY_LOCK:
        return any(thread.is_alive() for thread in PROXY_RECOVERY_THREADS)

def valid_guard_metadata(value):
    parent = value.get('owner_parent')
    if parent is not None and (type(parent) is not int or not 0 < parent <= 0xffffffff):
        return False
    for field in ('trusted_launch', 'unresolved'):
        if field in value and type(value[field]) is not bool:
            return False
    program = value.get('program')
    if program is not None and (not isinstance(program, str) or not 0 < len(program) <= 32768 or
                                '\x00' in program or not pathlib.Path(program).is_absolute()):
        return False
    identity = value.get('process')
    if identity is not None:
        if not isinstance(identity, dict) or program is None:
            return False
        pid, created = identity.get('pid'), identity.get('created')
        if (type(pid) is not int or not 0 < pid <= 0xffffffff or
                type(created) is not int or not 0 < created <= 0xffffffffffffffff):
            return False
    kinds = value.get('baseline_types', {})
    return isinstance(kinds, dict) and all(valid_proxy_type(name, kind) for name, kind in kinds.items())

def resume_owned_process(proc):
    class ThreadEntry(ctypes.Structure):
        _fields_ = [('size', ctypes.c_uint32), ('usage', ctypes.c_uint32),
                    ('thread', ctypes.c_uint32), ('owner', ctypes.c_uint32),
                    ('priority', ctypes.c_int32), ('delta', ctypes.c_int32),
                    ('flags', ctypes.c_uint32)]

    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateToolhelp32Snapshot.argtypes = (ctypes.c_uint32, ctypes.c_uint32)
    kernel.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    kernel.Thread32First.argtypes = (ctypes.c_void_p, ctypes.POINTER(ThreadEntry))
    kernel.Thread32First.restype = ctypes.c_int
    kernel.Thread32Next.argtypes = (ctypes.c_void_p, ctypes.POINTER(ThreadEntry))
    kernel.Thread32Next.restype = ctypes.c_int
    kernel.OpenThread.argtypes = (ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32)
    kernel.OpenThread.restype = ctypes.c_void_p
    kernel.ResumeThread.argtypes = (ctypes.c_void_p,)
    kernel.ResumeThread.restype = ctypes.c_uint32
    handle = kernel.CreateToolhelp32Snapshot(4, 0)
    if handle in (None, ctypes.c_void_p(-1).value):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        entry = ThreadEntry()
        entry.size = ctypes.sizeof(entry)
        available = kernel.Thread32First(handle, ctypes.byref(entry))
        while available:
            if entry.owner == proc.pid:
                thread = kernel.OpenThread(2, False, entry.thread)
                if not thread:
                    raise ctypes.WinError(ctypes.get_last_error())
                try:
                    if kernel.ResumeThread(thread) == 0xffffffff:
                        raise ctypes.WinError(ctypes.get_last_error())
                    return
                finally:
                    close_windows_handle(thread)
            entry.size = ctypes.sizeof(entry)
            available = kernel.Thread32Next(handle, ctypes.byref(entry))
        raise OSError('未找到受管进程的挂起主线程')
    finally:
        close_windows_handle(handle)

def _download_payload(settings):
    kind = settings['kind']
    path = pathlib.Path(settings['target'])
    maximum = settings['maximum']
    request = urllib.request.Request(settings['url'], headers={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
    started = time.monotonic()
    downloaded = 0
    digest = hashlib.sha256()
    try:
        with open_download(request, timeout=min(9, settings['time_limit']),
                           use_proxy=settings['use_proxy']) as response:
            final = urllib.parse.urlsplit(response.geturl())
            if final.scheme.lower() != 'https':
                raise ValueError('下载重定向离开 HTTPS')
            if kind == 'tor' and final.hostname not in (
                    'dist.torproject.org', 'archive.torproject.org', 'tor.eff.org'):
                raise ValueError('Tor 下载未停留在已核实的 HTTPS 分发域名')
            if kind == 'bridges' and final.hostname != 'gitlab.torproject.org':
                raise ValueError('官方配置跳转到了不可信域名')
            size_header = response.headers.get('Content-Length', '')
            length = int(size_header) if size_header else 0
            if length < 0 or length > maximum:
                raise ValueError('文件大小超过安全限制')
            with path.open('wb') as target:
                while not STOP.is_set():
                    if time.monotonic() - started >= settings['time_limit']:
                        raise TimeoutError('下载超过总时间限制')
                    chunk = response.read(131072)
                    if not chunk:
                        break
                    downloaded += len(chunk)
                    if downloaded > maximum:
                        raise ValueError('文件大小超过安全限制')
                    digest.update(chunk)
                    target.write(chunk)
            if STOP.is_set():
                raise InterruptedError('已停止')
            if length and downloaded != length:
                raise ValueError('下载内容不完整')
            if kind == 'psiphon':
                if downloaded < 100000:
                    raise ValueError('文件过小，无法确认为客户端')
                with path.open('rb') as file:
                    if file.read(2) != b'MZ':
                        raise ValueError('文件不是 Windows 可执行程序')
            elif kind == 'tor':
                if not downloaded or digest.hexdigest() != settings['sha256'].lower():
                    raise ValueError('Tor 官方版本固定 SHA-256 校验不匹配')
            elif not downloaded:
                raise ValueError('官方下载内容为空')
            return {'received': downloaded, 'elapsed': time.monotonic() - started}
    except Exception:
        safe_remove(path)
        raise

def _download_error(exc):
    if isinstance(exc, InterruptedError):
        return {'ok': False, 'error': 'cancelled', 'message': '已停止'}
    if isinstance(exc, TimeoutError):
        return {'ok': False, 'error': 'timeout', 'message': '下载超过总时间限制'}
    if isinstance(exc, ValueError):
        allowed = {'下载重定向离开 HTTPS', 'Tor 下载未停留在已核实的 HTTPS 分发域名',
                   '官方配置跳转到了不可信域名', '文件大小超过安全限制', '下载内容不完整',
                   '文件过小，无法确认为客户端', '文件不是 Windows 可执行程序',
                   'Tor 官方版本固定 SHA-256 校验不匹配', '官方下载内容为空'}
        message = str(exc)
        return {'ok': False, 'error': 'validation',
                'message': message if message in allowed else '下载内容不符合校验要求'}
    return {'ok': False, 'error': 'io', 'message': '官方资源下载或保存失败'}

def _valid_download_settings(settings):
    if not isinstance(settings, dict) or settings.get('kind') not in ('psiphon', 'tor', 'bridges'):
        return False
    if type(settings.get('use_proxy')) is not bool:
        return False
    maximum = settings.get('maximum')
    limit = settings.get('time_limit')
    if type(maximum) is not int or not 0 < maximum <= MAX_DOWNLOAD:
        return False
    if type(limit) not in (int, float) or not math.isfinite(limit) or not 0 < limit <= 120:
        return False
    if not isinstance(settings.get('target'), str) or not settings['target']:
        return False
    if not isinstance(settings.get('url'), str) or len(settings['url']) > 4096:
        return False
    try:
        url = urllib.parse.urlsplit(settings['url'])
        if url.scheme.lower() != 'https' or not url.hostname or url.username or url.password:
            return False
    except ValueError:
        return False
    if settings['kind'] == 'tor':
        expected = settings.get('sha256')
        if not isinstance(expected, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', expected):
            return False
    return True

def download_worker(request_path, result_path):
    timer = threading.Timer(125, lambda: os._exit(124))
    timer.daemon = True
    timer.start()
    try:
        settings = read_json_bounded(request_path, 16384)
        if not _valid_download_settings(settings):
            raise ValueError('下载任务无效')
        timer.cancel()
        timer = threading.Timer(settings['time_limit'], lambda: os._exit(124))
        timer.daemon = True
        timer.start()
        result = {'ok': True, **_download_payload(settings)}
    except Exception as exc:
        result = _download_error(exc)
    try:
        temporary = result_path.with_name(result_path.name + '.tmp')
        with temporary.open('w', encoding='utf-8') as output:
            json.dump(result, output, ensure_ascii=False, separators=(',', ':'))
        os.replace(temporary, result_path)
    finally:
        timer.cancel()

def _stop_download_process(proc):
    if proc is None or proc.poll() is not None:
        return True
    try:
        proc.kill()
    except OSError:
        pass
    try:
        proc.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        return proc.poll() is not None
    return True

def _run_download_job(kind, url, target, use_proxy, maximum, time_limit,
                      expected_sha256='', cancel=None):
    target = pathlib.Path(target)
    settings = {'kind': kind, 'url': url, 'target': str(target.absolute()),
                'use_proxy': use_proxy, 'maximum': maximum,
                'time_limit': time_limit, 'sha256': expected_sha256}
    if not _valid_download_settings(settings):
        raise ValueError('下载任务无效')
    started = time.monotonic()
    deadline = started + time_limit
    proc = None
    directory = None
    completed = False
    last_report = 0
    try:
        if STOP.is_set() or (cancel is not None and cancel.is_set()):
            raise InterruptedError('已停止')
        safe_remove(target)
        directory = pathlib.Path(tempfile.mkdtemp(prefix='download-job-', dir=str(target.parent)))
        request_path = directory / 'request.json'
        result_path = directory / 'result.json'
        request_path.write_text(json.dumps(settings, ensure_ascii=False), encoding='utf-8')
        if STOP.is_set() or (cancel is not None and cancel.is_set()):
            raise InterruptedError('已停止')
        if time.monotonic() >= deadline:
            raise TimeoutError('下载超过总时间限制')
        proc = subprocess.Popen(
            [sys.executable, '-I', '-B', str(pathlib.Path(__file__).resolve()),
             '--download-worker', str(request_path.absolute()), str(result_path.absolute())],
            cwd=str(target.parent.absolute()), stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        while True:
            if STOP.is_set() or (cancel is not None and cancel.is_set()):
                raise InterruptedError('已停止')
            now = time.monotonic()
            if now >= deadline:
                raise TimeoutError('下载超过总时间限制')
            result_code = proc.poll()
            if result_code is not None:
                if result_code == 124:
                    raise TimeoutError('下载超过总时间限制')
                if result_code != 0:
                    raise OSError('官方资源下载进程提前退出')
                result = read_json_bounded(result_path, 4096)
                if not isinstance(result, dict):
                    raise ValueError('下载结果无效')
                if result.get('ok') is not True:
                    errors = {'cancelled': InterruptedError, 'timeout': TimeoutError,
                              'validation': ValueError, 'io': OSError}
                    exception = errors.get(result.get('error'), OSError)
                    message = result.get('message')
                    if not isinstance(message, str) or len(message) > 80:
                        message = '官方资源下载失败'
                    raise exception(message)
                received = result.get('received')
                if type(received) is not int or not 0 < received <= maximum:
                    raise ValueError('下载结果无效')
                if target.stat().st_size != received:
                    raise ValueError('下载内容不完整')
                completed = True
                return {'received': received, 'elapsed': time.monotonic() - started}
            if now - last_report >= 0.5 and kind != 'bridges':
                last_report = now
                try:
                    received = target.stat().st_size
                except OSError:
                    received = 0
                if kind == 'psiphon':
                    stage(18, '正在下载官方 Psiphon', '已接收 %s KiB' % (received // 1024))
                else:
                    item('下载', 'Tor 官方 Expert Bundle：%s MiB' % (received // 1048576))
            STOP.wait(min(0.05, max(0, deadline - time.monotonic())))
    finally:
        if not _stop_download_process(proc):
            diagnostic('下载子进程未及时退出，独立超时保护仍生效')
        if not completed:
            safe_remove(target)
        if directory is not None:
            shutil.rmtree(directory, ignore_errors=True)

def network_signature_from_routes(value):
    if not isinstance(value, dict) or not isinstance(value.get('routes'), list):
        return None
    records = []
    for row in value['routes'][:128]:
        if not isinstance(row, dict):
            continue
        if row.get('up') != 1 or row.get('type') in (23, 24, 131):
            continue
        description = str(row.get('description', '')).casefold()
        name = str(row.get('name', '')).casefold()
        if 'psiphon' in description or 'psiphon' in name:
            continue
        guid = str(row.get('guid', '')).strip('{}').casefold()
        if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', guid):
            continue
        try:
            gateway = ipaddress.ip_address(str(row.get('gateway', '')).split('%', 1)[0])
        except ValueError:
            continue
        if gateway.is_unspecified or gateway.is_loopback or gateway.is_multicast:
            continue
        networks = row.get('network')
        if isinstance(networks, str):
            networks = [networks]
        if not isinstance(networks, list):
            continue
        networks = tuple(sorted({name for name in networks[:8]
                                 if isinstance(name, str) and 0 < len(name) <= 512
                                 and '\x00' not in name}))
        if not networks:
            continue
        metric = nonnegative(row.get('metric'), 4294967295)
        records.append((row.get('hardware') is True, gateway.version,
                        metric, guid, str(gateway), networks))
    if not records:
        return None
    physical = [entry for entry in records if entry[0]]
    candidates = physical or records
    selected = []
    for family in (4, 6):
        routes = [entry for entry in candidates if entry[1] == family]
        if routes:
            best = min(routes, key=lambda entry: (entry[2], entry[3], entry[4], entry[5]))
            selected.append((family, best[3], best[4], best[5]))
    payload = json.dumps(selected, ensure_ascii=True, separators=(',', ':')).encode('ascii')
    return hashlib.sha256(payload).digest()

def record_preparation_failure(state, name, error):
    record = state.setdefault('preparations', {}).setdefault(
        name, {'failures': 0, 'failure_streak': 0, 'updated': 0,
               'cooldown': 0, 'error': ''})
    streak = min(int(nonnegative(record.get('failure_streak'))) + 1, 20)
    record['failures'] = min(int(nonnegative(record.get('failures'))) + 1, 1000000)
    record['failure_streak'] = streak
    record['updated'] = time.time()
    record['cooldown'] = record['updated'] + min(
        PREPARATION_COOLDOWN_MAX, PREPARATION_COOLDOWN * 2 ** min(streak - 1, 6))
    record['error'] = re.sub(r'[\r\n\t]', ' ', str(error))[:160]

def clear_preparation_failure(state, name):
    record = state.get('preparations', {}).get(name)
    if record is not None:
        record['failure_streak'] = 0
        record['cooldown'] = 0
        record['error'] = ''

def startup_expired(session, since, now):
    if session['name'] != 'Tor':
        return now - since >= ENGINE_START_WINDOW
    progress_at = nonnegative(session.get('tor_progress_at'), since)
    progress_at = max(since, min(now, progress_at))
    return (now - since >= TOR_START_MAX_WINDOW
            or now - progress_at >= TOR_START_WINDOW)

def diverse_download_routes(routes):
    first, deferred, domains = [], [], set()
    for route in routes:
        host = (urllib.parse.urlsplit(route[0]).hostname or '').casefold()
        host = host[4:] if host.startswith('www.') else host
        if host in domains:
            deferred.append(route)
        else:
            domains.add(host)
            first.append(route)
    return first + deferred

def start_tor_preparation(data, state=None, refresh=False):
    if STOP.is_set():
        return None
    key = str(data.resolve())
    with TOR_PREPARATION_LOCK:
        previous = TOR_PREPARATIONS.get(key)
        if previous is not None:
            if (not previous['done'].is_set() or
                    (previous['error'] is None and
                     (not refresh or time.monotonic() - previous['checked_at'] <= 15))):
                return previous
            if previous['error'] is not None and time.monotonic() < previous['retry_at']:
                return previous
        preparation = (state or {}).get('preparations', {}).get('Tor', {})
        if nonnegative(preparation.get('cooldown')) > time.time():
            return previous
        record = {'done': threading.Event(), 'result': None, 'error': None,
                  'checked_at': 0.0, 'retry_at': 0.0, 'thread': None}
        TOR_PREPARATIONS[key] = record

        def prepare():
            try:
                record['result'] = trusted_tor_files(data)
                record['checked_at'] = time.monotonic()
                item('Tor', '可信备用组件已就绪，等待需要时启动')
            except Exception as exc:
                record['error'] = exc
                record['retry_at'] = time.monotonic() + 60
                if not STOP.is_set():
                    diagnostic('备用组件准备暂不可用：' + type(exc).__name__)
            finally:
                record['done'].set()

        thread = threading.Thread(target=prepare, name='TorAssetPreparation', daemon=True)
        record['thread'] = thread
        try:
            thread.start()
        except RuntimeError as exc:
            record['error'] = exc
            record['retry_at'] = time.monotonic() + 60
            record['done'].set()
        return record

def prepared_tor_files(data):
    record = start_tor_preparation(data, refresh=True)
    if record is None:
        raise InterruptedError('已停止')
    while not record['done'].wait(0.2):
        if STOP.is_set():
            raise InterruptedError('已停止')
    if STOP.is_set():
        raise InterruptedError('已停止')
    if record['error'] is not None:
        raise record['error']
    return record['result']

def finish_tor_preparations():
    with TOR_PREPARATION_LOCK:
        threads = [record['thread'] for record in TOR_PREPARATIONS.values()
                   if record['thread'] is not None]
    deadline = time.monotonic() + 3
    for thread in threads:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        if thread.is_alive():
            thread.join(timeout=remaining)


def entrypoint():
    if len(sys.argv) == 1:
        main()
        return 0
    if sys.argv[1] == '--download-worker' and len(sys.argv) == 4:
        download_worker(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]))
        return 0
    if sys.argv[1] == '--system-probe' and len(sys.argv) == 3:
        timer = threading.Timer(30, lambda: os._exit(124))
        timer.daemon = True
        timer.start()
        try:
            result = windows_system_probe(sys.argv[2])
        except Exception:
            result = {'passed': False}
        try:
            print(json.dumps(result, separators=(',', ':')))
        finally:
            timer.cancel()
        return 0
    if sys.argv[1] == '--proxy-watchdog' and len(sys.argv) == 5:
        try:
            proxy_watchdog(pathlib.Path(sys.argv[2]), int(sys.argv[3]), pathlib.Path(sys.argv[4]))
        except (OSError, ValueError, TypeError):
            return 1
        return 0
    return 2


if __name__ == '__main__':
    sys.exit(entrypoint())
