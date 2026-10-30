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
import tkinter as tk
import urllib.error
import urllib.parse
import urllib.request
from tkinter import filedialog, ttk

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
ENGINE_ORDER = ('Geph', 'Proton VPN', 'nthLink', 'Lantern', 'Psiphon', 'Tor')
ENGINE_COOLDOWN = 150
ENGINE_START_WINDOW = 110
TOR_START_WINDOW = 210
ENGINE_OUTAGE_WINDOW = 155
TOR_VERSION = '15.0.26'
TOR_SHA256 = 'c1988c701de2f24f7d098d1d6d7f507b58f27740d097f29c246e0524d639b252'
TOR_PORT = 19050
TOR_PORT_CANDIDATES = 12
PROXY_GUARD_TTL = 30 * 86400
TOR_ARCHIVE_URL = ('https://dist.torproject.org/torbrowser/' + TOR_VERSION +
                   '/tor-expert-bundle-windows-x86_64-' + TOR_VERSION + '.tar.gz')
TOR_SNOWFLAKE = ('snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 '
                 'fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 '
                 'url=https://1098762253.rsc.cdn77.org front=www.phpmyadmin.net,cdn.zk.mk '
                 'ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,'
                 'stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,'
                 'stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:3478,'
                 'stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443 '
                 'utls-imitate=hellorandomizedalpn')
KNOWN_EXES = {
    'Geph': ('geph5.exe',),
    'Proton VPN': ('ProtonVPN.Launcher.exe', 'ProtonVPN.Client.exe', 'ProtonVPN.exe', 'Proton VPN.exe'),
    'nthLink': ('nthLink.exe', 'nthlink.exe'),
    'Lantern': ('Lantern.exe', 'lantern.exe'),
}
SIGNER_TOKENS = {
    'Geph': ('geph',),
    'Proton VPN': ('proton ag',),
    'nthLink': ('nthlink',),
    'Lantern': ('lantern', 'innovate labs'),
}
LOG_QUEUE = collections.deque(maxlen=350)
LOG_LOCK = threading.Lock()
SIGNER_CACHE = {}
DISCOVERY_CACHE = {}
MESSAGES = queue.Queue()
STOP = threading.Event()


def send(kind, *values):
    if not STOP.is_set():
        MESSAGES.put((kind, values))


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


def load_state(path):
    try:
        obj = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(obj, dict):
            raise ValueError('状态格式不正确')
        records = obj.get('routes', {})
        if not isinstance(records, dict):
            records = {}
        routes = {}
        for key, value in records.items():
            if not isinstance(key, str) or not isinstance(value, dict) or len(key) > 350:
                continue
            tries = min(int(nonnegative(value.get('tries'))), 1000000)
            wins = min(int(nonnegative(value.get('wins'))), tries)
            speed = min(nonnegative(value.get('speed')), 100000000)
            updated = min(nonnegative(value.get('updated')), time.time() + 86400)
            error = value.get('error', '')
            routes[key] = {'tries': tries, 'wins': wins, 'speed': speed,
                           'updated': updated, 'error': error if isinstance(error, str) and len(error) < 40 else ''}
        channels = {}
        raw_channels = obj.get('channels', {})
        if isinstance(raw_channels, dict):
            for name in ('HTTP', 'SOCKS5', 'VPN'):
                value = raw_channels.get(name)
                if not isinstance(value, dict):
                    continue
                tries = min(int(nonnegative(value.get('tries'))), 1000000)
                channels[name] = {
                    'tries': tries,
                    'wins': min(int(nonnegative(value.get('wins'))), tries),
                    'latency': min(nonnegative(value.get('latency')), 60),
                    'updated': min(nonnegative(value.get('updated')), time.time() + 86400)
                }
        engines = {}
        raw_engines = obj.get('engines', {})
        if isinstance(raw_engines, dict):
            for name in ENGINE_ORDER:
                value = raw_engines.get(name)
                if not isinstance(value, dict):
                    continue
                tries = min(int(nonnegative(value.get('tries'))), 1000000)
                engines[name] = {'tries': tries, 'wins': min(int(nonnegative(value.get('wins'))), tries),
                                 'latency': min(nonnegative(value.get('latency')), 60),
                                 'updated': min(nonnegative(value.get('updated')), time.time() + 86400),
                                 'cooldown': min(nonnegative(value.get('cooldown')), time.time() + 86400)}
        bridges = {}
        if isinstance(obj.get('bridge_stats'), dict):
            for name in ('obfs4', 'snowflake', 'webtunnel', 'meek_lite', 'direct'):
                value = obj['bridge_stats'].get(name)
                if isinstance(value, dict):
                    tries = min(int(nonnegative(value.get('tries'))), 1000000)
                    bridges[name] = {'tries': tries,
                                     'wins': min(int(nonnegative(value.get('wins'))), tries),
                                     'updated': min(nonnegative(value.get('updated')), time.time() + 86400)}
        return {'version': 4, 'routes': routes, 'channels': channels, 'engines': engines,
                'bridge_stats': bridges,
                'connections': min(int(nonnegative(obj.get('connections'))), 1000000)}
    except (OSError, ValueError, TypeError, OverflowError):
        return {'version': 4, 'routes': {}, 'channels': {}, 'engines': {}, 'bridge_stats': {}, 'connections': 0}


def save_state(path, obj):
    temp = path.with_name(path.name + '.tmp')
    try:
        temp.write_text(json.dumps(obj, ensure_ascii=False, separators=(',', ':')), encoding='utf-8')
        os.replace(temp, path)
        return True
    except OSError:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
        item('存储', '状态保存失败；当前连接仍可继续')
        return False


def route_key(url, use_proxy):
    return url + ('|系统代理' if use_proxy else '|直接连接')


def ranked_routes(state):
    try:
        proxies = urllib.request.getproxies()
    except (OSError, ValueError):
        proxies = {}
    configured_proxy = bool(proxies.get('https'))
    modes = (True, False) if configured_proxy else (False,)
    routes = [(url, mode) for url in SOURCES for mode in modes]
    records = state['routes']
    current = time.time()

    def effective(route):
        value = records.get(route_key(*route), {})
        age = max(0, current - nonnegative(value.get('updated')))
        factor = 0.5 ** (age / ROUTE_HISTORY_HALFLIFE) if value.get('updated') else 0.5
        return (nonnegative(value.get('tries')) * factor,
                nonnegative(value.get('wins')) * factor,
                nonnegative(value.get('speed')) * factor)

    total = sum(effective(route)[0] for route in routes)

    def score(route):
        tries, wins, speed = effective(route)
        quality = (wins + 1) / (tries + 2)
        exploration = 0.23 * math.sqrt(math.log(total + 2) / (tries + 1))
        speed_bonus = 0.1 * min(speed / 3000000, 1)
        initial_preference = 0.04 if (route[1] == configured_proxy and not tries) else 0
        return quality + exploration + speed_bonus + initial_preference

    return sorted(routes, key=score, reverse=True)


def record_route(path, state, url, use_proxy, success, speed=0, error=''):
    key = route_key(url, use_proxy)
    value = state['routes'].setdefault(key, {'tries': 0, 'wins': 0, 'speed': 0,
                                             'updated': 0, 'error': ''})
    if value['tries'] >= 1000000:
        value['tries'] //= 2
        value['wins'] //= 2
    previous_updated = value['updated']
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
    total = sum(nonnegative(value.get('tries')) *
                0.5 ** (max(0, now - nonnegative(value.get('updated'))) / ROUTE_HISTORY_HALFLIFE)
                for value in records.values())

    def score(endpoint):
        value = records.get(endpoint[0], {})
        age = max(0, now - nonnegative(value.get('updated')))
        decay = 0.5 ** (age / ROUTE_HISTORY_HALFLIFE)
        tries = nonnegative(value.get('tries')) * decay
        wins = nonnegative(value.get('wins')) * decay
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


def download(url, path, use_proxy, cancel=None):
    handler = urllib.request.ProxyHandler() if use_proxy else urllib.request.ProxyHandler({})
    opener = urllib.request.build_opener(handler)
    request = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
    started = time.monotonic()
    downloaded = 0
    last_report = 0
    try:
        with opener.open(request, timeout=9) as response:
            final = urllib.parse.urlsplit(response.geturl())
            if final.scheme.lower() != 'https':
                raise ValueError('下载重定向离开 HTTPS')
            size_header = response.headers.get('Content-Length', '')
            length = int(size_header) if size_header else 0
            if length < 0 or length > MAX_DOWNLOAD:
                raise ValueError('文件大小超过安全限制')
            with path.open('wb') as target:
                while not STOP.is_set() and not (cancel and cancel.is_set()):
                    if time.monotonic() - started > DOWNLOAD_TIME_LIMIT:
                        raise TimeoutError('下载超过总时间限制')
                    chunk = response.read(131072)
                    if not chunk:
                        break
                    downloaded += len(chunk)
                    if downloaded > MAX_DOWNLOAD:
                        raise ValueError('文件大小超过安全限制')
                    target.write(chunk)
                    now = time.monotonic()
                    if now - last_report >= 0.35:
                        value = 14 + min(51, int(downloaded / length * 51)) if length else 18
                        stage(value, '正在下载官方 Psiphon',
                              f'已接收 {downloaded // 1024} KiB' +
                              (f' / {length // 1024} KiB' if length else ''))
                        last_report = now
            if STOP.is_set() or (cancel and cancel.is_set()):
                raise InterruptedError('已停止')
            if length and downloaded != length:
                raise ValueError('下载内容不完整')
            if downloaded < 100000:
                raise ValueError('文件过小，无法确认为客户端')
            with path.open('rb') as file:
                if file.read(2) != b'MZ':
                    raise ValueError('文件不是 Windows 可执行程序')
            return downloaded / max(time.monotonic() - started, 0.1)
    except (OSError, urllib.error.URLError, http.client.HTTPException, ValueError,
            TimeoutError, InterruptedError):
        safe_remove(path)
        raise


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

    def attempt(number, url, use_proxy):
        scratch = data / ('psiphon3.part.%s.exe' % number)
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
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r'Software\Microsoft\Windows\CurrentVersion\Internet Settings') as key:
            enabled = int(winreg.QueryValueEx(key, 'ProxyEnable')[0])
            server = str(winreg.QueryValueEx(key, 'ProxyServer')[0])
        if not enabled:
            return {}
    except (OSError, ValueError, TypeError):
        return {}
    candidates = {}
    for entry in server.split(';'):
        if not entry.strip():
            continue
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


def proxy_registry_snapshot():
    if sys.platform != 'win32':
        return None
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r'Software\Microsoft\Windows\CurrentVersion\Internet Settings') as key:
            values = {}
            for name in ('ProxyEnable', 'ProxyServer', 'ProxyOverride', 'AutoConfigURL', 'AutoDetect'):
                try:
                    values[name] = winreg.QueryValueEx(key, name)[0]
                except FileNotFoundError:
                    values[name] = None
            return values
    except (OSError, ValueError, TypeError):
        return None


def proxy_transition_matches(baseline, observed, current):
    fields = ('ProxyEnable', 'ProxyServer', 'ProxyOverride', 'AutoConfigURL', 'AutoDetect')
    if not all(isinstance(value, dict) for value in (baseline, observed, current)):
        return False
    if any(any(field not in value for field in fields) for value in (baseline, observed, current)):
        return False
    return all(current[field] in (baseline[field], observed[field]) for field in fields)


def notify_proxy_change():
    try:
        result = True
        for option in (39, 37):
            result = bool(ctypes.windll.wininet.InternetSetOptionW(None, option, None, 0)) and result
        return result
    except (OSError, AttributeError, TypeError, ValueError):
        return False


def restore_managed_proxy(baseline, observed):
    if not baseline or not observed or baseline == observed:
        return False
    current = proxy_registry_snapshot()
    if not proxy_transition_matches(baseline, observed, current):
        return False
    kinds = {'ProxyEnable': 4, 'ProxyServer': 1, 'ProxyOverride': 1,
             'AutoConfigURL': 1, 'AutoDetect': 4}
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r'Software\Microsoft\Windows\CurrentVersion\Internet Settings',
                            0, winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
            if proxy_registry_snapshot() != current:
                return False
            for name, reg_type in kinds.items():
                value = baseline.get(name)
                if current.get(name) == value:
                    continue
                if value is None:
                    try:
                        winreg.DeleteValue(key, name)
                    except FileNotFoundError:
                        pass
                else:
                    winreg.SetValueEx(key, name, 0, reg_type, value)
        changed = notify_proxy_change()
        return changed and proxy_registry_snapshot() == baseline
    except (OSError, AttributeError, TypeError, ValueError):
        return False


def save_proxy_guard(path, baseline, observed):
    if not baseline or not observed or baseline == observed:
        return False
    obj = {'baseline': baseline, 'observed': observed, 'when': time.time()}
    temp = path.with_name(path.name + '.tmp')
    try:
        with temp.open('w', encoding='utf-8') as output:
            output.write(json.dumps(obj, ensure_ascii=False))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp, path)
        return True
    except (OSError, ValueError, TypeError):
        safe_remove(temp)
        return False


def recover_proxy_guard(path):
    if not path.is_file():
        return
    try:
        obj = json.loads(path.read_text(encoding='utf-8'))
        baseline, observed = obj['baseline'], obj['observed']
        if not isinstance(baseline, dict) or not isinstance(observed, dict):
            raise ValueError('代理防护记录无效')
        current = proxy_registry_snapshot()
        if current is None:
            item('恢复', '暂时无法读取系统代理，保留防护记录')
            return
        if current == baseline:
            if notify_proxy_change():
                safe_remove(path)
            return
        if not proxy_transition_matches(baseline, observed, current):
            safe_remove(path)
            item('恢复', '系统代理已由其他程序改变，不覆盖现有设置')
            return
        if not (0 <= time.time() - float(obj.get('when', 0)) <= PROXY_GUARD_TTL):
            item('恢复', '代理防护记录已过期，暂不覆盖现有设置')
            return
        if proxy_ports_unclaimed(observed):
            if restore_managed_proxy(baseline, observed):
                safe_remove(path)
                item('恢复', '已恢复之前遗留的原系统代理')
            else:
                item('恢复', '代理恢复暂未完成，保留防护记录')
        else:
            item('恢复', '保留代理防护记录，未覆盖仍在使用的设置')
    except (OSError, TypeError, ValueError, KeyError, OverflowError):
        safe_remove(path)


def managed_proxy_snapshot(proc, client):
    if proc is None or proc.poll() is not None or not same_executable(proc.pid, client):
        return None
    configured = system_proxies()
    if not configured:
        return None
    for port in configured.values():
        listeners = listener_endpoints(port)
        if not any(owner == proc.pid for _, owner in listeners):
            return None
    return proxy_registry_snapshot()


def proxy_ports_unclaimed(observed=None):
    ports = set(system_proxies().values())
    if isinstance(observed, dict) and isinstance(observed.get('ProxyServer'), str):
        for part in observed['ProxyServer'].split(';'):
            value = part.split('=', 1)[-1].strip()
            match = re.fullmatch(r'(?:localhost|127\.0\.0\.1|\[::1\]):(\d{1,5})', value, re.I)
            if match and 0 < int(match.group(1)) <= 65535:
                ports.add(int(match.group(1)))
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
            host = '127.0.0.1' if address == bytes(4) else (
                socket.inet_ntoa(address) if address[0] == 127 else None)
        else:
            address = raw[offset:offset + 16]
            encoded_port = struct.unpack_from('<I', raw, offset + 20)[0]
            state, pid = struct.unpack_from('<II', raw, offset + 48)
            host = '::1' if address in (bytes(16), bytes(15) + b'\x01') else None
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


def read_exact(sock, length):
    output = bytearray()
    while len(output) < length:
        chunk = sock.recv(length - len(output))
        if not chunk:
            raise OSError('SOCKS5 代理提前断开连接')
        output.extend(chunk)
    return bytes(output)


def socks5_tunnel(host, port, destination):
    sock = socket.create_connection((host, port), timeout=6)
    try:
        sock.settimeout(6)
        sock.sendall(b'\x05\x01\x00')
        if read_exact(sock, 2) != b'\x05\x00':
            raise OSError('SOCKS5 不支持无认证连接')
        address = destination.encode('idna')
        if len(address) > 255:
            raise ValueError('目标域名过长')
        sock.sendall(b'\x05\x01\x00\x03' + bytes((len(address),)) + address + b'\x01\xbb')
        reply = read_exact(sock, 4)
        if reply[0] != 5 or reply[1] != 0:
            raise OSError('SOCKS5 建立连接失败')
        size = {1: 4, 4: 16}.get(reply[3])
        if reply[3] == 3:
            size = read_exact(sock, 1)[0]
        if size is None:
            raise OSError('SOCKS5 返回非法地址类型')
        read_exact(sock, size + 2)
        return sock
    except Exception:
        sock.close()
        raise


def open_tunnel(method, endpoint, target):
    if method == 'DIRECT':
        return socket.create_connection((target, 443), timeout=6)
    _, host, port, _ = endpoint
    if method == 'SOCKS5':
        return socks5_tunnel(host, port, target)
    conn = http.client.HTTPConnection(host, port, timeout=6)
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


def terminate_managed_process(proc, client):
    if proc is None or proc.poll() is not None or not same_executable(proc.pid, client):
        return False
    try:
        proc.terminate()
        return True
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
    if sys.platform != 'win32' or platform.machine().lower() not in ('amd64', 'x86_64'):
        raise RuntimeError('本程序仅支持 Windows 11 x64')
    version = sys.getwindowsversion()
    if version.major < 10 or version.build < 22000:
        raise RuntimeError('本程序要求 Windows 11')


def authenti_publisher(path):
    try:
        identity = (str(path.resolve()), path.stat().st_size, path.stat().st_mtime_ns)
    except OSError:
        return None
    cached = SIGNER_CACHE.get(identity)
    if cached is not None:
        return cached or None
    escaped = str(path).replace("'", "''")
    script = ("$ErrorActionPreference='Stop'; $s=Get-AuthenticodeSignature -LiteralPath '" +
              escaped + "'; if($s.Status -ne 'Valid' -or $null -eq $s.SignerCertificate)" +
              "{exit 1}; Write-Output $s.SignerCertificate.Subject")
    try:
        result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                                capture_output=True, text=True, encoding='utf-8', errors='replace',
                                timeout=20, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        subject = result.stdout.strip()[:500] if result.returncode == 0 else ''
    except (OSError, subprocess.TimeoutExpired):
        subject = ''
    if len(SIGNER_CACHE) > 100:
        SIGNER_CACHE.clear()
    SIGNER_CACHE[identity] = subject
    return subject or None


def signed_vendor(path, name):
    subject = authenti_publisher(path)
    if not subject:
        return False
    components = re.findall(r'(?:^|,\s*)(?:CN|O)\s*=\s*(\"[^\"]+\"|[^,]+)', subject, re.I)
    subjects = [part.strip().strip('\"').casefold() for part in components]
    if not subjects:
        return False
    allowed = SIGNER_TOKENS.get(name, ())
    return any(s == word or s.startswith(word + ',') or s.startswith(word + ' inc')
               or s.startswith(word + ' ltd') or s.startswith(word + ' llc')
               for s in subjects for word in allowed)


def find_installed(name):
    allowed = set(item.casefold() for item in KNOWN_EXES.get(name, ()))
    now = time.monotonic()
    cached = DISCOVERY_CACHE.get(name)
    if cached and now - cached[0] < 90:
        return cached[1]
    found = []

    def add(path):
        if path is not None and path.is_file() and path.name.casefold() in allowed and path not in found:
            found.append(path)

    for filename in KNOWN_EXES.get(name, ()):
        location = shutil.which(filename)
        if location:
            add(pathlib.Path(location))
    home = pathlib.Path.home()
    roots = [home / '.cargo' / 'bin',
             pathlib.Path(os.environ.get('ProgramFiles', r'C:\Program Files')),
             pathlib.Path(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)')),
             pathlib.Path(os.environ.get('LOCALAPPDATA', str(home / 'AppData' / 'Local')))]
    folders = {
        'Geph': ('Geph', 'Programs/Geph'),
        'Proton VPN': ('Proton/VPN', 'Proton/Proton VPN', 'ProtonVPN', 'Programs/ProtonVPN', 'Proton/ProtonVPN'),
        'nthLink': ('nthLink', 'Programs/nthLink'),
        'Lantern': ('Lantern', 'Programs/Lantern'),
    }
    for root in roots:
        for filename in KNOWN_EXES.get(name, ()):
            add(root / filename)
        for subdir in folders.get(name, ()):
            folder = root / pathlib.PurePosixPath(subdir)
            for filename in KNOWN_EXES.get(name, ()):
                add(folder / filename)
                add(folder / 'bin' / filename)
                add(folder / 'app' / filename)
                if name == 'Proton VPN' and folder.is_dir():
                    try:
                        for folder_version in list(folder.glob('v*'))[-10:]:
                            if folder_version.is_dir():
                                add(folder_version / filename)
                    except OSError:
                        pass
    try:
        import winreg
        hives = ((winreg.HKEY_CURRENT_USER, 0), (winreg.HKEY_LOCAL_MACHINE, 0),
                 (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY))
        base = r'Software\Microsoft\Windows\CurrentVersion\Uninstall'
        for hive, view in hives:
            try:
                parent = winreg.OpenKey(hive, base, 0, winreg.KEY_READ | view)
            except OSError:
                continue
            with parent:
                count = min(winreg.QueryInfoKey(parent)[0], 5000)
                for number in range(count):
                    try:
                        child_name = winreg.EnumKey(parent, number)
                        with winreg.OpenKey(parent, child_name) as key:
                            display = str(winreg.QueryValueEx(key, 'DisplayName')[0]).casefold()
                            if name.casefold().replace(' ', '') not in display.replace(' ', ''):
                                continue
                            for field in ('InstallLocation', 'DisplayIcon'):
                                try:
                                    value = str(winreg.QueryValueEx(key, field)[0]).strip().strip('"')
                                    if field == 'DisplayIcon':
                                        value = re.sub(r',-?\d+$', '', value).strip('"')
                                    location = pathlib.Path(os.path.expandvars(value))
                                    if location.is_file():
                                        add(location)
                                    elif location.is_dir():
                                        for candidate in KNOWN_EXES.get(name, ()):
                                            add(location / candidate)
                                except (OSError, ValueError):
                                    continue
                    except OSError:
                        continue
    except (OSError, ImportError):
        pass
    DISCOVERY_CACHE[name] = now, found
    return found


def find_geph_cli():
    for executable in find_installed('Geph'):
        if executable.name.casefold() == 'geph5.exe' and signed_vendor(executable, 'Geph'):
            return executable
    return None


def background_command(args, timeout=10):
    try:
        result = subprocess.run([str(piece) for piece in args], input='', capture_output=True,
                                text=True, encoding='utf-8', errors='replace', timeout=timeout,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        return result.returncode, (result.stdout + ' ' + result.stderr)[:2048]
    except (OSError, subprocess.TimeoutExpired) as exc:
        return -1, type(exc).__name__


def geph_ready(binary):
    code, output = background_command((binary, 'account'), timeout=7)
    if code != 0 or any(text in output.casefold() for text in ('not logged', 'not logged in', 'no account')):
        return False
    code, output = background_command((binary, 'status'), timeout=7)
    return code == 0 and not any(text in output.casefold() for text in ('manager unavailable', 'connection refused'))


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


def registered_process(binary):
    try:
        result = subprocess.run(['tasklist.exe', '/FO', 'CSV', '/NH'], capture_output=True,
                                text=True, errors='replace', timeout=6,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        expected = os.path.normcase(str(binary.resolve()))
        for row in csv.reader(result.stdout.splitlines()):
            if len(row) < 2 or row[0].casefold() != binary.name.casefold():
                continue
            try:
                pid = int(row[1].replace(',', ''))
                path = process_executable(pid)
                if path and os.path.normcase(str(path.resolve())) == expected:
                    return pid
            except (ValueError, OSError):
                continue
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def safe_asset_download(url, target, expected_sha256, maximum=65 * 1024 * 1024):
    request = urllib.request.Request(url, headers={'User-Agent': 'AccessMonitor/4 (Windows 11 x64)'})
    digest = hashlib.sha256()
    received = 0
    started = time.monotonic()
    safe_remove(target)
    try:
        with urllib.request.urlopen(request, timeout=12) as source:
            final = urllib.parse.urlsplit(source.geturl())
            if final.scheme != 'https' or final.hostname != 'dist.torproject.org':
                raise ValueError('Tor 下载未停留在官方 HTTPS 域名')
            length = source.headers.get('Content-Length')
            if length and int(length) > maximum:
                raise ValueError('下载大小超限')
            with target.open('wb') as output:
                while not STOP.is_set():
                    if time.monotonic() - started > 110:
                        raise TimeoutError('Tor 下载超时')
                    chunk = source.read(131072)
                    if not chunk:
                        break
                    received += len(chunk)
                    if received > maximum:
                        raise ValueError('下载大小超限')
                    digest.update(chunk)
                    output.write(chunk)
                    if received % (2 * 1024 * 1024) < len(chunk):
                        item('下载', 'Tor 官方 Expert Bundle：%s MiB' % (received // 1048576))
        if STOP.is_set():
            raise InterruptedError('已停止')
        if not received or digest.hexdigest().lower() != expected_sha256.lower():
            raise ValueError('Tor 官方版本固定 SHA-256 校验不匹配')
    except (OSError, ValueError, TimeoutError, InterruptedError, urllib.error.URLError,
            http.client.HTTPException):
        safe_remove(target)
        raise


def trusted_tor_files(data):
    bundle = data / ('tor-expert-' + TOR_VERSION + '.tar.gz')
    if bundle.is_file():
        with bundle.open('rb') as source:
            hash_value = hashlib.file_digest(source, 'sha256').hexdigest() if hasattr(hashlib, 'file_digest') else hashlib.sha256(source.read()).hexdigest()
        if hash_value != TOR_SHA256:
            safe_remove(bundle)
    if not bundle.is_file():
        item('Tor', '下载官方 Expert Bundle（固定版本 SHA-256 校验）')
        safe_asset_download(TOR_ARCHIVE_URL, bundle, TOR_SHA256)
    root = data / ('tor-' + TOR_VERSION)
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
                    shutil.copyfileobj(source, output, 131072)
        binaries = list(temporary.rglob('tor.exe'))
        transports = list(temporary.rglob('lyrebird.exe'))
        if len(binaries) != 1 or len(transports) != 1:
            raise ValueError('官方 Tor Bundle 缺少必要的 tor/lyrebird 可执行文件')
        if root.exists():
            shutil.rmtree(root)
        os.replace(temporary, root)
        return root / binaries[0].relative_to(temporary), root / transports[0].relative_to(temporary)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def tor_bridge_profiles(data):
    paths = (data.parent / 'tor_bridges.txt', data / 'tor_bridges.txt')
    groups = {'obfs4': [], 'webtunnel': [], 'snowflake': [], 'meek_lite': []}
    for path in paths:
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > 30000:
                continue
            for line in path.read_text(encoding='utf-8-sig').splitlines():
                line = line.strip()
                if not line or line.startswith('#') or len(line) > 1800:
                    continue
                if line.casefold().startswith('bridge '):
                    line = line[7:].strip()
                if not re.fullmatch(r'[\x21-\x7e ]+', line) or '\\' in line or '"' in line:
                    continue
                parts = line.split()
                if len(parts) < 3 or len(parts) > 45:
                    continue
                kind = parts[0].casefold()
                if kind == 'meek':
                    kind = 'meek_lite'
                    parts[0] = kind
                hostport = re.fullmatch(r'([A-Za-z0-9.\-]+):(\d{1,5})', parts[1])
                if not hostport or not 1 <= int(hostport.group(2)) <= 65535:
                    continue
                if kind in groups and len(groups[kind]) < 12:
                    groups[kind].append(' '.join(parts))
        except (OSError, UnicodeError):
            continue
    profiles = [(key, value) for key, value in groups.items() if value]
    if not groups['snowflake']:
        profiles.append(('snowflake', [TOR_SNOWFLAKE]))
    profiles.append(('direct', []))
    return profiles


def ranked_tor_bridges(profiles, state):
    records = state.get('bridge_stats', {})
    total = sum(nonnegative(record.get('tries')) for record in records.values())

    def score(profile):
        name = profile[0]
        record = records.get(name, {})
        age = max(0, time.time() - nonnegative(record.get('updated')))
        factor = 0.5 ** (age / ROUTE_HISTORY_HALFLIFE)
        tries = factor * nonnegative(record.get('tries'))
        wins = factor * nonnegative(record.get('wins'))
        success = (wins + 1) / (tries + 2)
        explore = 0.22 * math.sqrt(math.log(total + 2) / (tries + 1))
        return success + explore + (0.03 if profile[1] else -0.03)

    return sorted(profiles, key=score, reverse=True)


def record_bridge(state, profile, success):
    if not profile:
        return
    name = profile[0]
    records = state.setdefault('bridge_stats', {})
    value = records.setdefault(name, {'tries': 0, 'wins': 0, 'updated': 0})
    if value['tries'] >= 1000000:
        value['tries'] //= 2
        value['wins'] //= 2
    value['tries'] += 1
    if success:
        value['wins'] += 1
    value['updated'] = time.time()


def tor_configuration(data, tor, transport, profile, port=TOR_PORT):
    kind, bridges = profile
    tor_data = data / 'tor-private'
    tor_data.mkdir(exist_ok=True)
    rc = data / 'torrc-generated'
    lines = ['SocksPort 127.0.0.1:%s' % port,
             'DataDirectory "%s"' % str(tor_data).replace('\\', '/'),
             'ClientOnly 1', 'SafeLogging 1', 'AvoidDiskWrites 1']
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
    markers = {
        'Psiphon': ('psiphon',),
        'Geph': ('geph',),
        'Proton VPN': ('proton ag', 'protonvpn', 'proton vpn'),
        'Lantern': ('lantern',),
        'nthLink': ('nthlink',),
    }
    return any(word in description for word in markers.get(name, ()))


def probe_single(method, endpoint, target):
    url, expected, level = target
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname
    path = urllib.parse.urlunsplit(('', '', parsed.path or '/', parsed.query, ''))
    raw = None
    try:
        if STOP.is_set():
            return level, None
        begin = time.monotonic()
        raw = open_tunnel(method, endpoint, host)
        remote = raw.getpeername()[0] if method == 'DIRECT' else None
        raw.settimeout(6)
        context = ssl.create_default_context()
        with context.wrap_socket(raw, server_hostname=host) as secure:
            raw = None
            request = 'GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n' % (path, host)
            secure.sendall(request.encode('ascii'))
            reply = http.client.HTTPResponse(secure)
            try:
                reply.begin()
                code = reply.status
                reply.read(128)
                accepted = code == expected if expected is not None else 200 <= code < 400
                if accepted:
                    return level, (host, time.monotonic() - begin, remote)
            finally:
                reply.close()
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError, TimeoutError):
        pass
    finally:
        if raw is not None:
            raw.close()
    return level, None


def probe_quorum(method, endpoint=None):
    good = []
    normal = None
    if STOP.is_set():
        return good, normal
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=min(len(TARGETS), 4))
    pending = {pool.submit(probe_single, method, endpoint, target) for target in TARGETS}
    try:
        while pending and not STOP.is_set():
            completed, pending = concurrent.futures.wait(
                pending, timeout=0.3,
                return_when=concurrent.futures.FIRST_COMPLETED)
            for future in completed:
                try:
                    level, found = future.result()
                except Exception:
                    continue
                if found is None:
                    continue
                if level == '受限服务':
                    good.append(found)
                else:
                    normal = found
            if len(good) >= 2:
                break
        return good, normal
    finally:
        for future in pending:
            future.cancel()
        pool.shutdown(wait=False, cancel_futures=True)


def observed_owned_proxy(name, program, pid):
    result = []
    proxy = system_proxies()
    for key in ('https', 'http', 'all', 'socks'):
        port = proxy.get(key)
        if not port:
            continue
        for host, owner in listener_endpoints(port):
            actual = process_executable(owner)
            if actual is None:
                continue
            trusted = False
            try:
                if pid is not None and pid == owner and actual.resolve() == program.resolve():
                    trusted = True
                elif (actual.name.casefold().startswith(name.casefold().replace(' vpn', ''))
                      and signed_vendor(actual, name)):
                    trusted = True
                elif name == 'Geph' and actual.name.casefold() == 'geph5-client.exe':
                    trusted = actual.parent.resolve() == program.parent.resolve()
            except OSError:
                continue
            endpoint = ('SOCKS5' if key == 'socks' else 'HTTP', host, port, owner)
            if trusted and endpoint not in result:
                result.append(endpoint)
    return result


def engine_stats(state, name, passed, latency=None):
    records = state.setdefault('engines', {})
    record = records.setdefault(name, {'tries': 0, 'wins': 0, 'updated': 0,
                                       'cooldown': 0, 'latency': 0})
    if record['tries'] >= 1000000:
        record['tries'] //= 2
        record['wins'] //= 2
    record['tries'] += 1
    if passed:
        record['wins'] += 1
        if latency is not None:
            sample = min(nonnegative(latency), 60)
            record['latency'] = 0.65 * nonnegative(record.get('latency')) + 0.35 * sample
        record['cooldown'] = 0
    else:
        record['cooldown'] = time.time() + ENGINE_COOLDOWN
    record['updated'] = time.time()


def engines_ranked(state, available):
    now = time.time()
    statistics = state.get('engines', {})
    total = sum(nonnegative(v.get('tries')) for v in statistics.values())
    def score(name):
        number = ENGINE_ORDER.index(name)
        record = statistics.get(name, {})
        tries = nonnegative(record.get('tries'))
        wins = nonnegative(record.get('wins'))
        age = max(0, now - nonnegative(record.get('updated')))
        decay = 0.5 ** (age / ROUTE_HISTORY_HALFLIFE)
        estimate = (wins * decay + 1) / (tries * decay + 2)
        explore = 0.2 * math.sqrt(math.log(total + 2) / (tries * decay + 1))
        prefer = 0.035 * (len(ENGINE_ORDER) - number)
        cold = 1.5 if nonnegative(record.get('cooldown')) > now else 0
        return estimate + explore + prefer - cold
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
        pass


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
    if not binaries:
        return None
    good, unused = probe_quorum('DIRECT')
    if len(good) < 2:
        return None
    for name, program in binaries.items():
        if routes_match_provider(good, name):
            diagnostic('接管已有 ' + name + ' VPN 路由，避免同时启动多个 VPN')
            return {'name': name, 'program': program, 'proc': None,
                    'started': time.monotonic(), 'baseline': None, 'observed': None,
                    'bridge': None, 'owned': False, 'connected_by_us': False}
    return None


def create_session(name, data, state, state_path, bridge=None):
    session = {'name': name, 'proc': None, 'program': None, 'started': time.monotonic(),
               'baseline': None, 'observed': None, 'bridge': bridge, 'owned': False,
               'version': None, 'health': None}
    if name == 'Psiphon':
        already = running_verified_psiphon()
        if already is not None:
            session['program'] = already
            session['owned'] = False
            return session
        client = ensure_client(data, state_path, state)
        if client is None:
            return None
        if signature_status(client) != 'VALID':
            raise RuntimeError('Psiphon 可执行文件签名未通过')
        session['program'] = client
        session['baseline'] = proxy_registry_snapshot()
        session['proc'] = subprocess.Popen([str(client)], cwd=str(data),
                                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                           stderr=subprocess.DEVNULL,
                                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        session['owned'] = True
    elif name == 'Tor':
        tor, lyrebird = trusted_tor_files(data)
        session['program'] = tor
        port = free_tor_port()
        session['tor_port'] = port
        if bridge is None:
            bridge = tor_bridge_profiles(data)[0]
        session['bridge'] = bridge
        rc = tor_configuration(data, tor, lyrebird, bridge, port)
        session['proc'] = subprocess.Popen([str(tor), '-f', str(rc)], cwd=str(tor.parent),
                                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                           stderr=subprocess.DEVNULL,
                                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        session['owned'] = True
    elif name == 'Geph':
        cli = find_geph_cli()
        if cli is None or not geph_ready(cli):
            raise RuntimeError('缺少已配置账户且完成管理器注册的 Geph 5.8+ CLI')
        session['program'] = cli
        code, output = background_command([cli, 'connect'], timeout=18)
        if code != 0:
            raise RuntimeError('Geph connect 未成功：' + output.strip()[-100:])
        session['connected_by_us'] = True
    else:
        candidates = find_installed(name)
        signed = next((path for path in candidates if signed_vendor(path, name)), None)
        if signed is None:
            raise RuntimeError('未发现已安装且发布者签名可信的 ' + name + ' Windows 客户端')
        session['program'] = signed
        existing = registered_process(signed)
        if existing is None:
            session['proc'] = subprocess.Popen([str(signed)], cwd=str(signed.parent),
                                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                               stderr=subprocess.DEVNULL,
                                               creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            session['owned'] = True
        else:
            session['existing_pid'] = existing
    diagnostic(name + ' 开始连接/接管')
    return session


def health_session(session, state=None):
    name = session['name']
    proc = session.get('proc')
    program = session['program']
    if name in ('Tor', 'Psiphon') and proc is not None and proc.poll() is not None:
        return 'DOWN', '客户端进程已退出', None
    if name == 'Tor':
        port = session.get('tor_port', TOR_PORT)
        if proc is None or not tor_port_claimed(proc.pid, port):
            return 'DOWN', '等待 Tor SOCKS5 端口（尚未确认归属）', None
        endpoint = ('SOCKS5', '127.0.0.1', port, proc.pid)
        good, normal = probe_quorum('SOCKS5', endpoint)
        if len(good) >= 2:
            return 'PROXY', 'Tor SOCKS5：至少两个不同受限站点已验证', good[0][1]
        return ('PARTIAL' if good or normal else 'DOWN',
                'Tor 通道测试 %d/3，未验证全局 VPN' % len(good), None)
    direct_allowed = name != 'Psiphon' or psiphon_vpn_present() or not system_proxies()
    direct_good, direct_normal = [], None
    if direct_allowed:
        direct_good, direct_normal = probe_quorum('DIRECT')
        if len(direct_good) >= 2 and routes_match_provider(direct_good, name):
            return 'VPN', '%s 的 VPN 出口路由经至少两个受限站点验证' % name, direct_good[0][1]
    endpoints = []
    if name == 'Psiphon':
        endpoints = owned_proxies(system_proxies(), program, proc.pid if proc is not None else None)
    elif name in ('Geph', 'Proton VPN', 'nthLink', 'Lantern'):
        pid = registered_process(program)
        endpoints = observed_owned_proxy(name, program, pid)
    channel_state = state if state is not None else {'channels': {}}
    for endpoint in rank_channels(endpoints, channel_state):
        proxy_good, proxy_normal = probe_quorum(endpoint[0], endpoint)
        passed = len(proxy_good) >= 2
        if state is not None:
            record_channel(state, endpoint[0], passed, proxy_good[0][1] if passed else None)
        if passed:
            return 'PROXY', '%s 本地%s代理：至少两个受限站点已验证' % (name, endpoint[0]), proxy_good[0][1]
    if direct_allowed:
        if len(direct_good) >= 2:
            return 'UNCONFIRMED', '网站可达，但未证明路由经由 ' + name, None
        if direct_good or direct_normal:
            return 'PARTIAL', '仅 %d/3 个受限站点通过，尚不能判定通道可用' % len(direct_good), None
    return 'DOWN', '未发现通过多站点验证的 ' + name + ' 通道', None


def refresh_proxy_guard(session, guard_path):
    proc = session.get('proc')
    if session['name'] != 'Psiphon' or proc is None or proc.poll() is not None:
        return
    snapshot = managed_proxy_snapshot(proc, session['program'])
    if snapshot is None:
        return
    if session['baseline'] and session['baseline'] != snapshot:
        if save_proxy_guard(guard_path, session['baseline'], snapshot):
            session['observed'] = snapshot
        else:
            item('恢复', '无法保存 Psiphon 代理恢复记录，正在重试')


def apply_tor_proxy(session, guard_path):
    if session['name'] != 'Tor' or session.get('observed') is not None:
        return
    original = proxy_registry_snapshot()
    if not original:
        return
    if original.get('ProxyEnable') or original.get('AutoConfigURL') or original.get('AutoDetect'):
        item('Tor', 'SOCKS5 可用；已有系统代理/PAC/自动检测，未修改')
        return
    expected = dict(original)
    expected['ProxyServer'] = 'socks=127.0.0.1:%s' % session.get('tor_port', TOR_PORT)
    expected['ProxyEnable'] = 1
    if not save_proxy_guard(guard_path, original, expected):
        item('Tor', '无法保存代理恢复记录，禁止修改系统代理')
        return
    session['baseline'] = original
    session['observed'] = expected
    try:
        import winreg
        location = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, location, 0,
                            winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
            if proxy_registry_snapshot() != original:
                safe_remove(guard_path)
                session['baseline'] = None
                session['observed'] = None
                item('Tor', '系统代理已由其他程序改变，取消本次修改')
                return
            winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, expected['ProxyServer'])
            winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 1)
        if proxy_registry_snapshot() != expected or not notify_proxy_change():
            raise RuntimeError('系统代理设置或广播未完成')
        item('Tor', '已为系统代理应用设置 Tor SOCKS5；不代表整机 VPN')
    except (OSError, AttributeError, TypeError, ValueError, RuntimeError) as exc:
        item('Tor', '系统代理修改失败：' + type(exc).__name__)
        if restore_managed_proxy(original, expected):
            safe_remove(guard_path)
            session['baseline'] = None
            session['observed'] = None
        else:
            item('恢复', '保留代理防护记录，后续继续尝试恢复')


def cleanup_session(session, guard_path, exiting=False):
    if not session:
        return
    name = session['name']
    proc = session.get('proc')
    program = session.get('program')
    if proc is not None and proc.poll() is None and session.get('owned') and (not exiting or name == 'Tor'):
        if name == 'Psiphon' and same_executable(proc.pid, program):
            request_graceful_close(proc.pid)
            try:
                proc.wait(timeout=12)
            except subprocess.TimeoutExpired:
                if terminate_managed_process(proc, program):
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
        elif name == 'Tor':
            try:
                proc.terminate()
                proc.wait(timeout=8)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    proc.kill()
                    proc.wait(timeout=4)
                except (OSError, subprocess.TimeoutExpired):
                    diagnostic('Tor 进程无法终止，保留代理防护记录')
        elif name not in ('Geph',):
            if program is not None and same_executable(proc.pid, program):
                request_graceful_close(proc.pid)
    if name == 'Geph' and not exiting and session.get('connected_by_us'):
        cli = session.get('program')
        if cli is not None:
            background_command([cli, 'disconnect'], timeout=8)
    if session.get('observed') and session.get('baseline'):
        if name == 'Psiphon' and proc is not None and proc.poll() is None:
            return
        if proxy_ports_unclaimed(session['observed']) and restore_managed_proxy(session['baseline'], session['observed']):
            safe_remove(guard_path)
            item('恢复', '已恢复原有 Windows 代理设置')
    diagnostic(name + (' 监控窗口退出' if exiting else ' 切换/清理'))


def run_engine(session, data, guard_path, state, state_path):
    name = session['name']
    since = time.monotonic()
    unavailable_since = None
    ever_healthy = False
    recorded = False
    bridge_recorded = False
    last_saved = time.monotonic()
    good_streak = 0
    failed_streak = 0
    while not STOP.is_set():
        refresh_proxy_guard(session, guard_path)
        kind, message, latency = health_session(session, state)
        now = time.monotonic()
        item('连接状态', message)
        item('最近检查', datetime.datetime.now().strftime('%H:%M:%S'))
        item('运行引擎', name + (' / ' + session['bridge'][0] if session.get('bridge') else ''))
        item('访问测试', kind + '：' + message)
        if kind in ('VPN', 'PROXY'):
            good_streak += 1
            failed_streak = 0
            unavailable_since = None
            if good_streak >= 1:
                if not recorded:
                    engine_stats(state, name, True, latency)
                    if name == 'Tor':
                        record_bridge(state, session.get('bridge'), True)
                        bridge_recorded = True
                    recorded = True
                    state['connections'] = min(state.get('connections', 0) + 1, 1000000)
                    save_state(state_path, state)
                ever_healthy = True
                title = ('VPN 路由已验证：' if kind == 'VPN' else '代理通道已验证：') + name
                connection_state(title, message + ('；不代表全部协议均经 VPN' if kind == 'VPN'
                                                    else '；仅使用代理的应用受益'))
                stage(100, '已通过多站点连通性验证', message)
                item('恢复', '持续监测通道；故障时有限频切换')
                if kind == 'PROXY' and name == 'Tor':
                    apply_tor_proxy(session, guard_path)
                interval = max(18, min(55, int(20 + 6 * (latency or 0))))
        else:
            good_streak = 0
            failed_streak += 1
            if unavailable_since is None:
                unavailable_since = now
            elapsed = now - (unavailable_since if ever_healthy else since)
            connection_state('正在验证/恢复：' + name, message)
            if kind == 'UNCONFIRMED':
                item('恢复', '网站可达，但不是已证明的受管通道；暂不冒进重启')
            else:
                item('恢复', '连续 %s 次未验证，通过限频策略考虑切换' % failed_streak)
            stage(82 if ever_healthy else 87, '正在验证/恢复：' + name, message)
            if ((not ever_healthy and now - since >= (TOR_START_WINDOW if name == 'Tor' else ENGINE_START_WINDOW))
                    or (ever_healthy and failed_streak >= 5 and elapsed >= ENGINE_OUTAGE_WINDOW)):
                if name == 'Tor' and (not bridge_recorded or ever_healthy):
                    record_bridge(state, session.get('bridge'), False)
                    bridge_recorded = True
                engine_stats(state, name, False)
                recorded = True
                save_state(state_path, state)
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


def connect(data):
    validate_windows()
    stage(5, 'Windows 11 x64 已验证', '准备在已选文件夹存放运行数据')
    item('系统', 'Windows 11 x64 / Python %s.%s' % sys.version_info[:2])
    for scratch in data.glob('psiphon3.part.*.exe'):
        safe_remove(scratch)
    item('数据目录', str(data))
    state_path = data / 'state.json'
    guard_path = data / 'proxy_guard.json'
    recover_proxy_guard(guard_path)
    state = load_state(state_path)
    for name in ENGINE_ORDER:
        item(name, '正在检查')
    while not STOP.is_set():
        available = []
        candidates = {}
        geph = find_geph_cli()
        if geph is not None and geph_ready(geph):
            available.append('Geph')
            candidates['Geph'] = geph
            item('Geph', '已找到 CLI、账户及管理器')
        else:
            item('Geph', '未找到已登录且注册管理器的 CLI')
        for name in ('Proton VPN', 'nthLink', 'Lantern'):
            locations = find_installed(name)
            ready = next((location for location in locations if signed_vendor(location, name)), None)
            if ready:
                available.append(name)
                candidates[name] = ready
                item(name, '检测到可信安装，依赖客户端自身自动连接设置')
            else:
                item(name, '未找到可信已安装客户端')
        existing_psiphon = running_verified_psiphon()
        if existing_psiphon is not None:
            candidates['Psiphon'] = existing_psiphon
            item('Psiphon', '找到已运行且签名可信的 Psiphon，优先避免重复启动')
        existing = existing_vpn_session(candidates)
        if existing is not None:
            name = existing['name']
            stage(100, '检测到已在运行的 VPN', name + ' 经多站点及专属路由验证')
            item('运行引擎', '接管已有 ' + name + ' VPN')
            try:
                run_engine(existing, data, guard_path, state, state_path)
            finally:
                cleanup_session(existing, guard_path, exiting=STOP.is_set())
            if STOP.is_set():
                return
        available.extend(('Psiphon', 'Tor'))
        for name in engines_ranked(state, available):
            if STOP.is_set():
                return
            record = state.get('engines', {}).get(name, {})
            if nonnegative(record.get('cooldown')) > time.time():
                continue
            bridge = None
            if name == 'Tor':
                profiles = ranked_tor_bridges(tor_bridge_profiles(data), state)
                bridge = profiles[0]
                item('Tor 网桥', bridge[0] + ('（自带/已配置）' if bridge[1] else '（直连）'))
            item('运行引擎', '准备 ' + name)
            stage(12, '正在准备：' + name, '检查官方程序、权限、签名及本地状态')
            session = None
            try:
                session = create_session(name, data, state, state_path, bridge)
                if session is None:
                    continue
                item(name, '已启动，等待多站点及路由归属验证')
                run_engine(session, data, guard_path, state, state_path)
            except (OSError, RuntimeError, ValueError, KeyError, tarfile.TarError,
                    urllib.error.URLError, http.client.HTTPException, TimeoutError) as exc:
                diagnostic(name + '：' + type(exc).__name__ + ' ' + str(exc)[:125])
                item(name, '暂不可用：' + str(exc)[:115])
                engine_stats(state, name, False)
                save_state(state_path, state)
                connection_state('尝试其他引擎', name + '：' + str(exc)[:120])
            finally:
                cleanup_session(session, guard_path, exiting=STOP.is_set())
                write_diagnostics(data)
            if STOP.is_set():
                return
        stage(15, '全部候选正在冷却', '未伪报连接成功；等待重试或客户端/账户前置条件就绪')
        connection_state('等待下一轮', '已按历史表现排序尝试，可用通道将被持续监测')
        item('恢复', '暂停 30 秒后自动复查全部引擎')
        save_state(state_path, state)
        write_diagnostics(data)
        if STOP.wait(30):
            return


def worker(data):
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


def acquire_mutex(data):
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


def main():
    app = tk.Tk()
    app.withdraw()
    app.title('多引擎网络连接 · 自动准备与监测')
    folder = filedialog.askdirectory(parent=app, title='请选择客户端和运行数据的保存文件夹', mustexist=True)
    if not folder:
        app.destroy()
        return
    data = pathlib.Path(folder).resolve() / 'connection_data'
    app.configure(bg='#101827')
    app.geometry(f'{min(1120, max(360, app.winfo_screenwidth() - 40))}x{min(830, max(440, app.winfo_screenheight() - 70))}')
    app.minsize(min(500, app.winfo_screenwidth()), min(440, app.winfo_screenheight()))
    try:
        app.tk.call('tk', 'scaling', min(1.35, max(1.0, app.winfo_fpixels('1i') / 96)))
    except tk.TclError:
        pass
    header = tk.Frame(app, bg='#101827')
    header.pack(fill='x', padx=20, pady=(14, 5))
    tk.Label(header, text='多引擎网络连接状态', font=('Microsoft YaHei UI', 18, 'bold'),
             bg='#101827', fg='#f2f6fc').pack(anchor='w')
    status = tk.StringVar(value='初始化中')
    detail = tk.StringVar(value='选择文件夹后自动执行，无需进一步操作')
    tk.Label(app, textvariable=status, font=('Microsoft YaHei UI', 11, 'bold'),
             bg='#101827', fg='#80d8ff', anchor='w').pack(fill='x', padx=20, pady=(5, 3))
    detail_label = tk.Label(app, textvariable=detail, font=('Microsoft YaHei UI', 9),
                            bg='#101827', fg='#cbd5e1', anchor='w', justify='left')
    detail_label.pack(fill='x', padx=20, pady=(0, 8))
    style = ttk.Style(app)
    style.theme_use('clam')
    style.configure('Conn.Horizontal.TProgressbar', troughcolor='#27354a', background='#35c3a6',
                    bordercolor='#27354a', lightcolor='#35c3a6', darkcolor='#35c3a6', thickness=18)
    bar = ttk.Progressbar(app, maximum=100, value=0, style='Conn.Horizontal.TProgressbar')
    bar.pack(fill='x', padx=20)
    percent = tk.StringVar(value='准备 0%')
    tk.Label(app, textvariable=percent, font=('Consolas', 12, 'bold'),
             bg='#101827', fg='#f2f6fc').pack(anchor='e', padx=20, pady=(3, 8))
    panel_box = tk.Frame(app, bg='#172339')
    panel_box.pack(fill='both', expand=True, padx=20, pady=(0, 8))
    canvas = tk.Canvas(panel_box, bg='#172339', highlightthickness=0, borderwidth=0)
    scrollbar = ttk.Scrollbar(panel_box, orient='vertical', command=canvas.yview)
    canvas.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side='right', fill='y')
    canvas.pack(side='left', fill='both', expand=True)
    panel = tk.Frame(canvas, bg='#172339')
    panel_id = canvas.create_window((0, 0), window=panel, anchor='nw')
    panel.bind('<Configure>', lambda event: canvas.configure(scrollregion=canvas.bbox('all')))
    canvas.bind('<Configure>', lambda event: canvas.itemconfigure(panel_id, width=event.width))
    labels = {}
    names = ('连接状态', '运行引擎', 'Geph', 'Proton VPN', 'nthLink', 'Lantern',
             'Psiphon', 'Tor', 'Tor 网桥', '访问测试', '最近检查', '恢复', '自适应',
             '安全', '下载', '系统', '数据目录', '存储')
    lines = []
    for index, name in enumerate(names):
        line = tk.Frame(panel, bg='#172339')
        title = tk.Label(line, text=name, width=10, anchor='nw', font=('Microsoft YaHei UI', 9),
                         bg='#172339', fg='#93a4bb')
        title.pack(side='left')
        value = tk.StringVar(value='—')
        field = tk.Label(line, textvariable=value, font=('Microsoft YaHei UI', 9),
                         bg='#172339', fg='#e1e9f5', anchor='nw', justify='left')
        field.pack(side='left', fill='x', expand=True)
        labels[name] = (value, field)
        lines.append(line)
    footer = tk.Label(app, text='代理≠整机 VPN；退出会关闭本程序托管的 Tor 并尝试恢复代理；网桥可放入 tor_bridges.txt。',
                      bg='#101827', fg='#93a4bb', font=('Microsoft YaHei UI', 8), anchor='w')
    footer.pack(fill='x', padx=20, pady=(0, 9))
    app.deiconify()
    app.update_idletasks()

    measured_layout = None

    def resize(event=None):
        nonlocal measured_layout
        if event is not None and event.widget is not app:
            return
        width = max(260, app.winfo_width() - 40)
        columns = 2 if width >= 700 else 1
        signature = (columns, width // 16)
        if signature == measured_layout:
            return
        measured_layout = signature
        detail_label.configure(wraplength=width)
        cell_width = (width - 20) // columns
        for index, line in enumerate(lines):
            line.grid_forget()
            line.grid(row=index // columns, column=index % columns,
                      sticky='new', padx=7, pady=2)
        for col_index in range(2):
            panel.grid_columnconfigure(col_index, weight=1 if col_index < columns else 0,
                                       minsize=cell_width if col_index < columns else 0)
        for value, field in labels.values():
            field.configure(wraplength=max(140, cell_width - 128))

    app.bind('<Configure>', resize)
    resize()
    scan_direction = [1]

    def auto_show_all():
        if STOP.is_set():
            return
        try:
            canvas.update_idletasks()
            lo, hi = canvas.yview()
            if hi - lo < 0.997:
                if scan_direction[0] > 0 and hi >= 0.995:
                    scan_direction[0] = -1
                elif scan_direction[0] < 0 and lo <= 0.005:
                    scan_direction[0] = 1
                canvas.yview_moveto(max(0, min(1.0, lo + 0.17 * scan_direction[0])))
        except tk.TclError:
            return
        app.after(3300, auto_show_all)

    app.after(5000, auto_show_all)
    labels['数据目录'][0].set(str(data))
    labels['存储'][0].set('监控数据存放此目录；第三方客户端可能另有自身数据')
    last_progress = 0

    def poll_ui():
        nonlocal last_progress
        if STOP.is_set():
            return
        for _ in range(120):
            try:
                kind, values = MESSAGES.get_nowait()
            except queue.Empty:
                break
            if kind == 'stage':
                amount, title, message = values
                last_progress = amount
                bar['value'] = last_progress
                percent.set(f'准备 {last_progress}%')
                if last_progress < 100:
                    status.set(title)
                    detail.set(message)
            elif kind == 'connection':
                title, message = values
                status.set(title)
                detail.set(message)
            elif kind == 'item':
                name, value = values
                if name in labels:
                    labels[name][0].set(value)
        app.after(120, poll_ui)

    working_thread = [None]

    def close_app():
        if STOP.is_set():
            return
        STOP.set()
        status.set('正在停止监测并清理受管 Tor 代理')
        started_at = time.monotonic()

        def finish():
            thread = working_thread[0]
            if thread is None or not thread.is_alive():
                app.destroy()
                return
            if time.monotonic() - started_at > 25:
                status.set('后台任务仍在清理中；完成后自动关闭')
            app.after(200, finish)

        finish()

    app.protocol('WM_DELETE_WINDOW', close_app)
    try:
        validate_windows()
        data.mkdir(parents=True, exist_ok=True)
        mutex = acquire_mutex(data)
    except (OSError, RuntimeError) as exc:
        status.set('无法启动自动连接')
        detail.set(str(exc))
        labels['连接状态'][0].set('未启动监控后台任务')
    else:
        app.after(50, poll_ui)
        working_thread[0] = threading.Thread(target=worker, args=(data,), daemon=False)
        working_thread[0].start()
    app.mainloop()
    if 'mutex' in locals():
        ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(mutex))


if __name__ == '__main__':
    main()
