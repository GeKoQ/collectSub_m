#!/usr/bin/env python3
# dyzh.py
# Enhanced version of dyzh.py
# Features:
# - Local-first subscription parsing (base64 / Clash YAML / JS inline / JSON)
# - If local parsing fails, fall back to remote subscription conversion services
# - USER_AGENTS tried in order when downloading subscriptions (and when calling APIs)
# - Telegram channel scraping (as original)
# - Detailed logging to stdout, logs/log.txt and logs/error.log (GitHub Actions friendly)
# - Clash -> node link conversion supporting vmess/vless/ss/trojan/hysteria2/tuic

import yaml
import aiohttp
import asyncio
import os
import base64
from urllib.parse import urlparse, quote
import re
import datetime
import sys
import json
import traceback
from glob import glob

# ========== 配置 ==========
USER_AGENTS = [
    'meta/0.2.0.5.Meta',
    'v2rayN/7.15.0',
    #'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    #'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Safari/605.1.15'
]

TG_DOMAINS = [
    "t.me",
    "tx.me",
    "telegram.me",
    "tgstat.com",
]

RE_URL = r"https?://[-A-Za-z0-9+&@#/%?=~_|!:,.;]+"

CHECK_URL_LIST = [
    'sub.789.st',
    'sub.xeton.dev',
    'subconverters.com',
    'subapi.cmliussss.net',
    'url.v1.mk'
]
TARGET = 'clash'
CHECK_NODE_URL_STR = "https://{}/sub?target={}&url={}&insert=false&config=https%3A%2F%2Fraw.nameless13.com%2Fapi%2Fpublic%2Fdl%2FzKF9vFbb%2Feasy.ini"

# ========== 多代理设置 ==========
def get_proxy_list():
    http_list = os.getenv("HTTP_PROXY", "").split(",")
    https_list = os.getenv("HTTPS_PROXY", "").split(",")
    socks5_list = os.getenv("SOCKS5_PROXY", "").split(",")
    proxies = [p for p in http_list + https_list + socks5_list if p]
    # env proxies may be like http://ip:port, keep as-is for aiohttp
    return proxies or []

PROXY_LIST = get_proxy_list()

# ========== 日志系统 ==========
class Logger:
    def __init__(self, stream, log_file):
        self.stream = stream
        self.log_file = log_file
    def write(self, message):
        self.stream.write(message)
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(message)
        except Exception:
            pass
    def flush(self):
        try:
            self.stream.flush()
        except Exception:
            pass

os.makedirs("logs", exist_ok=True)
log_file = os.path.join("logs", "log.txt")
error_log_file = os.path.join("logs", "error.log")
# redirect stdout/stderr to logger while preserving console output
sys.stdout = Logger(sys.stdout, log_file)
sys.stderr = Logger(sys.stderr, error_log_file)

def log(msg):
    print(msg)

def log_error(msg):
    print(msg, file=sys.stderr)

log(f"\n{'='*80}\n🚀 启动任务时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n{'='*80}")

# ========== 加载配置 ==========
if not os.path.exists('pool.yaml'):
    log_error("⚠️ 未找到 pool.yaml，程序退出。")
    sys.exit(1)

with open('pool.yaml', 'r', encoding='utf-8') as f:
    try:
        config = yaml.safe_load(f)
    except Exception as e:
        log_error(f"⚠️ 解析 pool.yaml 失败: {e}")
        sys.exit(1)

subscriptions = config.get('subscriptions', []) or []
tgchannels = config.get('tgchannels', []) or config.get('tgchannel', []) or []

# ========== 异常保存 ==========
def save_null_data(source_url, content):
    os.makedirs("pool", exist_ok=True)
    null_path = os.path.join("pool", "NULL.txt")
    try:
        with open(null_path, "a", encoding="utf-8") as f:
            f.write(f"\n{'='*80}\n来源: {source_url}\n内容片段:\n{str(content)[:500]}\n")
    except Exception as e:
        log_error(f"[错误] 无法写入 NULL.txt: {e}")

# === 清理 NULL.txt ===
def clean_null_file():
    null_path = os.path.join("pool", "NULL.txt")
    if not os.path.exists(null_path):
        return
    try:
        with open(null_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        pattern = re.compile(
            r'^(?!(socks5?|https?|ss|vmess|vless|trojan|hy2?|hysteria2?|tuic|anytls|sn|wireguard|shadowsocks|shadowtls)[^\s]+).*$', 
            re.IGNORECASE
        )
        kept_lines = [l for l in lines if not pattern.match(l.strip())]
        with open(null_path, "w", encoding="utf-8") as f:
            f.writelines(kept_lines)
        log(f"🧹 已清理 NULL.txt，删除 {len(lines) - len(kept_lines)} 行无效内容")
    except Exception as e:
        log_error(f"[错误] 清理 NULL.txt 失败: {e}")

# ========== HTTP 请求（按 USER_AGENTS 顺序 + 可选代理） ==========
async def fetch_with_ua_and_proxies(session, url, timeout=30):
    """
    按 PROXY_LIST（若有）和 USER_AGENTS 顺序尝试请求，遇到第一个成功返回内容即停止。
    返回字符串内容或空字符串
    """
    tried = []
    proxies_to_try = PROXY_LIST + [None]
    for proxy in proxies_to_try:
        for ua in USER_AGENTS:
            headers = {"User-Agent": ua}
            try:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout), proxy=proxy) as r:
                    status = r.status
                    text = await r.text()
                    tried.append((proxy, ua, status, len(text)))
                    if status == 200 and text and len(text.strip()) > 8:
                        # basic cloudflare/string checks
                        low = text.lower()
                        if any(x in low for x in ["just a moment", "enable javascript", "cloudflare"]):
                            log(f"🚫 UA [{ua}] 被 Cloudflare 拦截 使用代理 {proxy}")
                            continue
                        log(f"✅ [{ua}] 获取成功 ({status}, {len(text)} bytes) {url} (proxy={proxy})")
                        return text
                    else:
                        log(f"⚠️ [{ua}] 返回状态 {status} / 长度 {len(text)} for {url} (proxy={proxy})")
            except Exception as e:
                log(f"⚠️ [{ua}] 请求失败 代理 {proxy} -> {e}")
                # continue to next UA/proxy
    log_error(f"🚫 全部 UA/代理 请求失败: {url} ; 尝试记录: {tried}")
    save_null_data(url, json.dumps(tried, ensure_ascii=False))
    return ""

# ========== Telegram 抓取（保持原有行为） ==========
async def extract_sub_links(session, channel):
    all_links = []
    for domain in TG_DOMAINS:
        url = f"https://{domain}/s/{channel}"
        log(f"\n🌐 正在访问 {url}")
        html = await fetch_with_ua_and_proxies(session, url)
        if not html:
            continue
        urls = re.findall(RE_URL, html)
        for u in urls:
            if re.search(r'(sub|clash|v2ray|vmess|ss|trojan|subscribe)', u, re.IGNORECASE):
                if "t.me" not in u and "cdn-telegram" not in u:
                    all_links.append(u)
        node_pattern = re.compile(
            r'^(socks5?|https?|ss|vmess|vless|trojan|hy2?|hysteria2?|tuic|anytls|sn|wireguard|shadowsocks|shadowtls)[^\s]+',
            re.IGNORECASE | re.MULTILINE
        )
        matches = list(re.finditer(node_pattern, html))
        if matches:
            os.makedirs("pool", exist_ok=True)
            for match in matches:
                line = match.group(0).strip()
                proto = line.split("://")[0].lower() if "://" in line else 'unknown'
                file_path = os.path.join("pool", f"{proto}.txt")
                old_lines = set()
                if os.path.exists(file_path):
                    old_lines = {l.strip() for l in open(file_path, encoding="utf-8") if l.strip()}
                if line not in old_lines:
                    with open(file_path, "a", encoding="utf-8") as f:
                        f.write(line + "\n")
            log(f"💾 已从 {channel} 提取 {len(matches)} 条节点，保存到 pool/ 下")
        if urls:
            log(f"🎯 在 {domain} 提取到 {len(urls)} 条订阅链接")
    return list(set(all_links))

async def process_tgchannels(session, tgchannels):
    results = await asyncio.gather(*[extract_sub_links(session, ch) for ch in tgchannels], return_exceptions=True)
    links = []
    for res in results:
        if isinstance(res, list):
            links.extend(res)
    return list(set(links))

# ========== 订阅转换（远程 API） ==========
async def convert_sub(session, sub_url, domain):
    """
    调用订阅转换 API，将订阅转为节点列表
    现在 sub_url 会先进行 URL 编码再拼入 API 调用中
    """
    encoded_url = quote(sub_url, safe='')
    api_url = CHECK_NODE_URL_STR.format(domain, TARGET, encoded_url)
    tried_proxies = PROXY_LIST + [None]
    for proxy in tried_proxies:
        try:
            async with session.get(api_url, timeout=aiohttp.ClientTimeout(total=100), proxy=proxy) as response:
                status = response.status
                content = (await response.text()).strip()
                if status != 200:
                    log_error(f"[错误] {api_url} 返回状态码 {status} 代理 {proxy}")
                    continue
                if "<html" in content.lower() or "error" in content.lower():
                    log_error(f"[错误] {api_url} 返回非期望内容 代理 {proxy}")
                    continue
                # padding base64
                if len(content) % 4:
                    content += "=" * (4 - len(content) % 4)
                try:
                    decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                    return [line.strip() for line in decoded.splitlines() if line.strip()]
                except Exception as e:
                    log_error(f"[错误] Base64 解码失败 {api_url} 代理 {proxy} -> {e}")
                    continue
        except Exception as e:
            log_error(f"[错误] convert_sub({domain}) 出错 代理 {proxy} -> {repr(e)}")
    save_null_data(api_url, "全部代理请求失败")
    return []

async def process_subscriptions_remote(session, subscriptions):
    tasks = [convert_sub(session, sub, dom) for sub in subscriptions for dom in CHECK_URL_LIST]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    lines = []
    for r in results:
        if isinstance(r, list):
            lines.extend(r)
    return lines

# ========== Clash / YAML / JS inline -> 链接 转换 ==========

def is_base64_text(s: str) -> bool:
    # heuristic: long string, contains only base64 chars and possibly newlines
    s2 = s.strip().replace('\n','')
    if len(s2) < 16:
        return False
    return re.fullmatch(r'[A-Za-z0-9+/=\\n\\r]+', s2) is not None


def decode_base64_to_lines(s: str):
    data = s.strip()
    # try padding if needed
    data = data.replace('\r', '').replace('\n', '')
    try:
        if len(data) % 4:
            data += '=' * (4 - len(data) % 4)
        decoded = base64.b64decode(data)
        try:
            text = decoded.decode('utf-8', errors='ignore')
            return [l.strip() for l in text.splitlines() if l.strip()]
        except Exception:
            return []
    except Exception:
        return []


def clash_to_links(clash_yaml_content: str):
    """
    将 Clash 配置内容（YAML 或 JS 行内格式）转换为标准节点链接
    支持 vmess / vless / trojan / ss / hysteria2 / tuic
    """
    try:
        data = yaml.safe_load(clash_yaml_content)
    except Exception as e:
        log_error(f"⚠️ 无法解析 Clash/YAML 内容: {e}")
        return []

    proxies = data.get('proxies') or data.get('Proxy') or data.get('proxy') or []
    if not proxies:
        log_error("⚠️ 未检测到 proxies 节点")
        return []

    links = []
    for p in proxies:
        try:
            t = str(p.get('type', '')).lower()
            name = p.get('name') or p.get('ps') or 'Unnamed'

            if t == 'vmess':
                node = {
                    'v': '2',
                    'ps': name,
                    'add': p.get('server') or p.get('addr') or p.get('host'),
                    'port': str(p.get('port') or p.get('remote') or ''),
                    'id': p.get('uuid') or p.get('id'),
                    'aid': str(p.get('alterId', p.get('aid', 0)) or 0),
                    'net': p.get('network', p.get('net', 'tcp')),
                    'type': p.get('type', ''),
                    'host': p.get('host', '') or p.get('ws-headers', {}).get('Host', ''),
                    'path': p.get('path', ''),
                    'tls': 'tls' if p.get('tls') or p.get('tls', False) else ''
                }
                # vmess 链接需要 base64 编码 JSON（这里用 yaml dump 保持 unicode）
                node_json = json.dumps(node, ensure_ascii=False)
                link = 'vmess://' + base64.b64encode(node_json.encode()).decode()
                links.append(link)

            elif t == 'vless':
                params = []
                if p.get('flow'): params.append(f"flow={p['flow']}")
                if p.get('network'): params.append(f"type={p['network']}")
                if p.get('reality-opts'):
                    ro = p['reality-opts']
                    if 'public-key' in ro:
                        params.append(f"pbk={ro['public-key']}")
                    if 'short-id' in ro:
                        params.append(f"sid={ro['short-id']}")
                if p.get('servername'): params.append(f"sni={p['servername']}")
                if p.get('client-fingerprint'): params.append(f"fp={p['client-fingerprint']}")
                security = 'reality' if 'reality-opts' in p else ('tls' if p.get('tls') else 'none')
                params.append(f"security={security}")
                qs = '&'.join(params)
                link = f"vless://{p.get('uuid')}@{p.get('server')}:{p.get('port')}?{qs}#{quote(str(name))}"
                links.append(link)

            elif t == 'trojan':
                qs = []
                if p.get('flow'): qs.append(f"flow={p['flow']}")
                if p.get('sni'): qs.append(f"sni={p['sni']}")
                if p.get('alpn'): qs.append(f"alpn={p['alpn']}")
                qs.append(f"security={'tls' if p.get('tls') else 'none'}")
                q = '&'.join(qs)
                link = f"trojan://{p.get('password')}@{p.get('server')}:{p.get('port')}?{q}#{quote(str(name))}"
                links.append(link)

            elif t in ('ss', 'shadowsocks'):
                method = p.get('cipher') or p.get('method')
                password = p.get('password')
                if method and password:
                    base = base64.b64encode(f"{method}:{password}".encode()).decode()
                    link = f"ss://{base}@{p.get('server')}:{p.get('port')}#{quote(str(name))}"
                    links.append(link)

            elif t in ('hysteria2', 'hy2'):
                qs = []
                if p.get('sni'): qs.append(f"sni={p['sni']}")
                if p.get('auth'): qs.append(f"auth={p['auth']}")
                if p.get('skip-cert-verify') or p.get('insecure'):
                    qs.append("insecure=1")
                q = '&'.join(qs)
                link = f"hysteria2://{p.get('password')}@{p.get('server')}:{p.get('port')}?{q}#{quote(str(name))}"
                links.append(link)

            elif t == 'tuic':
                qs = []
                if p.get('sni'): qs.append(f"sni={p['sni']}")
                if p.get('token'): qs.append(f"token={p['token']}")
                if p.get('alpn'): qs.append(f"alpn={p['alpn']}")
                q = '&'.join(qs)
                link = f"tuic://{p.get('uuid')}:{p.get('password')}@{p.get('server')}:{p.get('port')}?{q}#{quote(str(name))}"
                links.append(link)

            else:
                log(f"⚠️ 未识别的节点类型: {t} ({name})")
        except Exception as e:
            log_error(f"[错误] 转换单个 proxy 失败: {e} \n{traceback.format_exc()}")
    return links

# ========== pool 操作 ==========

def deduplicate_pool_files():
    os.makedirs("pool", exist_ok=True)
    files = glob("pool/*.txt")
    for file in files:
        try:
            with open(file, "r", encoding="utf-8") as f:
                lines = {l.strip() for l in f if l.strip()}
            if not lines:
                os.remove(file)
                log(f"🗑️ 已删除空文件 {file}")
                continue
            with open(file, "w", encoding="utf-8") as f:
                f.write("\n".join(sorted(lines)) + "\n")
            log(f"🧩 已去重 {file} ({len(lines)} 条)")
        except Exception as e:
            log_error(f"[错误] 去重 {file} 失败: {e}")


def write_to_pool_and_day(proto, new_lines):
    os.makedirs("pool", exist_ok=True)
    pool_file = os.path.join("pool", f"{proto}.txt")
    old_pool_lines = set()
    if os.path.exists(pool_file):
        old_pool_lines = {l.strip() for l in open(pool_file, encoding="utf-8") if l.strip()}
    all_pool_lines = sorted(old_pool_lines | set(new_lines))
    with open(pool_file, "w", encoding="utf-8") as f:
        f.write("\n".join(all_pool_lines) + "\n")
    today = datetime.datetime.now().strftime("%Y-%m-%d")
    day_dir = os.path.join("Day", today)
    os.makedirs(day_dir, exist_ok=True)
    day_file = os.path.join(day_dir, f"{proto}.txt")
    old_day_lines = set()
    if os.path.exists(day_file):
        old_day_lines = {l.strip() for l in open(day_file, encoding="utf-8") if l.strip()}
    new_day_lines = set(new_lines) - old_pool_lines
    all_day_lines = sorted(old_day_lines | new_day_lines)
    if new_day_lines:
        with open(day_file, "w", encoding="utf-8") as f:
            f.write("\n".join(all_day_lines) + "\n")

# ========== 本地解析逻辑（订阅优先本地解析） ==========

def extract_nodes_from_text(text: str):
    """尝试从纯文本中提取节点行（vmess:// / vless:// / ss:// / trojan:// ...）"""
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    nodes = []
    pattern = re.compile(r'^(socks5?|https?|ss|vmess|vless|trojan|hy2?|hysteria2?|tuic|anytls|sn|wireguard|shadowsocks|shadowtls)[^\s]+', re.IGNORECASE)
    for l in lines:
        if pattern.match(l):
            nodes.append(l)
    return nodes

async def parse_subscription_content_local(content: str):
    """
    优先尝试：
    1) 识别并解码 base64 -> nodes
    2) 作为 YAML/Clash -> clash_to_links
    3) 作为 JSON -> 提取 proxies / nodes
    4) 从文本中抽取节点行
    返回节点列表
    """
    # 1) base64
    if is_base64_text(content):
        lines = decode_base64_to_lines(content)
        nodes = extract_nodes_from_text('\n'.join(lines))
        if nodes:
            return nodes
    # 2) YAML/Clash
    try:
        links = clash_to_links(content)
        if links:
            return links
    except Exception:
        pass
    # 3) JSON
    try:
        data = json.loads(content)
        # common panel formats: may contain 'data' -> 'nodes' or 'proxies'
        candidates = []
        if isinstance(data, dict):
            for k in ('proxies', 'nodes', 'data'):
                if k in data:
                    candidates = data[k]
                    break
        if isinstance(candidates, list) and candidates:
            # try to convert each entry to link if possible
            out = []
            for item in candidates:
                if isinstance(item, str):
                    out.append(item)
                elif isinstance(item, dict):
                    # reuse clash_to_links by creating a fake clash wrapper
                    fake = {'proxies': [item]}
                    try:
                        out.extend(clash_to_links(yaml.safe_dump(fake, allow_unicode=True)))
                    except Exception:
                        continue
            if out:
                return out
    except Exception:
        pass
    # 4) 从文本中摘取节点行
    nodes = extract_nodes_from_text(content)
    return nodes

# ========== 主流程（local 模式 + fallback remote） ==========
async def main_local_mode():
    async with aiohttp.ClientSession() as session:
        # Step A: Telegram 频道抓取（先抓取 TG，方便新增订阅）
        if tgchannels:
            log(f"\n📡 开始抓取 Telegram 频道（共 {len(tgchannels)} 个）")
            new_links = await process_tgchannels(session, tgchannels)
            log(f"✅ 抓取完成，共发现 {len(new_links)} 条 Telegram 链接")
        else:
            log("⚠️ tgchannels 为空，跳过抓取")
            new_links = []

        # 更新 subscriptions 列表：pool.yaml + 新抓取的链接
        all_subs = list(dict.fromkeys(subscriptions + new_links))

        # local-first parse
        local_nodes = []
        failed_subs = []
        log(f"\n📦 尝试本地解析订阅（共 {len(all_subs)} 条）")
        for sub in all_subs:
            log(f"\n🔹 处理订阅: {sub}")
            content = await fetch_with_ua_and_proxies(session, sub)
            if not content:
                log_error(f"⚠️ 本地下载失败: {sub}")
                failed_subs.append(sub)
                continue
            nodes = await parse_subscription_content_local(content)
            if nodes:
                log(f"✅ 本地解析成功: {len(nodes)} 条节点 从 {sub}")
                local_nodes.extend(nodes)
            else:
                log(f"⚠️ 本地解析未提取到节点: {sub}")
                failed_subs.append(sub)

        # For failed subs, call remote conversion API (one by one)
        if failed_subs:
            log(f"\n🌐 使用订阅转换 API 处理 {len(failed_subs)} 条失败订阅...")
            remote_nodes = await process_subscriptions_remote(session, failed_subs)
            log(f"✅ 远程转换完成，共解析出 {len(remote_nodes)} 条节点")
        else:
            remote_nodes = []

        # 合并所有节点
        proxy_lines = list(dict.fromkeys(local_nodes + remote_nodes))
        log(f"\n✅ 合并节点完成，共 {len(proxy_lines)} 条（去重前）")

        # 分类保存
        proxy_dict = {}
        for line in proxy_lines:
            try:
                parsed = urlparse(line)
                if parsed.scheme:
                    proto = parsed.scheme.lower()
                    proxy_dict.setdefault(proto, []).append(line)
                else:
                    # fallback: detect vmess/vless by prefix
                    if line.startswith('vmess://'):
                        proxy_dict.setdefault('vmess', []).append(line)
                    else:
                        save_null_data('Invalid proxy line', line)
            except Exception as e:
                save_null_data('Invalid proxy line', f"{line}\n{e}")
        for proto, lines in proxy_dict.items():
            write_to_pool_and_day(proto, lines)
            log(f"💾 已写入 {proto}.txt 到 pool 并更新当天 Day 文件")

        # 清理与去重
        clean_null_file()
        deduplicate_pool_files()

        log("\n✅ 全部完成！日志已保存到 logs/log.txt")

# ========== CLI: clash 转换模式 =============

def cli_clash_mode(path_or_content):
    # 如果传入的是文件路径则读取文件，否则当作字符串内容
    if os.path.exists(path_or_content):
        with open(path_or_content, 'r', encoding='utf-8') as f:
            content = f.read()
    else:
        content = path_or_content
    # 如果是 base64 大串，先 decode
    out = []
    if is_base64_text(content):
        lines = decode_base64_to_lines(content)
        out.extend(lines)
    # 尝试 clash parse
    try:
        c2l = clash_to_links(content)
        out.extend(c2l)
    except Exception as e:
        log_error(f"[错误] clash parse failed: {e}")
    # 如果没有结果，尝试提取节点行
    if not out:
        out = extract_nodes_from_text(content)
    # 输出
    for line in out:
        print(line)
    log(f"✅ 共输出 {len(out)} 条链接")

# ========== 入口 ==========
if __name__ == '__main__':
    if len(sys.argv) >= 2 and sys.argv[1] == 'clash':
        if len(sys.argv) >= 3:
            cli_clash_mode(sys.argv[2])
        else:
            log_error('用法: python dyzh.py clash config.yaml')
        sys.exit(0)

    # local 模式（默认）
    if len(sys.argv) >= 2 and sys.argv[1] == 'local':
        asyncio.run(main_local_mode())
        sys.exit(0)

    # 默认执行原有主流程 (保留向后兼容性：抓 TG + 转换订阅全部走远程)
    async def main_default():
        async with aiohttp.ClientSession() as session:
            # process tgchannels
            if tgchannels:
                log(f"\n📡 开始抓取 Telegram 频道（共 {len(tgchannels)} 个）")
                new_links = await process_tgchannels(session, tgchannels)
                log(f"✅ 抓取完成，共发现 {len(new_links)} 条 Telegram 链接")
            else:
                new_links = []

            # update pool.yaml
            all_subs = list(set(subscriptions + new_links))
            filtered_subs, removed = [], []
            for sub in all_subs:
                if re.search(r'\b(?:[\w-]+\.)*telesco\.pe\b', sub, re.IGNORECASE):
                    removed.append(sub)
                    continue
                if re.search(r'\.(?:apk|apks|exe|jpg)$', sub, re.IGNORECASE):
                    removed.append(sub)
                    continue
                filtered_subs.append(sub)
            config['subscriptions'] = filtered_subs
            with open('pool.yaml', 'w', encoding='utf-8') as f:
                yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False)
            log(f"🧾 已更新 pool.yaml：保留 {len(filtered_subs)} 条订阅，过滤掉 {len(removed)} 条无效链接")

            # remote convert all filtered_subs
            log(f"\n🔄 开始远程转换 {len(filtered_subs)} 条订阅...")
            proxy_lines = await process_subscriptions_remote(session, filtered_subs)
            log(f"✅ 远程转换完成，共解析出 {len(proxy_lines)} 条节点")

            # classify and write
            proxy_dict = {}
            for line in proxy_lines:
                try:
                    parsed = urlparse(line)
                    if parsed.scheme:
                        proxy_dict.setdefault(parsed.scheme, []).append(line)
                except Exception as e:
                    save_null_data('Invalid proxy line', f"{line}\n{e}")
            for proto, lines in proxy_dict.items():
                write_to_pool_and_day(proto, lines)
                log(f"💾 已写入 {proto}.txt 到 pool 并更新当天 Day 文件")
            clean_null_file()
            deduplicate_pool_files()
            log("\n✅ 全部完成！日志已保存到 logs/log.txt")

    asyncio.run(main_default())
