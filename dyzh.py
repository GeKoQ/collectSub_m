import yaml
import aiohttp
import asyncio
import os
import base64
from urllib.parse import urlparse
import re
import datetime
import sys
from glob import glob

# ================= 配置 =================
USER_AGENTS = [
    'meta/0.2.0.5.Meta',
    'v2rayN/7.15.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Safari/605.1.15'
]

TG_DOMAINS = ["t.me", "tx.me", "telegram.me", "tgstat.com"]

RE_URL = r"https?://[-A-Za-z0-9+&@#/%?=~_|!:,.;]+"
CHECK_URL_LIST = ['sub.789.st', 'sub.xeton.dev', 'subconverters.com', 'subapi.cmliussss.net', 'url.v1.mk']
TARGET = 'mixed'
CHECK_NODE_URL_STR = "https://{}/sub?target={}&url={}&insert=false"

# ================= 多代理设置 =================
def get_proxy_list():
    http_list = os.getenv("HTTP_PROXY", "").split(",")
    https_list = os.getenv("HTTPS_PROXY", "").split(",")
    socks5_list = os.getenv("SOCKS5_PROXY", "").split(",")
    proxies = [p for p in http_list + https_list + socks5_list if p]
    return proxies or []

PROXY_LIST = get_proxy_list()

# ================= 日志 =================
class Logger:
    def __init__(self, stream, log_file):
        self.stream = stream
        self.log_file = log_file
    def write(self, message):
        self.stream.write(message)
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(message)
    def flush(self):
        self.stream.flush()

def init_logger():
    os.makedirs("logs", exist_ok=True)
    log_file = os.path.join("logs", "log.txt")
    sys.stdout = Logger(sys.stdout, log_file)
    sys.stderr = Logger(sys.stderr, log_file)

init_logger()
print(f"\n{'='*80}\n🚀 启动任务时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n{'='*80}")

# ================= 加载配置 =================
if not os.path.exists('pool.yaml'):
    print("⚠️ 未找到 pool.yaml，程序退出。")
    sys.exit(1)

with open('pool.yaml', 'r', encoding='utf-8') as f:
    config = yaml.safe_load(f)

subscriptions = config.get('subscriptions', [])
tgchannels = config.get('tgchannels', [])

# ================= 异常保存 =================
def save_null_data(source_url, content):
    os.makedirs("pool", exist_ok=True)
    null_path = os.path.join("pool", "NULL.txt")
    try:
        with open(null_path, "a", encoding="utf-8") as f:
            f.write(f"\n{'='*80}\n来源: {source_url}\n内容片段:\n{content[:500]}\n")
    except Exception as e:
        print(f"[错误] 无法写入 NULL.txt: {e}")

def clean_null_file():
    null_path = os.path.join("pool", "NULL.txt")
    if not os.path.exists(null_path):
        return
    try:
        with open(null_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        pattern = re.compile(r'^(?!(socks5?|https?|ss|vmess|vless|trojan|hy2?|hysteria2?|tuic|anytls|sn|wireguard|shadowsocks|shadowtls)[^\s]+).*$', re.IGNORECASE)
        kept_lines = [l for l in lines if not pattern.match(l.strip())]
        with open(null_path, "w", encoding="utf-8") as f:
            f.writelines(kept_lines)
        print(f"🧹 已清理 NULL.txt，删除 {len(lines) - len(kept_lines)} 行无效内容")
    except Exception as e:
        print(f"[错误] 清理 NULL.txt 失败: {e}")

# ================= 通用写入函数 =================
def write_to_pool_and_day(proto, new_lines):
    """写入 pool 文件，并同步 Day 文件，只保存当天新增节点"""
    if not new_lines:
        return

    # --- pool 写入（全量去重） ---
    os.makedirs("pool", exist_ok=True)
    pool_path = os.path.join("pool", f"{proto}.txt")

    old_pool_lines = set()
    if os.path.exists(pool_path):
        old_pool_lines = {l.strip() for l in open(pool_path, encoding="utf-8") if l.strip()}

    merged_pool = sorted(old_pool_lines | set(new_lines))
    with open(pool_path, "w", encoding="utf-8") as f:
        f.write("\n".join(merged_pool) + "\n")

    # --- Day 写入（仅当天新增） ---
    today = datetime.datetime.now().strftime("%Y-%m-%d")
    day_dir = os.path.join("Day", today)
    os.makedirs(day_dir, exist_ok=True)
    day_path = os.path.join(day_dir, f"{proto}.txt")

    day_new_lines = sorted(set(new_lines) - old_pool_lines)
    if day_new_lines:
        with open(day_path, "w", encoding="utf-8") as f:
            f.write("\n".join(day_new_lines) + "\n")

    print(f"💾 pool/{proto}.txt 已更新 ({len(merged_pool)} 条)，Day/{today}/{proto}.txt 保存当天新增 ({len(day_new_lines)} 条)")

# ================= Telegram 抓取 =================
async def fetch_with_proxies(session, url):
    tried_proxies = PROXY_LIST + [None]
    for proxy in tried_proxies:
        for ua in USER_AGENTS:
            try:
                headers = {"User-Agent": ua}
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30), proxy=proxy) as r:
                    text = await r.text()
                    if r.status != 200:
                        print(f"⚠️ 状态码 {r.status} ({url}) 使用代理 {proxy}")
                        continue
                    if any(x in text for x in ["Just a moment", "enable JavaScript", "Cloudflare"]):
                        print(f"🚫 UA [{ua[:20]}] 被 Cloudflare 拦截 使用代理 {proxy}")
                        continue
                    return text
            except Exception as e:
                print(f"⚠️ 请求失败 UA[{ua[:20]}] 代理 {proxy} -> {e}")
                save_null_data(url, str(e))
    return ""

async def extract_sub_links(session, channel):
    all_links = []
    for domain in TG_DOMAINS:
        url = f"https://{domain}/s/{channel}"
        print(f"\n🌐 正在访问 {url}")
        html = await fetch_with_proxies(session, url)
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
            for match in matches:
                line = match.group(0).strip()
                proto = line.split("://")[0].lower()
                write_to_pool_and_day(proto, [line])
            print(f"💾 已从 {channel} 提取 {len(matches)} 条节点")

        if urls:
            print(f"🎯 在 {domain} 提取到 {len(urls)} 条订阅链接")
    return list(set(all_links))

async def process_tgchannels(session, tgchannels):
    results = await asyncio.gather(*[extract_sub_links(session, ch) for ch in tgchannels], return_exceptions=True)
    links = []
    for res in results:
        if isinstance(res, list):
            links.extend(res)
    return list(set(links))

# ================= 订阅转换 =================
async def convert_sub(session, sub_url, domain):
    api_url = CHECK_NODE_URL_STR.format(domain, TARGET, sub_url)
    tried_proxies = PROXY_LIST + [None]
    for proxy in tried_proxies:
        try:
            async with session.get(api_url, timeout=aiohttp.ClientTimeout(total=100), proxy=proxy) as response:
                status = response.status
                content = (await response.text()).strip()
                if status != 200 or "<html" in content.lower() or "error" in content.lower():
                    continue
                if len(content) % 4:
                    content += "=" * (4 - len(content) % 4)
                try:
                    decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                    return [line.strip() for line in decoded.splitlines() if line.strip()]
                except Exception as e:
                    print(f"[错误] Base64 解码失败 {api_url} -> {e}")
        except Exception as e:
            print(f"[错误] convert_sub({domain}) 出错 -> {repr(e)}")
    save_null_data(api_url, "全部代理请求失败")
    return []

async def process_subscriptions(session, subscriptions):
    tasks = [convert_sub(session, sub, dom) for sub in subscriptions for dom in CHECK_URL_LIST]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    lines = []
    for r in results:
        if isinstance(r, list):
            lines.extend(r)
    return lines

# ================= 去重函数 =================
def deduplicate_pool_files():
    os.makedirs("pool", exist_ok=True)
    files = glob("pool/*.txt")
    for file in files:
        try:
            with open(file, "r", encoding="utf-8") as f:
                lines = {l.strip() for l in f if l.strip()}
            if not lines:
                os.remove(file)
                print(f"🗑️ 已删除空文件 {file}")
                continue
            with open(file, "w", encoding="utf-8") as f:
                f.write("\n".join(sorted(lines)) + "\n")
            print(f"🧩 已去重 {file} ({len(lines)} 条)")
        except Exception as e:
            print(f"[错误] 去重 {file} 失败: {e}")

# ================= 主流程 =================
async def main():
    async with aiohttp.ClientSession() as session:
        # Telegram 抓取
        if tgchannels:
            print(f"\n📡 开始抓取 Telegram 频道（共 {len(tgchannels)} 个）")
            new_links = await process_tgchannels(session, tgchannels)
            print(f"✅ 抓取完成，共发现 {len(new_links)} 条 Telegram 链接")
        else:
            print("⚠️ tgchannels 为空，跳过抓取")
            new_links = []

        # 更新 pool.yaml
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
        config["subscriptions"] = filtered_subs
        with open("pool.yaml", "w", encoding="utf-8") as f:
            yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False)
        print(f"🧾 已更新 pool.yaml：保留 {len(filtered_subs)} 条订阅，过滤掉 {len(removed)} 条无效链接")

        # 转换订阅
        print(f"\n🔄 开始转换 {len(filtered_subs)} 条订阅...")
        proxy_lines = await process_subscriptions(session, filtered_subs)
        print(f"✅ 转换完成，共解析出 {len(proxy_lines)} 条节点")

        # Step 4 分类保存
        proxy_dict = {}
        for line in proxy_lines:
            try:
                parsed = urlparse(line)
                if parsed.scheme:
                    proxy_dict.setdefault(parsed.scheme, []).append(line)
            except Exception as e:
                save_null_data("Invalid proxy line", f"{line}\n{e}")

        for proto, lines in proxy_dict.items():
            write_to_pool_and_day(proto, lines)

        # 清理与去重
        clean_null_file()
        deduplicate_pool_files()

        print("\n✅ 全部完成！日志已保存到 logs/log.txt")

if __name__ == "__main__":
    asyncio.run(main())