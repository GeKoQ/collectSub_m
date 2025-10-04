import yaml
import aiohttp
import asyncio
import os
import base64
from urllib.parse import urlparse
import re

# ========== 全局配置 ==========

# UA 顺序尝试（从轻到重）
USER_AGENTS = [
    'meta/0.2.0.5.Meta',
    'v2rayN/7.15.0',
    # 常见浏览器 UA（最后尝试）
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Safari/605.1.15'
]

# Telegram 镜像域名（自动切换）
TG_DOMAINS = ["t.me", "telegram.me", "tgo.li", "tg.rip"]

# 链接正则
RE_URL = r"https?://[-A-Za-z0-9+&@#/%?=~_|!:,.;]+"

# ========== 加载配置文件 ==========
with open('pool.yaml', 'r', encoding='utf-8') as f:
    config = yaml.safe_load(f)

subscriptions = config.get('subscriptions', [])
tgchannels = config.get('tgchannels', [])

# ========== 保存异常数据 ==========
def save_null_data(source_url, content):
    """将异常或无效订阅数据保存到 pool/NULL.txt"""
    os.makedirs("pool", exist_ok=True)
    null_path = os.path.join("pool", "NULL.txt")
    try:
        with open(null_path, "a", encoding="utf-8") as f:
            f.write(f"\n{'='*80}\n")
            f.write(f"来源: {source_url}\n")
            f.write(f"内容片段:\n")
            f.write(content[:500] + "\n")
    except Exception as e:
        print(f"[错误] 无法写入 NULL.txt: {e}")

# ========== 抓取 Telegram 频道订阅链接（无 BeautifulSoup） ==========

async def fetch_html(session, url):
    """尝试多 UA 抓取页面 HTML"""
    for ua in USER_AGENTS:
        try:
            headers = {"User-Agent": ua}
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=20)) as r:
                if r.status == 200:
                    text = await r.text()
                    # 检测 Cloudflare 拦截
                    if any(x in text for x in ["Just a moment", "enable JavaScript", "Cloudflare"]):
                        print(f"🚫 UA [{ua[:25]}...] 被 Cloudflare 拦截，尝试下一个 UA")
                        continue
                    print(f"✅ UA 成功: {ua[:50]}...")
                    return text
                else:
                    print(f"⚠️ UA [{ua[:25]}...] 状态码: {r.status}")
        except Exception as e:
            print(f"⚠️ 请求失败 UA[{ua[:25]}]: {e}")
            save_null_data(url, str(e))
    return ""

async def extract_sub_links(session, channel):
    """从 Telegram 频道抓取订阅链接（纯正则）"""
    links = []

    for domain in TG_DOMAINS:
        url = f"https://{domain}/s/{channel}"
        print(f"\n🌐 正在访问 {url}")

        html = await fetch_html(session, url)
        if not html:
            print(f"❌ 获取失败，切换下一个镜像")
            continue

        # 用正则匹配所有链接
        urls = re.findall(RE_URL, html)
        for u in urls:
            if re.search(r'(sub|clash|v2ray|vmess|ss|trojan|subscribe)', u, re.IGNORECASE):
                # 排除 Telegram 自身和 CDN 链接
                if "t.me" not in u and "cdn-telegram" not in u:
                    links.append(u)

        if links:
            print(f"🎯 成功抓取 {len(links)} 个订阅链接")
            return list(set(links))
        else:
            print(f"❌ 未发现订阅链接，切换下一个镜像...")

    print(f"❌ 所有镜像均访问失败: {channel}")
    return []

# ========== 异步处理 Telegram 频道 ==========
async def process_tgchannels(session, tgchannels):
    tasks = [extract_sub_links(session, ch) for ch in tgchannels]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    new_links = []
    for result in results:
        if not isinstance(result, Exception):
            new_links.extend(result)
    return list(set(new_links))

# ========== 订阅转换部分 ==========
CHECK_URL_LIST = [
    'sub.789.st',
    'sub.xeton.dev',
    'subconverters.com',
    'subapi.cmliussss.net',
    'url.v1.mk'
]
target = 'mixed'
CHECK_NODE_URL_STR = "https://{}/sub?target={}&url={}&insert=false"

async def convert_sub(session, sub_url, domain):
    api_url = CHECK_NODE_URL_STR.format(domain, target, sub_url)
    try:
        async with session.get(api_url, timeout=aiohttp.ClientTimeout(total=100)) as response:
            if response.status == 200:
                content = await response.text()
                content = content.strip()
                if "<html" in content.lower() or "error" in content.lower():
                    print(f"[警告] {api_url} 返回 HTML/错误，保存到 NULL.txt。")
                    save_null_data(api_url, content)
                    return []

                # Base64 修正
                padding = len(content) % 4
                if padding:
                    content += '=' * (4 - padding)
                try:
                    decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                except Exception as e:
                    print(f"[错误] Base64 解码失败：{api_url} -> {e}")
                    save_null_data(api_url, content)
                    return []

                lines = [line.strip() for line in decoded.splitlines() if line.strip()]
                return lines
    except Exception as e:
        print(f"Error processing {api_url}: {e}")
        save_null_data(api_url, str(e))
    return []

async def process_subscriptions(session, subscriptions):
    proxy_lines = []
    tasks = []
    for sub_url in subscriptions:
        for domain in CHECK_URL_LIST:
            tasks.append(convert_sub(session, sub_url, domain))
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if not isinstance(result, Exception) and result:
            proxy_lines.extend(result)
    return proxy_lines

# ========== 主流程 ==========
async def main():
    global subscriptions
    global config

    async with aiohttp.ClientSession() as session:
        # 处理 Telegram 频道
        new_links = await process_tgchannels(session, tgchannels)

        # 更新 subscriptions
        subscriptions.extend(new_links)
        subscriptions = list(set(subscriptions))
        config['subscriptions'] = subscriptions

        with open('pool.yaml', 'w', encoding='utf-8') as f:
            yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False)

        # 创建 pool 文件夹
        os.makedirs('pool', exist_ok=True)

        # 处理订阅
        proxy_lines = await process_subscriptions(session, subscriptions)

        # 分类写入文件
        proxy_dict = {}
        for line in proxy_lines:
            try:
                parsed = urlparse(line)
                if parsed.scheme:
                    proxy_type = parsed.scheme
                    proxy_dict.setdefault(proxy_type, []).append(line)
            except Exception as e:
                print(f"[警告] 无效链接被跳过: {line[:80]}... 原因: {e}")
                save_null_data("Invalid proxy line", f"{line}\n原因: {e}")

        # 写入文件（去重 + 排序）
        for proxy_type, new_lines in proxy_dict.items():
            file_path = os.path.join('pool', f"{proxy_type}.txt")
            existing_lines = set()
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    existing_lines = set(line.strip() for line in f if line.strip())
            new_set = set(line.strip() for line in new_lines if line.strip())
            all_lines = sorted(existing_lines.union(new_set))
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(all_lines) + '\n')

if __name__ == "__main__":
    asyncio.run(main())
