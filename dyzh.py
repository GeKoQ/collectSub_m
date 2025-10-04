import yaml
import aiohttp
import asyncio
from bs4 import BeautifulSoup
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

# 加载配置文件
with open('pool.yaml', 'r') as f:
    config = yaml.safe_load(f)

subscriptions = config.get('subscriptions', [])
tgchannels = config.get('tgchannels', [])

# ========== 抓取 Telegram 频道订阅链接 ==========

async def extract_sub_links(session, channel):
    """
    从 Telegram 频道抓取订阅链接
    - 顺序尝试多个 UA
    - 遇到 Cloudflare 或超时自动切换镜像站
    """
    links = []

    for domain in TG_DOMAINS:
        url = f"https://{domain}/s/{channel}"
        print(f"\n🌐 尝试访问 {url}")

        for ua in USER_AGENTS:
            headers = {'User-Agent': ua}
            try:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=20)) as response:
                    if response.status != 200:
                        print(f"⚠️ UA [{ua[:25]}...] 返回状态码: {response.status}")
                        continue

                    text = await response.text()

                    # 检测是否被 Cloudflare 拦截
                    if "Just a moment" in text or "Cloudflare" in text or "enable JavaScript" in text:
                        print(f"🚫 UA [{ua[:25]}...] 被 Cloudflare 拦截，尝试下一个 UA")
                        continue

                    # 调试输出
                    print(f"✅ UA 成功: {ua[:60]}...")
                    print(f"🔍 内容前 200 字符: {text[:200].replace(chr(10),' ')}")

                    # 解析 HTML
                    soup = BeautifulSoup(text, 'html.parser')
                    messages = soup.find_all('div', class_='tgme_widget_message_text')

                    for msg in messages:
                        for a in msg.find_all('a', href=True):
                            href = a['href']
                            if re.search(r'(sub|clash|v2ray|vmess|ss|trojan|subscribe)', href, re.IGNORECASE):
                                links.append(href)

                    if links:
                        print(f"🎯 成功抓取 {len(links)} 个订阅链接")
                        return links  # 成功则退出循环
                    else:
                        print(f"❌ 页面加载成功但未发现订阅链接，尝试下一个 UA")

            except Exception as e:
                print(f"⚠️ 请求 {url} 失败 ({type(e).__name__}): {e}")

        print(f"🔁 {domain} 尝试失败，切换下一个镜像域名...")

    print(f"❌ 所有镜像均访问失败: {channel}")
    return []

# 异步处理 Telegram 频道
async def process_tgchannels(session, tgchannels):
    tasks = [extract_sub_links(session, channel) for channel in tgchannels]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    new_links = []
    for result in results:
        if not isinstance(result, Exception):
            new_links.extend(result)
    return new_links


# ========== 订阅转换部分（原样保留） ==========

CHECK_URL_LIST = ['sub.789.st', 'sub.xeton.dev', 'subconverters.com', 'subapi.cmliussss.net', 'url.v1.mk']
target = 'mixed'
CHECK_NODE_URL_STR = "https://{}/sub?target={}&url={}&insert=false"

async def convert_sub(session, sub_url, domain):
    api_url = CHECK_NODE_URL_STR.format(domain, target, sub_url)
    try:
        async with session.get(api_url, timeout=aiohttp.ClientTimeout(total=100)) as response:
            if response.status == 200:
                content = await response.text()
                content = content.strip()
                # Base64 修正
                padding = len(content) % 4
                if padding:
                    content += '=' * (4 - padding)
                decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                lines = [line.strip() for line in decoded.splitlines() if line.strip()]
                return lines
    except Exception as e:
        print(f"Error processing {api_url}: {e}")
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

        with open('pool.yaml', 'w') as f:
            yaml.dump(config, f)

        # 创建 pool 文件夹
        os.makedirs('pool', exist_ok=True)

        # 处理订阅
        proxy_lines = await process_subscriptions(session, subscriptions)

        # 分类写入文件
        proxy_dict = {}
        for line in proxy_lines:
            parsed = urlparse(line)
            if parsed.scheme:
                proxy_type = parsed.scheme
                proxy_dict.setdefault(proxy_type, []).append(line)

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

# 运行主函数
if __name__ == "__main__":
    asyncio.run(main())
