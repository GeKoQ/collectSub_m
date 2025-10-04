import yaml
import aiohttp
import asyncio
from bs4 import BeautifulSoup
import os
import base64
from urllib.parse import urlparse
import re

# 加载 pool.yaml 文件
with open('pool.yaml', 'r') as f:
    config = yaml.safe_load(f)

subscriptions = config.get('subscriptions', [])
tgchannels = config.get('tgchannels', [])

# 异步函数：从 Telegram 频道中提取订阅链接
async def extract_sub_links(session, channel):
    url = f"https://t.me/s/{channel}"
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
    try:
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=100)) as response:
            response.raise_for_status()
            text = await response.text()
            soup = BeautifulSoup(text, 'html.parser')
            messages = soup.find_all('div', class_='tgme_widget_message_text')
            links = []
            for msg in messages:
                for a in msg.find_all('a', href=True):
                    href = a['href']
                    if re.search(r'(sub|clash|v2ray|vmess|ss|trojan|subscribe)', href, re.IGNORECASE):
                        links.append(href)
            return links
    except Exception as e:
        print(f"Error scraping {channel}: {e}")
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

# 转换设置
CHECK_URL_LIST = ['sub.789.st', 'sub.xeton.dev', 'subconverters.com', 'subapi.cmliussss.net', 'url.v1.mk']
target = 'v2ray'
CHECK_NODE_URL_STR = "https://{}/sub?target={}&url={}&insert=false&config=config%2FACL4SSR.ini&list=true"

# 异步函数：转换订阅
async def convert_sub(session, sub_url, domain):
    api_url = CHECK_NODE_URL_STR.format(domain, target, sub_url)
    try:
        async with session.get(api_url, timeout=aiohttp.ClientTimeout(total=100)) as response:
            if response.status == 200:
                content = await response.text()
                content = content.strip()
                # 如果需要，填充 base64
                padding = len(content) % 4
                if padding:
                    content += '=' * (4 - padding)
                decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                lines = [line.strip() for line in decoded.splitlines() if line.strip()]
                return lines
    except Exception as e:
        print(f"Error processing {api_url}: {e}")
    return []

# 异步处理订阅
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

# 主异步函数
async def main():
    global subscriptions
    global config
    async with aiohttp.ClientSession() as session:
        # 处理 Telegram 频道
        new_links = await process_tgchannels(session, tgchannels)
        # 将新链接追加到现有订阅中，而不覆盖
        subscriptions.extend(new_links)
        # 去除重复项
        subscriptions = list(set(subscriptions))
        # 更新 pool.yaml 中的 'subscriptions' 键，而不覆盖其他部分
        config['subscriptions'] = subscriptions
        with open('pool.yaml', 'w') as f:
            yaml.dump(config, f)
        
        # 创建 pool 文件夹
        os.makedirs('pool', exist_ok=True)
        
        # 处理订阅
        proxy_lines = await process_subscriptions(session, subscriptions)
        
        # 按类型存储代理的字典
        proxy_dict = {}
        for line in proxy_lines:
            parsed = urlparse(line)
            if parsed.scheme:
                proxy_type = parsed.scheme
                proxy_dict.setdefault(proxy_type, []).append(line)
        
        # 写入文件
        for proxy_type, lines in proxy_dict.items():
            file_path = os.path.join('pool', f"{proxy_type}.txt")
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines) + '\n')

# 运行主函数
asyncio.run(main())