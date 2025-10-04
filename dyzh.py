import yaml
import aiohttp
import asyncio
from bs4 import BeautifulSoup
import os
import base64
from urllib.parse import urlparse
import re
import logging

# ----------------------
# 基础配置
# ----------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

RE_URL = r'https?://[^\s"\']+'  # 简单匹配所有 http(s) 链接

# ----------------------
# 工具函数
# ----------------------
def load_yaml_config(config_file='pool.yaml'):
    with open(config_file, 'r') as f:
        return yaml.safe_load(f)

async def fetch_content(url, session):
    """异步获取页面 HTML 内容"""
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0'}
    try:
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=100)) as response:
            if response.status == 200:
                return await response.text()
            else:
                logger.warning(f"获取 {url} 状态码异常: {response.status}")
    except Exception as e:
        logger.error(f"请求 {url} 失败: {e}")
    return None

# ----------------------
# 新增函数（你提供的两段）
# ----------------------
async def get_channel_urls(channel_url, session):
    """从 Telegram 频道页面抓取所有订阅链接，并过滤无关链接"""
    content = await fetch_content(channel_url, session)
    if content:
        all_urls = re.findall(RE_URL, content)
        filtered = [u for u in all_urls if "//t.me/" not in u and "cdn-telegram.org" not in u]
        logger.info(f"从 {channel_url} 提取 {len(filtered)} 个链接")
        return filtered
    else:
        logger.warning(f"无法获取 {channel_url} 的内容")
        return []


def get_config_channels(config_file='pool.yaml'):
    """
    从配置文件中获取 Telegram 频道链接，
    将类似 https://t.me/univstar 转换为 https://t.me/s/univstar 格式
    """
    config = load_yaml_config(config_file)
    tgchannels = config.get('tgchannels', [])
    new_list = []
    for url in tgchannels:
        parts = url.strip().split('/')
        if parts:
            channel_id = parts[-1]
            new_list.append(f'https://t.me/s/{channel_id}')
    return new_list

# ----------------------
# 异步任务区
# ----------------------
async def process_tgchannels(session, tgchannels):
    """批量抓取 Telegram 频道中的订阅链接"""
    tasks = [get_channel_urls(channel, session) for channel in tgchannels]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    new_links = []
    for result in results:
        if isinstance(result, list):
            new_links.extend(result)
    return list(set(new_links))

# ----------------------
# 订阅转换逻辑（原样保留）
# ----------------------
CHECK_URL_LIST = ['sub.789.st', 'sub.xeton.dev', 'subconverters.com', 'subapi.cmliussss.net', 'url.v1.mk']
target = 'mixed'
CHECK_NODE_URL_STR = "https://{}/sub?target={}&url={}&insert=false"

async def convert_sub(session, sub_url, domain):
    api_url = CHECK_NODE_URL_STR.format(domain, target, sub_url)
    try:
        async with session.get(api_url, timeout=aiohttp.ClientTimeout(total=100)) as response:
            if response.status == 200:
                content = await response.text()
                padding = len(content) % 4
                if padding:
                    content += '=' * (4 - padding)
                decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                lines = [line.strip() for line in decoded.splitlines() if line.strip()]
                return lines
    except Exception as e:
        logger.error(f"Error processing {api_url}: {e}")
    return []

async def process_subscriptions(session, subscriptions):
    proxy_lines = []
    tasks = []
    for sub_url in subscriptions:
        for domain in CHECK_URL_LIST:
            tasks.append(convert_sub(session, sub_url, domain))
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, list):
            proxy_lines.extend(result)
    return proxy_lines

# ----------------------
# 主逻辑入口
# ----------------------
async def main():
    logger.info("启动订阅抓取任务...")
    config = load_yaml_config()
    subscriptions = config.get('subscriptions', [])
    tgchannels = get_config_channels()  # 新的读取逻辑

    async with aiohttp.ClientSession() as session:
        new_links = await process_tgchannels(session, tgchannels)
        logger.info(f"共抓取到 {len(new_links)} 条新链接")

        # 合并订阅
        subscriptions = list(set(subscriptions + new_links))
        config['subscriptions'] = subscriptions

        with open('pool.yaml', 'w') as f:
            yaml.dump(config, f)
        logger.info("pool.yaml 已更新")

        os.makedirs('pool', exist_ok=True)
        proxy_lines = await process_subscriptions(session, subscriptions)

        proxy_dict = {}
        for line in proxy_lines:
            parsed = urlparse(line)
            if parsed.scheme:
                proxy_dict.setdefault(parsed.scheme, []).append(line)

        for proxy_type, new_lines in proxy_dict.items():
            file_path = os.path.join('pool', f"{proxy_type}.txt")
            existing_lines = set()
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    existing_lines = set(line.strip() for line in f if line.strip())
            all_lines = sorted(existing_lines.union(set(new_lines)))
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(all_lines) + '\n')
            logger.info(f"已写入 {len(all_lines)} 条 {proxy_type} 节点 -> {file_path}")

    logger.info("✅ 全部任务完成！")

# ----------------------
# 运行入口
# ----------------------
if __name__ == "__main__":
    asyncio.run(main())
