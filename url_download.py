import requests
import base64
import os
import time
import ssl
import logging
import threading
from pathlib import Path
from typing import Tuple, List, Dict, Set
from tqdm import tqdm
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from itertools import islice
import hashlib

# 禁用SSL验证（谨慎使用，仅限调试环境）
ssl._create_default_https_context = ssl._create_unverified_context

# 常量定义
PROJECT_ROOT = Path(__file__).parent
SUB_DIR = PROJECT_ROOT / 'sub'
URL_DOWN_DIR = SUB_DIR / 'url_down'
ALL_DIR = SUB_DIR / 'ALL'
CONFIG = {
    'base64_output': ALL_DIR / 'base64.txt',
    'proxies_output': ALL_DIR / 'proxies.txt',
    'config_files': [
        PROJECT_ROOT / 'config_v2.txt',
        PROJECT_ROOT / 'config_sub_store.txt',
        PROJECT_ROOT / 'config_loon.txt',
        PROJECT_ROOT / 'config_clash.txt'
    ],
    'request_timeout': 5,
    'max_retries': 4,
    'max_concurrent_threads': 100
}

# 创建sub目录
SUB_DIR.mkdir(parents=True, exist_ok=True)

# 配置日志记录
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(SUB_DIR / 'fetch_log.log'),
        logging.StreamHandler()
    ]
)

file_access_lock = threading.Lock()

class ContentHandler:
    """处理和保存下载内容的工具类"""

    HTML_CONTENT_PATTERN = re.compile(
        r'(<!DOCTYPE html>|<html\b.*?>|<head\b.*?>|<body\b.*?>|<script\b.*?>|</html>)',
        re.IGNORECASE
    )
    CLASH_CONFIG_END_PATTERN = re.compile(r'proxy-groups:.*$', re.DOTALL)

    @staticmethod
    def remove_duplicates_from_file(file_path: Path) -> List[str]:
        """从文件中移除重复行并保持原有顺序"""
        with file_access_lock:
            if not file_path.exists():
                file_path.touch()
                logging.info(f"创建新文件: {file_path}")
                return []

            unique_lines = []
            seen_lines = set()

            with file_path.open("r", encoding="utf-8", errors="replace") as file:
                for line in file:
                    cleaned_line = line.strip()
                    if cleaned_line and cleaned_line not in seen_lines:
                        seen_lines.add(cleaned_line)
                        unique_lines.append(cleaned_line)

            with file_path.open("w", encoding="utf-8") as file:
                file.write("\n".join(unique_lines) + "\n")

            logging.info(f"已对文件 {file_path} 去重，发现 {len(unique_lines)} 条唯一行")
            return unique_lines

    @staticmethod
    def read_unique_lines_from_files(config_files: List[Path]) -> List[str]:
        """从多个配置文件中读取唯一行，不修改源文件"""
        all_lines = []
        for file_path in config_files:
            if file_path.exists():
                logging.info(f"读取配置文件: {file_path}")
                with file_path.open("r", encoding="utf-8", errors="replace") as file:
                    for line in file:
                        stripped = line.strip()
                        if stripped:
                            all_lines.append(stripped)
            else:
                logging.warning(f"配置文件不存在: {file_path}")

        seen = set()
        unique_lines = [line for line in all_lines if line not in seen and not seen.add(line)]
        logging.info(f"从所有配置文件中读取 {len(unique_lines)} 条唯一URL")
        return unique_lines

    @staticmethod
    def check_base64_encoding(text: str) -> Tuple[bool, str]:
        """验证文本是否为有效Base64编码并解码"""
        if not text or not isinstance(text, str):
            return False, ""

        cleaned_text = ''.join(text.split())
        try:
            decoded_bytes = base64.b64decode(cleaned_text, validate=True)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            if len(decoded_str) > 50 and (":" in decoded_str or "proxies" in decoded_str):
                return True, decoded_str
            return False, ""
        except Exception:
            return False, ""

    @classmethod
    def is_html_page(cls, content: str) -> bool:
        """检查内容是否为HTML页面"""
        return bool(content and cls.HTML_CONTENT_PATTERN.search(content))

    @staticmethod
    def create_output_filename(is_clash_config: bool, source_url: str, output_dir: Path) -> Path:
        """根据内容类型和URL生成唯一文件名"""
        url_hash = hashlib.md5(source_url.encode('utf-8')).hexdigest()[:8]
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        file_prefix = 'clash' if is_clash_config else 'proxies'
        filename = f'{file_prefix}_{timestamp}_{url_hash}.txt'
        logging.debug(f"生成文件名: {filename} for URL: {source_url}")
        return output_dir / filename

    @classmethod
    def clean_clash_config(cls, content: str) -> str:
        """从Clash配置中移除proxy-groups及其后面的内容"""
        return cls.CLASH_CONFIG_END_PATTERN.sub('', content).strip()

    @classmethod
    def save_downloaded_content(cls, content: str, is_clash_config: bool, source_url: str) -> bool:
        """将下载的内容保存到独立文件"""
        output_dir = URL_DOWN_DIR if is_clash_config else ALL_DIR
        output_file = cls.create_output_filename(is_clash_config, source_url, output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        if is_clash_config:
            content = cls.clean_clash_config(content)

        try:
            with file_access_lock:
                with output_file.open('w', encoding='utf-8') as file:
                    file.write(f"# 来源URL: {source_url}\n# 保存时间: {datetime.now()}\n{content}\n")
            logging.info(f"成功保存内容到 {output_file}，来源: {source_url}")

            if is_clash_config and output_file.stat().st_size < 1024:
                output_file.unlink(missing_ok=True)
                logging.info(f"文件 {output_file} 小于1KB，已删除")
                return False

            return True
        except Exception as e:
            pass
#logging.error(f"保存内容到 {output_file} 失败: {e}")
            return False

    @classmethod
    def save_decoded_base64(cls, decoded_content: str, source_url: str) -> bool:
        """保存Base64解码后的内容并去重"""
        try:
            with file_access_lock:
                with CONFIG['base64_output'].open('a', encoding='utf-8') as file:
                    file.write(f"# 来源URL: {source_url}\n# 保存时间: {datetime.now()}\n{decoded_content}\n")
            logging.info(f"Base64解码内容已保存并去重到 {CONFIG['base64_output']}，来源: {source_url}")
            return True
        except Exception as e:
            pass
#logging.error(f"保存Base64内容失败: {e}")
            return False

    @staticmethod
    def read_proxy_chunk(proxy_file: Path, chunk_size: int = 10000) -> Set[str]:
        """分块读取代理文件内容"""
        proxies = set()
        try:
            with proxy_file.open("r", encoding="utf-8") as file:
                while True:
                    chunk = set(line.strip() for line in islice(file, chunk_size)
                              if line.strip() and not line.startswith("#"))
                    if not chunk:
                        break
                    proxies.update(chunk)
        except Exception as e:
            pass
#logging.error(f"读取 {proxy_file} 失败: {e}")
        return proxies

    @staticmethod
    def combine_proxy_files(chunk_size: int = 10000):
        """优化后的代理文件合并方法，合并后去重"""
        proxy_files = list(ALL_DIR.glob("proxies_*.txt"))
        if not proxy_files:
            logging.warning("没有找到任何proxies_*.txt文件需要合并")
            return

        logging.info(f"找到 {len(proxy_files)} 个代理文件待合并: {proxy_files}")
        all_proxies = set()
        output_file = CONFIG['proxies_output']

        with ThreadPoolExecutor(max_workers=min(CONFIG['max_concurrent_threads'], len(proxy_files))) as executor:
            future_to_file = {executor.submit(ContentHandler.read_proxy_chunk, f, chunk_size): f 
                            for f in proxy_files}
            for future in tqdm(future_to_file, desc="读取代理文件中", total=len(proxy_files)):
                try:
                    proxies = future.result()
                    all_proxies.update(proxies)
                except Exception as e:
                    pass
#logging.error(f"处理 {future_to_file[future]} 失败: {e}")

        if all_proxies:
            try:
                ALL_DIR.mkdir(parents=True, exist_ok=True)
                with file_access_lock:
                    with output_file.open("a", encoding="utf-8") as file:
                        proxy_list = sorted(all_proxies)
                        for i in range(0, len(proxy_list), chunk_size):
                            file.write("\n".join(proxy_list[i:i + chunk_size]) + "\n")
                logging.info(f"合并完成，共 {len(all_proxies)} 条唯一代理，已保存到 {output_file}")
                ContentHandler.remove_duplicates_from_file(output_file)
            except Exception as e:
                pass
#logging.error(f"写入合并后的代理文件 {output_file} 失败: {e}")
        else:
            logging.warning("合并后没有找到有效的代理内容")

        with ThreadPoolExecutor(max_workers=CONFIG['max_concurrent_threads']) as executor:
            executor.map(lambda f: f.unlink(missing_ok=True), proxy_files)
        logging.info("临时代理文件已清理")

class URLDownloader:
    """从URL下载内容的工具类"""

    USER_AGENTS = [
        'v2rayNG/1.10.23',
        'NekoBox/Android/1.4.0(Prefer ClashMeta Format)',
        'sing-box',
        'ClashForWindows',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0'
    ]

    CLASH_KEYWORDS = ["proxies:", "proxy-groups:", "rules:", "port:", "socks-port:", "allow-lan:", "mode:", "log-level:"]

    @classmethod
    def download_single_url(cls, url: str) -> Tuple[str, str]:
        """下载单个URL的内容，使用多个User-Agent依次尝试"""
        http_session = requests.Session()  # 为每个URL创建新会话以避免共享状态

        for attempt in range(CONFIG['max_retries'] + 1):
            user_agent = cls.USER_AGENTS[attempt % len(cls.USER_AGENTS)]  # 循环使用User-Agent列表
            http_session.headers.update({'User-Agent': user_agent})
            #logging.info(f"尝试下载 {url} 使用User-Agent: {user_agent} (尝试 {attempt + 1})")

            try:
                response = http_session.get(url, timeout=CONFIG['request_timeout'])
                response.raise_for_status()
                content = response.text

                if ContentHandler.is_html_page(content):
                    return url, "html_discarded"

                is_base64, decoded_content = ContentHandler.check_base64_encoding(content)
                if is_base64:
                    ContentHandler.save_decoded_base64(decoded_content, url)
                    return url, "base64"

                is_clash_config = any(kw in content for kw in cls.CLASH_KEYWORDS)
                ContentHandler.save_downloaded_content(content, is_clash_config, url)
                return url, "clash" if is_clash_config else "proxy"

            except requests.HTTPError as e:
                pass
#logging.error(f"HTTP错误 {response.status_code} 获取 {url} 失败: {e}")
            except requests.Timeout:
                pass
#logging.error(f"请求超时: {url}")
            except requests.RequestException as e:
                pass
#logging.error(f"请求异常: {url}, 错误: {e}")

            if attempt < CONFIG['max_retries']:
                sleep_time = 2 ** attempt
                #logging.info(f"{url} 重试 {attempt+1}/{CONFIG['max_retries']}，等待 {sleep_time} 秒")

        return url, "failed"

    @classmethod
    def download_multiple_urls(cls, urls: List[str]) -> Dict[str, int]:
        """并发下载多个URL的内容"""
        stats = {
            "success": 0, 
            "failed": 0, 
            "html_discarded": 0, 
            "base64_processed": 0, 
            "proxies_processed": 0, 
            "clash_processed": 0
        }

        with ThreadPoolExecutor(max_workers=CONFIG['max_concurrent_threads']) as executor:
            results = list(tqdm(executor.map(cls.download_single_url, urls), 
                              total=len(urls), desc="正在下载URL内容"))

        for url, result in results:
            if result == "base64":
                stats["base64_processed"] += 1
                stats["success"] += 1
            elif result == "proxy":
                stats["proxies_processed"] += 1
                stats["success"] += 1
            elif result == "clash":
                stats["clash_processed"] += 1
                stats["success"] += 1
            elif result == "html_discarded":
                stats["html_discarded"] += 1
            elif result == "failed":
                stats["failed"] += 1

        return stats

def main():
    """主函数"""
    URL_DOWN_DIR.mkdir(parents=True, exist_ok=True)
    ALL_DIR.mkdir(parents=True, exist_ok=True)
    unique_urls = ContentHandler.read_unique_lines_from_files(CONFIG['config_files'])
    if unique_urls:
        download_stats = URLDownloader.download_multiple_urls(unique_urls)
        print("\n下载统计:", download_stats)
        ContentHandler.combine_proxy_files()
        ContentHandler.remove_duplicates_from_file(CONFIG['base64_output'])
    else:
        logging.warning("未找到有效的URL")

if __name__ == "__main__":
    main()
