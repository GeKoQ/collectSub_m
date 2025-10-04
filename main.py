import asyncio
import aiohttp
import re
import yaml
import os
import base64
from urllib.parse import quote, unquote
from tqdm import tqdm
from loguru import logger
import json  # 新增：用于可能的 JSON 解析

# 全局配置（保持原样）
RE_URL = r"https?://[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]"
CHECK_NODE_URL_STR = "https://{}/sub?target={}&url={}&insert=false&config=config%2FACL4SSR.ini"
CHECK_URL_LIST = ['api.dler.io', 'sub.xeton.dev', 'sub.id9.cc', 'sub.maoxiongnet.com']

# 修改：User-Agent 列表，顺序测试
USER_AGENTS = [
    'v2rayNG/1.10.23',
    'NekoBox/Android/1.4.0(Prefer ClashMeta Format)',
    'sing-box',
    'ClashForWindows',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0'
]

# -------------------------------
# 配置文件操作（保持原样）
# -------------------------------
def load_yaml_config(path_yaml):
    """读取 YAML 配置文件，如文件不存在则返回默认结构"""
    if os.path.exists(path_yaml):
        with open(path_yaml, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
    else:
        config = {
            "机场订阅": [],
            "clash订阅": [],
            "v2订阅": [],
            "开心玩耍": [],
            "tgchannel": []
        }
    return config

def save_yaml_config(config, path_yaml):
    """保存配置到 YAML 文件"""
    with open(path_yaml, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True)

def get_config_channels(config_file='config.yaml'):
    """
    从配置文件中获取 Telegram 频道链接，
    将类似 https://t.me/univstar 转换为 https://t.me/s/univstar 格式
    """
    config = load_yaml_config(config_file)
    tgchannels = config.get('tgchannel', [])
    new_list = []
    for url in tgchannels:
        parts = url.strip().split('/')
        if parts:
            channel_id = parts[-1]
            new_list.append(f'https://t.me/s/{channel_id}')
    return new_list

# -------------------------------
# 异步 HTTP 请求辅助函数（修改：顺序尝试多个 User-Agent）
# -------------------------------
async def fetch_content(url, session, method='GET', headers=None, timeout=15):
    """获取指定 URL 的文本内容，顺序尝试 User-Agent"""
    base_headers = {
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate'
    }
    if headers:
        base_headers.update(headers)
    
    for ua_index, user_agent in enumerate(USER_AGENTS):
        request_headers = base_headers.copy()
        request_headers['User-Agent'] = user_agent
        
        try:
            async with session.request(method, url, headers=request_headers, timeout=timeout) as response:
                if response.status == 200:
                    text = await response.text()
                    logger.debug(f"请求 {url} 成功，使用 UA: {user_agent} (第 {ua_index + 1} 个)")
                    return text
                else:
                    logger.warning(f"URL {url} 返回状态 {response.status}，使用 UA: {user_agent} (第 {ua_index + 1} 个)")
        except asyncio.TimeoutError:
            logger.warning(f"请求 {url} 超时，使用 UA: {user_agent} (第 {ua_index + 1} 个)")
        except asyncio.CancelledError:
            logger.warning(f"请求 {url} 被取消，使用 UA: {user_agent} (第 {ua_index + 1} 个)")
            return None
        except Exception as e:
            logger.error(f"请求 {url} 异常: {e}，使用 UA: {user_agent} (第 {ua_index + 1} 个)")
        
        # 除了最后一个，稍作延迟再试下一个
        if ua_index < len(USER_AGENTS) - 1:
            await asyncio.sleep(0.5)
    
    logger.error(f"所有 User-Agent 尝试失败: {url}")
    return None

# -------------------------------
# 新增：订阅解析函数（保持原样）
# -------------------------------
async def parse_subscription_content(content, sub_type):
    """
    解析订阅内容，根据类型提取可导入的节点链接（ss://, vmess:// 等）
    返回字典：{protocol: [links]}
    支持类型：'clash', 'v2', 'loon', 'sub' (机场，通常 base64 V2)
    """
    protocols = {
        'ss': [],
        'vmess': [],
        'trojan': [],
        'vless': [],
        'ssr': [],
        'other': []  # 其他如 hysteria 等
    }

    if not content or len(content.strip()) < 10:
        return protocols

    try:
        if sub_type == 'clash':
            # Clash YAML 解析
            config = yaml.safe_load(content)
            if 'proxies' in config:
                for proxy in config['proxies']:
                    p_type = proxy.get('type', '').lower()
                    name = proxy.get('name', 'Unnamed')
                    # 根据类型生成 share link
                    if p_type == 'ss':
                        server = proxy['server']
                        port = proxy['port']
                        method = proxy['cipher']
                        password = proxy['password']
                        link = f"ss://{quote(base64.b64encode(f'{method}:{password}@{server}:{port}'.encode()).decode())}#{quote(name)}"
                        protocols['ss'].append(link)
                    elif p_type == 'vmess':
                        # VMess JSON to link
                        v_obj = {
                            "v": "2",
                            "ps": name,
                            "add": proxy['server'],
                            "port": str(proxy['port']),
                            "id": proxy['uuid'],
                            "aid": str(proxy.get('alterId', 0)),
                            "net": proxy.get('network', 'tcp'),
                            "type": "none",
                            "host": proxy.get('ws-headers', {}).get('Host', ''),
                            "path": proxy.get('ws-path', ''),
                            "tls": proxy.get('tls', '')
                        }
                        json_str = json.dumps(v_obj)
                        link = f"vmess://{quote(base64.b64encode(json_str.encode()).decode())}"
                        protocols['vmess'].append(link)
                    elif p_type == 'trojan':
                        server = proxy['server']
                        port = proxy['port']
                        password = proxy['password']
                        link = f"trojan://{quote(password)}@{server}:{port}#{quote(name)}"
                        protocols['trojan'].append(link)
                    elif p_type == 'vless':
                        server = proxy['server']
                        port = proxy['port']
                        uuid = proxy['uuid']
                        link = f"vless://{quote(uuid)}@{server}:{port}#{quote(name)}"
                        protocols['vless'].append(link)
                    else:
                        protocols['other'].append(f"clash://{p_type}:{name}")  # 简化其他类型

        elif sub_type in ['v2', 'sub']:  # V2 和机场通常 base64 编码的链接列表
            # 尝试 base64 解码
            try:
                decoded = base64.b64decode(content.strip()).decode('utf-8', errors='ignore')
                lines = [line.strip() for line in decoded.split('\n') if line.strip()]
            except:
                lines = [line.strip() for line in content.split('\n') if line.strip()]  # 如果不是 base64，假设原始

            for line in lines:
                if line.startswith('ss://'):
                    protocols['ss'].append(line)
                elif line.startswith('vmess://'):
                    protocols['vmess'].append(line)
                elif line.startswith('trojan://'):
                    protocols['trojan'].append(line)
                elif line.startswith('vless://'):
                    protocols['vless'].append(line)
                elif line.startswith('ssr://'):
                    protocols['ssr'].append(line)
                else:
                    protocols['other'].append(line)

        elif sub_type == 'loon':
            # Loon 格式：每行 proxy = url, name 或直接 URI
            lines = [line.strip() for line in content.split('\n') if line.strip() and '=' in line]
            for line in lines:
                if line.startswith('[Proxy]'):
                    continue
                parts = line.split('=', 1)
                if len(parts) == 2:
                    url_part = parts[1].strip().strip('"')
                    if url_part.startswith('ss://'):
                        protocols['ss'].append(url_part)
                    elif url_part.startswith('vmess://'):
                        protocols['vmess'].append(url_part)
                    elif url_part.startswith('trojan://'):
                        protocols['trojan'].append(url_part)
                    elif url_part.startswith('vless://'):
                        protocols['vless'].append(url_part)
                    else:
                        protocols['other'].append(url_part)

    except Exception as e:
        logger.error(f"解析 {sub_type} 订阅内容异常: {e}")
        protocols['other'].append(content[:200])  # 保留原始片段用于调试

    # 过滤空列表
    protocols = {k: v for k, v in protocols.items() if v}
    return protocols

async def download_and_process_all_txt(all_txt_path, sub_dir='sub'):
    """
    从 all.txt 下载订阅信息到 sub/ 文件夹，按代理类型分类保存链接
    """
    if not os.path.exists(all_txt_path):
        logger.error(f"all.txt 不存在: {all_txt_path}")
        return

    # 创建 sub/ 文件夹
    os.makedirs(sub_dir, exist_ok=True)

    # 读取 all.txt 并分割部分
    with open(all_txt_path, 'r', encoding='utf-8') as f:
        content = f.read()

    sections = re.split(r'--\s*(\w+)\s*--', content)  # 分割 -- Section --
    urls_by_type = {}  # {type: [urls]}

    for i in range(1, len(sections), 2):  # 跳过空部分
        section_name = sections[i].strip().lower()
        section_content = sections[i+1].strip() if i+1 < len(sections) else ''
        urls = re.findall(RE_URL, section_content)
        if urls:
            # 映射 section 到 sub_type
            if 'sub store' in section_name:
                sub_type = 'sub'  # 机场，通常 V2 base64
            elif 'loon' in section_name:
                sub_type = 'loon'
            elif 'clash' in section_name:
                sub_type = 'clash'
            elif 'v2' in section_name:
                sub_type = 'v2'
            else:
                sub_type = 'other'
            urls_by_type[sub_type] = list(set(urls))  # 去重

    logger.info(f"从 all.txt 提取订阅类型: {urls_by_type.keys()}")

    # 并发下载和解析 - 使用单个 session
    connector = aiohttp.TCPConnector(limit=50)
    timeout = aiohttp.ClientTimeout(total=60, connect=15)  # 增加超时时间
    semaphore = asyncio.Semaphore(10)  # 降低并发数，避免 Actions 网络压力

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        async def process_single_url(url, sub_type):
            async with semaphore:
                try:
                    logger.debug(f"开始处理 URL: {url}")
                    content = await fetch_content(url, session, timeout=aiohttp.ClientTimeout(total=30))
                    if content:
                        return await parse_subscription_content(content, sub_type)
                    else:
                        logger.debug(f"URL {url} 无内容")
                    return {}
                except asyncio.CancelledError:
                    logger.warning(f"Task for {url} was cancelled")
                    return {}
                except Exception as e:
                    logger.error(f"Error processing {url}: {e}")
                    return {}

        all_protocols = {p: [] for p in ['ss', 'vmess', 'trojan', 'vless', 'ssr', 'other']}

        for sub_type, urls in urls_by_type.items():
            logger.info(f"处理 {sub_type} 类型: {len(urls)} 个 URL")
            tasks = [process_single_url(url, sub_type) for url in urls]
            completed = 0
            for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc=f"解析{sub_type}"):
                try:
                    protocols = await coro
                    for proto, links in protocols.items():
                        all_protocols[proto].extend(links)
                    completed += 1
                except asyncio.CancelledError:
                    logger.warning(f"as_completed for {sub_type} was cancelled")
                except Exception as e:
                    logger.error(f"Error in as_completed for {sub_type}: {e}")
                    completed += 1
            logger.info(f"{sub_type} 处理完成: {completed}/{len(urls)}")

        # 保存到文件
        for proto, links in all_protocols.items():
            unique_links = sorted(set(links))
            if unique_links:
                file_path = os.path.join(sub_dir, f"{proto}_links.txt")
                # 修改：追加模式 ('a')，并处理首次写入
                with open(file_path, 'a', encoding='utf-8') as f:
                   if os.path.getsize(file_path) == 0:  # 如果文件为空，添加标题
                       f.write(f"# {proto.upper()} Links (Updated: {asyncio.get_event_loop().time()})\n\n")
                   f.write("\n".join(unique_links) + "\n")  # 追加链接，每行一个
                logger.info(f"追加保存 {len(unique_links)} 个 {proto} 链接到 {file_path}")

# -------------------------------
# 频道抓取及订阅检查（修改：使用顺序 User-Agent）
# -------------------------------
async def get_channel_urls(channel_url, session):
    """从 Telegram 频道页面抓取所有订阅链接，并过滤无关链接"""
    content = await fetch_content(channel_url, session)
    if content:
        # 提取所有 URL，并排除包含“//t.me/”或“cdn-telegram.org”的链接
        all_urls = re.findall(RE_URL, content)
        filtered = [u for u in all_urls if "//t.me/" not in u and "cdn-telegram.org" not in u]
        logger.info(f"从 {channel_url} 提取 {len(filtered)} 个链接")
        return filtered
    else:
        logger.warning(f"无法获取 {channel_url} 的内容")
        return []

async def sub_check(url, session):
    """
    改进的订阅检查函数：
      - 判断响应头中的 subscription-userinfo 用于机场订阅
      - 判断内容中是否包含 'proxies:' 判定 clash 订阅
      - 尝试 base64 解码判断 v2 订阅（识别 ss://、ssr://、vmess://、trojan://、vless://）
      - 增加重试机制和更好的错误处理
    返回一个字典：{"url": ..., "type": ..., "info": ...}
    """
    base_headers = {
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate'
    }

    # 重试机制（包括 UA 尝试）
    for attempt in range(2):
        success = False
        for ua_index, user_agent in enumerate(USER_AGENTS):
            headers = base_headers.copy()
            headers['User-Agent'] = user_agent
            
            try:
                async with session.get(url, headers=headers, timeout=12) as response:
                    if response.status == 200:
                        text = await response.text()

                        # 检查内容是否为空或过短
                        if not text or len(text.strip()) < 10:
                            logger.debug(f"订阅 {url} 内容为空或过短，使用 UA: {user_agent}")
                            continue  # 尝试下一个 UA

                        result = {"url": url, "type": None, "info": None}

                        # 判断机场订阅（检查流量信息）
                        sub_info = response.headers.get('subscription-userinfo')
                        if sub_info:
                            nums = re.findall(r'\d+', sub_info)
                            if len(nums) >= 3:
                                upload, download, total = map(int, nums[:3])
                                if total > 0:  # 确保总流量大于0
                                    unused = (total - upload - download) / (1024 ** 3)
                                    if unused > 0:
                                        result["type"] = "机场订阅"
                                        result["info"] = f"可用流量: {round(unused, 2)} GB"
                                        logger.debug(f"订阅 {url} 成功 (机场)，使用 UA: {user_agent}")
                                        return result

                        # 判断 clash 订阅 - 更严格的检查
                        if "proxies:" in text and ("name:" in text or "server:" in text):
                            proxy_count = text.count("- name:")
                            if proxy_count > 0:
                                result["type"] = "clash订阅"
                                result["info"] = f"包含 {proxy_count} 个节点"
                                logger.debug(f"订阅 {url} 成功 (clash)，使用 UA: {user_agent}")
                                return result

                        # 判断 v2 订阅，通过 base64 解码检测
                        try:
                            # 检查是否可能是base64编码（更宽松的检查）
                            text_clean = text.strip().replace('\n', '').replace('\r', '')
                            if len(text_clean) > 20:
                                try:
                                    # 尝试解码
                                    decoded = base64.b64decode(text_clean).decode('utf-8', errors='ignore')
                                    protocols = ['ss://', 'ssr://', 'vmess://', 'trojan://', 'vless://']
                                    found_protocols = [proto for proto in protocols if proto in decoded]

                                    if found_protocols:
                                        node_count = sum(decoded.count(proto) for proto in found_protocols)
                                        if node_count > 0:
                                            result["type"] = "v2订阅"
                                            result["info"] = f"包含 {node_count} 个节点 (base64)"
                                            logger.debug(f"订阅 {url} 成功 (v2 base64)，使用 UA: {user_agent}")
                                            return result
                                    else:
                                        # 检查解码后是否包含配置关键字
                                        config_keywords = ['server', 'port', 'password', 'method', 'host', 'path']
                                        if any(keyword in decoded.lower() for keyword in config_keywords):
                                            lines = [line.strip() for line in decoded.split('\n') if line.strip()]
                                            if len(lines) > 0:
                                                result["type"] = "v2订阅"
                                                result["info"] = f"包含 {len(lines)} 行配置 (base64)"
                                                logger.debug(f"订阅 {url} 成功 (v2 config)，使用 UA: {user_agent}")
                                                return result
                                except Exception:
                                    # base64解码失败，继续其他检查
                                    pass
                        except Exception as e:
                            logger.debug(f"订阅 {url} base64检测异常: {e}，使用 UA: {user_agent}")
                            pass

                        # 检查是否是原始格式的v2订阅
                        protocols = ['ss://', 'ssr://', 'vmess://', 'trojan://', 'vless://']
                        found_protocols = [proto for proto in protocols if proto in text]
                        if found_protocols:
                            node_count = sum(text.count(proto) for proto in found_protocols)
                            if node_count > 0:
                                result["type"] = "v2订阅"
                                result["info"] = f"包含 {node_count} 个节点 (原始)"
                                logger.debug(f"订阅 {url} 成功 (v2 原始)，使用 UA: {user_agent}")
                                return result

                        # 如果内容看起来像配置但不匹配已知格式，记录调试信息
                        if len(text) > 100:
                            # 显示内容的前100个字符用于调试
                            preview = text[:100].replace('\n', '\\n').replace('\r', '\\r')
                            logger.info(f"⚠️  订阅 {url} 内容不匹配已知格式，使用 UA: {user_agent}")
                            logger.info(f"   长度: {len(text)} 字符")
                            logger.info(f"   预览: {preview}...")

                            # 检查是否可能是其他格式
                            if 'http' in text.lower() or 'server' in text.lower():
                                logger.info(f"   可能包含服务器配置，但格式未识别")

                        success = True  # 即使不匹配类型，也视为成功（避免无限重试）
                        return None

                    elif response.status in [403, 404, 410, 500]:
                        # 这些状态码通常表示永久失败
                        logger.debug(f"订阅检查 {url} 返回状态 {response.status}，使用 UA: {user_agent}")
                        continue  # 尝试下一个 UA
                    else:
                        logger.warning(f"订阅检查 {url} 返回状态 {response.status}，使用 UA: {user_agent}")
                        if ua_index < len(USER_AGENTS) - 1:
                            await asyncio.sleep(0.5)  # 延迟再试下一个 UA
                            continue
                        else:
                            return None

            except asyncio.TimeoutError:
                logger.debug(f"订阅检查 {url} 超时，使用 UA: {user_agent}，尝试 {attempt + 1}/2")
                continue  # 尝试下一个 UA
            except Exception as e:
                logger.debug(f"订阅检查 {url} 异常: {e}，使用 UA: {user_agent}，尝试 {attempt + 1}/2")
                continue  # 尝试下一个 UA

        if success:
            break  # 如果成功，跳出重试循环

        if attempt == 0:  # 第一次失败，重试整个过程
            await asyncio.sleep(1)

    return None

# -------------------------------
# 节点有效性检测（修改：添加异常处理，并顺序尝试 User-Agent）
# -------------------------------
async def url_check_valid(url, target, session):
    """
    改进的节点有效性检测：
    通过遍历多个检测入口检查订阅节点有效性，
    不仅检查状态码，还验证返回内容的有效性。
    """
    encoded_url = quote(url, safe='')

    for check_base in CHECK_URL_LIST:
        success = False
        for ua_index, user_agent in enumerate(USER_AGENTS):
            headers = {'User-Agent': user_agent}
            check_url = CHECK_NODE_URL_STR.format(check_base, target, encoded_url)
            try:
                async with session.get(check_url, headers=headers, timeout=20) as resp:
                    if resp.status == 200:
                        content = await resp.text()

                        # 检查返回内容是否有效
                        if not content or len(content.strip()) < 50:
                            logger.debug(f"节点检测 {url} 在 {check_base} 返回内容过短，使用 UA: {user_agent}")
                            continue  # 尝试下一个 UA

                        # 根据目标类型验证内容
                        if target == "clash":
                            if "proxies:" in content and ("name:" in content or "server:" in content):
                                proxy_count = content.count("- name:")
                                if proxy_count > 0:
                                    logger.debug(f"节点检测 {url} 在 {check_base} 成功，包含 {proxy_count} 个节点，使用 UA: {user_agent}")
                                    return url
                        elif target == "loon":
                            # Loon格式通常包含[Proxy]段落
                            if "[Proxy]" in content or "=" in content:
                                logger.debug(f"节点检测 {url} 在 {check_base} 成功 (Loon格式)，使用 UA: {user_agent}")
                                return url
                        elif target == "v2ray":
                            # V2Ray格式可能是JSON或其他格式
                            if len(content.strip()) > 100:  # 基本长度检查
                                logger.debug(f"节点检测 {url} 在 {check_base} 成功 (V2Ray格式)，使用 UA: {user_agent}")
                                return url
                        else:
                            # 其他格式，基本长度检查
                            if len(content.strip()) > 100:
                                logger.debug(f"节点检测 {url} 在 {check_base} 成功，使用 UA: {user_agent}")
                                return url

                        logger.debug(f"节点检测 {url} 在 {check_base} 内容格式不匹配，使用 UA: {user_agent}")
                        success = True  # 视为成功，继续下一个检测点
                        break  # 跳出 UA 循环

                    else:
                        logger.debug(f"节点检测 {url} 在 {check_base} 返回状态 {resp.status}，使用 UA: {user_agent}")
                        if ua_index < len(USER_AGENTS) - 1:
                            await asyncio.sleep(0.5)
                            continue
                        else:
                            break  # UA 用完，尝试下一个 check_base

            except asyncio.TimeoutError:
                logger.debug(f"节点检测 {url} 在 {check_base} 超时，使用 UA: {user_agent}")
                continue  # 尝试下一个 UA
            except asyncio.CancelledError:
                logger.debug(f"节点检测 {url} 在 {check_base} 被取消，使用 UA: {user_agent}")
                return None
            except Exception as e:
                logger.debug(f"节点检测 {url} 在 {check_base} 异常: {e}，使用 UA: {user_agent}")
                continue  # 尝试下一个 UA

        if success:
            break  # 如果成功，跳出 check_base 循环

    logger.debug(f"节点检测 {url} 在所有检测点都失败")
    return None

# -------------------------------
# 主流程：更新订阅与合并（保持原样，但 main 中添加新步骤）
# -------------------------------
async def update_today_sub(session):
    """
    从 Telegram 频道获取最新订阅链接，
    返回一个去重后的 URL 列表
    """
    tg_channels = get_config_channels('config.yaml')
    all_urls = []
    for channel in tg_channels:
        urls = await get_channel_urls(channel, session)
        all_urls.extend(urls)
    return list(set(all_urls))

async def check_subscriptions(urls):
    """
    异步检查所有订阅链接的有效性，
    返回检查结果列表，每个结果为字典 {url, type, info}
    """
    if not urls:
        return []

    results = []
    # 创建连接器，限制并发连接数
    connector = aiohttp.TCPConnector(
        limit=100,
        limit_per_host=20,
        ttl_dns_cache=300,
        use_dns_cache=True,
    )

    timeout = aiohttp.ClientTimeout(total=30, connect=10)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        # 使用信号量限制并发数
        semaphore = asyncio.Semaphore(50)

        async def check_single(url):
            async with semaphore:
                return await sub_check(url, session)

        tasks = [check_single(url) for url in urls]
        for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="订阅筛选"):
            try:
                res = await coro
                if res:
                    results.append(res)
            except Exception as e:
                logger.error(f"Error in check_subscriptions: {e}")

    return results

async def check_nodes(urls, target, session):
    """
    异步检查每个订阅节点的有效性，
    返回检测有效的节点 URL 列表
    """
    if not urls:
        return []

    valid_urls = []
    # 使用信号量限制并发数
    semaphore = asyncio.Semaphore(20)  # 节点检测并发数较低，避免被封

    async def check_single_node(url):
        async with semaphore:
            return await url_check_valid(url, target, session)

    tasks = [check_single_node(url) for url in urls]
    for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc=f"检测{target}节点"):
        try:
            res = await coro
            if res:
                valid_urls.append(res)
        except Exception as e:
            logger.error(f"Error in check_nodes: {e}")

    return valid_urls

def write_url_list(url_list, file_path):
    """将 URL 列表写入文本文件"""
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(url_list))
    logger.info(f"已保存 {len(url_list)} 个链接到 {file_path}")

def merge_files_to_all_txt(sub_store_file, loon_file, clash_file, v2_file, all_file):
    """将多个配置文件合并到 all.txt"""
    merged_content = []
    
    # 添加 Sub Store 内容
    if os.path.exists(sub_store_file):
        with open(sub_store_file, 'r', encoding='utf-8') as f:
            sub_content = f.read()
        merged_content.append("-- Sub Store --")
        merged_content.append(sub_content)
        merged_content.append("")
    
    # 添加 Loon 内容
    if os.path.exists(loon_file):
        with open(loon_file, 'r', encoding='utf-8') as f:
            loon_content = f.read().strip()
        if loon_content:
            merged_content.append("-- Loon --")
            merged_content.append(loon_content)
            merged_content.append("")
    
    # 添加 Clash 内容
    if os.path.exists(clash_file):
        with open(clash_file, 'r', encoding='utf-8') as f:
            clash_content = f.read().strip()
        if clash_content:
            merged_content.append("-- Clash --")
            merged_content.append(clash_content)
            merged_content.append("")
    
    # 添加 V2 内容
    if os.path.exists(v2_file):
        with open(v2_file, 'r', encoding='utf-8') as f:
            v2_content = f.read().strip()
        if v2_content:
            merged_content.append("-- V2 --")
            merged_content.append(v2_content)
            merged_content.append("")
    
    # 写入 all.txt
    with open(all_file, 'w', encoding='utf-8') as f:
        f.write("\n".join(merged_content))
    logger.info(f"📄 已合并生成: {all_file}")

# -------------------------------
# 主函数入口（修改：添加第八步处理 all.txt）
# -------------------------------
async def validate_existing_subscriptions(config, session):
    """验证现有订阅的有效性，移除失效订阅"""
    logger.info("🔍 开始验证现有订阅的有效性...")

    all_existing_urls = []

    # 提取所有现有订阅URL
    for category in ["机场订阅", "clash订阅", "v2订阅"]:
        for item in config.get(category, []):
            if isinstance(item, str) and item.strip():
                all_existing_urls.append((item.strip(), category))

    # 从开心玩耍中提取URL
    for item in config.get("开心玩耍", []):
        if isinstance(item, str) and item.strip():
            url_match = re.search(r'https?://[^\s]+', item)
            if url_match:
                all_existing_urls.append((url_match.group(), "开心玩耍"))

    if not all_existing_urls:
        logger.info("📝 没有现有订阅需要验证")
        return {"机场订阅": [], "clash订阅": [], "v2订阅": [], "开心玩耍": []}

    logger.info(f"📊 需要验证 {len(all_existing_urls)} 个现有订阅")

    # 使用信号量限制并发
    semaphore = asyncio.Semaphore(30)

    async def check_single_existing(url_info):
        url, category = url_info
        async with semaphore:
            result = await sub_check(url, session)
            return (url, category, result)

    valid_existing = {"机场订阅": [], "clash订阅": [], "v2订阅": [], "开心玩耍": []}
    tasks = [check_single_existing(url_info) for url_info in all_existing_urls]

    for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="验证现有订阅"):
        try:
            url, category, result = await coro
            if result:
                if result["type"] == "机场订阅":
                    valid_existing["机场订阅"].append(url)
                    if result["info"]:
                        valid_existing["开心玩耍"].append(f'{result["info"]}\n{url}')
                elif result["type"] == "clash订阅":
                    valid_existing["clash订阅"].append(url)
                elif result["type"] == "v2订阅":
                    valid_existing["v2订阅"].append(url)
        except Exception as e:
            logger.error(f"Error in validate_existing: {e}")

    # 统计验证结果
    total_original = len(all_existing_urls)
    total_valid = sum(len(valid_existing[cat]) for cat in ["机场订阅", "clash订阅", "v2订阅"])

    logger.info(f"✅ 现有订阅验证完成: {total_original} → {total_valid} (有效率: {total_valid/total_original*100:.1f}%)")

    return valid_existing

async def main():
    config_path = 'config.yaml'

    logger.info("🚀 开始订阅管理流程...")
    logger.info("=" * 60)

    # 加载现有配置
    config = load_yaml_config(config_path)

    # 统计原始数据
    original_counts = {}
    for category in ["机场订阅", "clash订阅", "v2订阅", "开心玩耍"]:
        original_counts[category] = len(config.get(category, []))

    logger.info("📊 原始配置统计:")
    for category, count in original_counts.items():
        logger.info(f"   {category}: {count:,} 个")

    # 创建优化的会话
    connector = aiohttp.TCPConnector(
        limit=100,
        limit_per_host=20,
        ttl_dns_cache=300,
        use_dns_cache=True,
    )
    timeout = aiohttp.ClientTimeout(total=30, connect=10)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:

        # 第一步：验证现有订阅
        logger.info("\n🔍 第一步：验证现有订阅")
        logger.info("-" * 40)
        valid_existing = await validate_existing_subscriptions(config, session)

        # 第二步：获取新的订阅链接
        logger.info("\n📡 第二步：获取新的订阅链接")
        logger.info("-" * 40)
        today_urls = await update_today_sub(session)
        logger.info(f"📥 从 Telegram 频道获得 {len(today_urls)} 个新链接")

        # 第三步：检查新订阅的有效性
        logger.info("\n🔍 第三步：检查新订阅有效性")
        logger.info("-" * 40)
        new_results = await check_subscriptions(today_urls)

        # 分类新订阅
        new_subs = [res["url"] for res in new_results if res and res["type"] == "机场订阅"]
        new_clash = [res["url"] for res in new_results if res and res["type"] == "clash订阅"]
        new_v2 = [res["url"] for res in new_results if res and res["type"] == "v2订阅"]
        new_play = [f'{res["info"]} {res["url"]}' for res in new_results 
                   if res and res["type"] == "机场订阅" and res["info"]]

        logger.info(f"✅ 新增有效订阅: 机场{len(new_subs)}个, clash{len(new_clash)}个, v2{len(new_v2)}个")

        # 第四步：合并有效订阅
        logger.info("\n🔄 第四步：合并有效订阅")
        logger.info("-" * 40)

        final_config = {
            "机场订阅": sorted(list(set(valid_existing["机场订阅"] + new_subs))),
            "clash订阅": sorted(list(set(valid_existing["clash订阅"] + new_clash))),
            "v2订阅": sorted(list(set(valid_existing["v2订阅"] + new_v2))),
            "开心玩耍": sorted(list(set(valid_existing["开心玩耍"] + new_play))),
            "tgchannel": config.get("tgchannel", [])  # 保留频道配置
        }

        # 统计最终结果
        logger.info("📈 最终统计对比:")
        total_original = sum(original_counts.values())
        total_final = sum(len(final_config[cat]) for cat in ["机场订阅", "clash订阅", "v2订阅", "开心玩耍"])

        for category in ["机场订阅", "clash订阅", "v2订阅", "开心玩耍"]:
            original = original_counts[category]
            final = len(final_config[category])
            change = final - original
            change_str = f"(+{change})" if change > 0 else f"({change})" if change < 0 else "(=)"
            logger.info(f"   {category}: {original:,} → {final:,} {change_str}")

        logger.info(f"📊 总体: {total_original:,} → {total_final:,} "
                   f"(清理率: {(total_original-total_final)/total_original*100:.1f}%)")

        # 保存更新后的配置
        save_yaml_config(final_config, config_path)
        logger.info("💾 配置文件已更新")

        # 第五步：生成输出文件
        logger.info("\n📝 第五步：生成输出文件")
        logger.info("-" * 40)

        # 写入订阅存储文件
        sub_store_file = config_path.replace('.yaml', '_sub_store.txt')
        content = ("-- play_list --\n\n" + 
                  "\n".join(final_config["开心玩耍"]) + 
                  "\n\n-- sub_list --\n\n" + 
                  "\n".join(final_config["机场订阅"]))
        with open(sub_store_file, 'w', encoding='utf-8') as f:
            f.write(content)
        logger.info(f"📄 订阅存储文件已保存: {sub_store_file}")

        # 第六步：检测节点有效性
        logger.info("\n🔍 第六步：检测节点有效性")
        logger.info("-" * 40)

        loon_file = None
        clash_file = None
        v2_file = None

        # 检测机场订阅节点
        if final_config["机场订阅"]:
            valid_loon = await check_nodes(final_config["机场订阅"], "loon", session)
            loon_file = config_path.replace('.yaml', '_loon.txt')
            write_url_list(valid_loon, loon_file)

        # 检测clash订阅节点
        if final_config["clash订阅"]:
            valid_clash = await check_nodes(final_config["clash订阅"], "clash", session)
            clash_file = config_path.replace('.yaml', '_clash.txt')
            write_url_list(valid_clash, clash_file)

        # 检测v2订阅节点
        if final_config["v2订阅"]:
            valid_v2 = await check_nodes(final_config["v2订阅"], "v2ray", session)
            v2_file = config_path.replace('.yaml', '_v2.txt')
            write_url_list(valid_v2, v2_file)

        # 第七步：合并文件到 all.txt
        logger.info("\n🔗 第七步：合并文件到 all.txt")
        logger.info("-" * 40)
        all_file = config_path.replace('.yaml', '_all.txt')
        merge_files_to_all_txt(sub_store_file, loon_file, clash_file, v2_file, all_file)

        # 第八步：下载 all.txt 中的订阅到 sub/ 文件夹，按类型分类
        logger.info("\n📥 第八步：下载并分类订阅链接到 sub/ 文件夹")
        logger.info("-" * 40)
        try:
            await download_and_process_all_txt(all_file)
        except Exception as e:
            logger.error(f"Error in download_and_process_all_txt: {e}")
            logger.info("继续流程，尽管下载步骤失败")

    logger.info("\n🎉 订阅管理流程完成！")
    logger.info("=" * 60)




if __name__ == '__main__':
    asyncio.run(main())