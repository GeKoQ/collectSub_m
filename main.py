import html
import asyncio
import aiohttp
import aiofiles
import base64
import yaml
import re
import os
import json
import logging
from typing import List, Dict, Any, Optional, Set, Tuple
from urllib.parse import urlencode, quote_plus, urlparse

# ---------------------------
# 配置（可按需修改）
# ---------------------------
POOL_DIR = "pool"
POOL_YAML_TEMPLATE = "pool.yaml"  # 用于读取 subscriptions / tgchannels
MAX_CONCURRENT_DOWNLOADS = 10
REMOTE_CONVERT_SEMAPHORE = 5  # 同时调用远端转换服务限制

USER_AGENTS = [
    "meta/0.2.0.5.Meta",
    "v2rayN/7.15.0",
]

TG_DOMAINS = ["t.me", "tx.me", "telegram.me", "tgstat.com"]

RE_URL = r"https?://[-A-Za-z0-9+&@#/%?=~_|!:,.;]+"
RE_URL_COMPILED = re.compile(RE_URL)

# 备用远程转换服务列表（用于本地解析失败的情况）
CHECK_URL_LIST = [
    "sub.789.st",
    "sub.xeton.dev",
    "subconverters.com",
    "subapi.cmliussss.net",
    "url.v1.mk",
]

TARGET = "clash"
CHECK_NODE_URL_TEMPLATE = "https://{domain}/sub?target={target}&url={url}&insert=false&config=https%3A%2F%2Fraw.nameless13.com%2Fapi%2Fpublic%2Fdl%2FzKF9vFbb%2Feasy.ini"

PROXY_LIST_ENV = os.environ.get("PROXY_LIST", "")  # 多个以逗号分隔

# 支持的协议/类型集合（全部小写）
SUPPORTED_NODE_TYPES = {
    "ss", "ssocks", "socks", "socks5", "http", "https",
    "vmess", "vless", "trojan",
    "hysteria", "hysteria2", "hy", "hy2", "tuic",
    "anytls", "sn", "snell", "wireguard", "shadowtls", "shadowsocks"
}

# 为 parse_node_line 动态生成 regex（匹配以 supported proto 开头的 URI）
_PROTO_RE = re.compile(r"^(" + r"|".join(sorted(SUPPORTED_NODE_TYPES, key=lambda x: -len(x))) + r")://(.+)$", re.I)

# 初始化日志（控制台输出）
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("subscription_processor")

# ---------------------------
# 全局用于文件锁（避免并发写入冲突）
# ---------------------------
_file_locks: Dict[str, asyncio.Lock] = {}
_file_locks_lock = asyncio.Lock()


async def get_lock_for(path: str) -> asyncio.Lock:
    """为每个文件路径创建并返回一个 asyncio.Lock（线程安全）"""
    async with _file_locks_lock:
        lock = _file_locks.get(path)
        if lock is None:
            lock = asyncio.Lock()
            _file_locks[path] = lock
        return lock


# ---------------------------
# 工具函数
# ---------------------------
def normalize_proxy(raw: str) -> str:
    """规范化 proxy 字符串：若没有 scheme，则补 http://"""
    raw = raw.strip()
    if not raw:
        return raw
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", raw):
        return raw
    # 缺少 scheme，默认用 http
    return "http://" + raw


def get_proxy_list_from_env() -> List[str]:
    if not PROXY_LIST_ENV:
        return []
    parts = [p.strip() for p in PROXY_LIST_ENV.split(",") if p.strip()]
    return [normalize_proxy(p) for p in parts]


def mask_sensitive(data: Any) -> Any:
    """对日志中可能包含敏感字段的对象做模糊处理（简单原则）。"""
    try:
        if isinstance(data, dict):
            d = {}
            for k, v in data.items():
                if k.lower() in ("password", "pass", "uuid", "token", "psk", "secret"):
                    if isinstance(v, str) and v:
                        d[k] = v[:3] + "..." + v[-3:]
                    else:
                        d[k] = "***"
                else:
                    d[k] = mask_sensitive(v)
            return d
        elif isinstance(data, list):
            return [mask_sensitive(x) for x in data]
        elif isinstance(data, str):
            # 若太长，截断显示
            if len(data) > 200:
                return data[:50] + "..." + data[-50:]
            return data
        else:
            return data
    except Exception:
        return "***"


# ---------------------------
# 网络下载（支持轮换代理与 UA、Content-Type 检查）
# ---------------------------
async def fetch_with_user_agents_and_proxies(session: aiohttp.ClientSession, url: str) -> Tuple[str, Optional[str]]:
    """
    下载 URL 内容，返回 (text, content_type)
    - 尝试不用代理、以及按 PROXY_LIST 轮换
    - 根据 Content-Type 把响应类型一并返回（小写）
    """
    proxies = get_proxy_list_from_env()
    user_agents = USER_AGENTS or ["python-httplib"]
    attempts = [None] + proxies  # None 表示不使用代理
    for proxy in attempts:
        for ua in user_agents:
            try:
                headers = {"User-Agent": ua, "Accept": "*/*"}
                timeout = aiohttp.ClientTimeout(total=30)
                conn_args = {"timeout": timeout, "headers": headers}
                if proxy:
                    conn_args["proxy"] = proxy
                async with session.get(url, **conn_args) as resp:
                    text = await resp.text(errors="ignore")
                    ct = resp.headers.get("Content-Type", "")
                    return text, ct.lower()
            except Exception as e:
                logger.debug(f"fetch error (proxy={proxy} ua={ua}) for {url}: {e}")
                await asyncio.sleep(0.2)
    logger.warning(f"无法下载 URL: {url}")
    return "", None


# ---------------------------
# Base64 识别与解码（改良）
# ---------------------------
_base64_re = re.compile(r"^[A-Za-z0-9+/=\s\r\n]+$")


def is_probably_base64(text: str) -> bool:
    """较宽松的判断：包含 Base64 字符集，且长度合理"""
    s = text.strip()
    if not s:
        return False
    # 太短肯定不是
    if len(s) < 16:
        return False
    # 判断字符集（包含换行也允许）
    return bool(_base64_re.match(s))


def try_decode_base64_whole(text: str) -> Optional[str]:
    """尝试整体解码 base64（去掉空白）"""
    try:
        compact = "".join(text.split())
        decoded = base64.b64decode(compact, validate=False)
        # 尝试 utf-8
        return decoded.decode("utf-8", errors="ignore")
    except Exception:
        return None


def try_decode_base64_per_line(text: str) -> List[str]:
    """逐行尝试把每一行当作 base64 解码，返回成功解码的行（文本）"""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # 允许 urlsafe base64 / padding 不足
        try:
            # 补齐 padding
            padding = (-len(line)) % 4
            candidate = line + ("=" * padding)
            decoded = base64.b64decode(candidate, validate=False)
            s = decoded.decode("utf-8", errors="ignore")
            if s:
                out.append(s)
        except Exception:
            # 也尝试 urlsafe
            try:
                padding = (-len(line)) % 4
                candidate = line.replace("-", "+").replace("_", "/") + ("=" * padding)
                decoded = base64.b64decode(candidate, validate=False)
                s = decoded.decode("utf-8", errors="ignore")
                if s:
                    out.append(s)
            except Exception:
                continue
    return out


# ---------------------------
# 常见格式解析器（Clash YAML proxies / JS proxies / 行级节点链接等）
# ---------------------------
def parse_clash_proxies(yaml_text: str) -> List[Dict[str, Any]]:
    """尝试把文本解析为 Clash YAML，并抽取 proxies 列表"""
    try:
        data = yaml.safe_load(yaml_text)
        if not data:
            return []
        # 常见位置为 top-level 'proxies'
        proxies = data.get("proxies")
        if isinstance(proxies, list):
            return proxies
        # 有时 proxies 在 'proxy-providers' 或其他处，尝试扫全局
        found = []
        def scan(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k == "proxies" and isinstance(v, list):
                        found.extend(v)
                    else:
                        scan(v)
            elif isinstance(obj, list):
                for item in obj:
                    scan(item)
        scan(data)
        return found
    except Exception as e:
        logger.debug(f"parse_clash_proxies 失败: {e}")
        return []


_js_proxies_re = re.compile(r"proxies\s*[:=]\s*(\[[\s\S]*?\])", re.I)


def extract_proxies_from_js(text: str) -> List[Dict[str, Any]]:
    """从简单的 JS 脚本中提取 proxies = [...] 数组（若存在）"""
    try:
        m = _js_proxies_re.search(text)
        if not m:
            return []
        arr_text = m.group(1)
        # 尝试把 JS 数组转换为 JSON：替换单引号为双引号、移除尾逗号等
        jslike = arr_text
        jslike = re.sub(r"(\w+)\s*:", r'"\1":', jslike)  # 简单键名转引号
        jslike = jslike.replace("'", '"')
        jslike = re.sub(r",\s*([}\]])", r"\1", jslike)  # 删除尾逗号
        # 解析 JSON
        objs = json.loads(jslike)
        if isinstance(objs, list):
            return objs
        return []
    except Exception as e:
        logger.debug(f"extract_proxies_from_js 失败: {e}")
        return []


# ---------------------------
# 行级节点解析（识别并标准化多协议）
# ---------------------------
_line_vmess_re = re.compile(r"^vmess://(.+)$", re.I)


def parse_node_line(line: str) -> Optional[Dict[str, Any]]:
    """
    解析单行节点链接（尽可能提取为 dict 形式）
    支持：SUPPORTED_NODE_TYPES 中列出的所有前缀。
    - 对 vmess 尝试解 base64->json
    - 其他协议保留 {"type": proto, "raw": line} 以便保存与后续处理
    """
    line = line.strip()
    if not line:
        return None
    # vmess://base64_json（优先解码）
    m = _line_vmess_re.match(line)
    if m:
        b64 = m.group(1).strip()
        try:
            padding = (-len(b64)) % 4
            b = base64.b64decode(b64 + ("=" * padding))
            j = json.loads(b.decode("utf-8", errors="ignore"))
            j["type"] = "vmess"
            return j
        except Exception:
            return {"type": "vmess", "raw": line}
    # 通用协议匹配（任何 SUPPORTED_NODE_TYPES 开头）
    m2 = _PROTO_RE.match(line)
    if m2:
        proto = m2.group(1).lower()
        # 对一些协议可以进一步尝试解析（如 ss://、ssr://）
        if proto in ("ss", "shadowsocks", "ssocks"):
            return {"type": "ss", "raw": line}
        # 其余协议先保留 raw（用户可在 YAML 中查看详情）
        return {"type": proto, "raw": line}
    # 若看起来像 JSON
    try:
        j = json.loads(line)
        if isinstance(j, dict) and j.get("type"):
            t = j.get("type")
            if isinstance(t, str) and t.lower() in SUPPORTED_NODE_TYPES:
                return j
            # 若未知 type 也接受
            return j
    except Exception:
        pass
    return None


# ---------------------------
# proxies -> 链接 及 校验（尽可能构造常见链接格式）
# ---------------------------
def proxies_dict_to_link(proxy: Dict[str, Any]) -> Optional[str]:
    """
    把 Clash 风格 proxy dict 转为标准节点链接（尽量完整校验字段），失败返回 None
    说明：对于无法安全构造为单行链接的协议，返回 None，但 proxy 会被写入 YAML。
    """
    try:
        t = (proxy.get("type") or proxy.get("protocol") or "").lower()
        if not t:
            # 有时 Clash dict 里 type 在字段 protocol 中
            t = (proxy.get("protocol") or "").lower()
        # 规范化一些同义词
        if t in ("shadowsocks",):
            t = "ss"
        if t in ("ssocks",):
            t = "socks"
        # vmess
        if t == "vmess":
            server = proxy.get("server") or proxy.get("add") or proxy.get("address")
            port = proxy.get("port")
            uuid = proxy.get("uuid") or proxy.get("id")
            name = proxy.get("name") or proxy.get("ps") or ""
            if not (server and port and uuid):
                return None
            vmess_obj = {
                "v": "2",
                "ps": name,
                "add": server,
                "port": str(port),
                "id": uuid,
                "aid": str(proxy.get("alterId", 0) or proxy.get("aid", 0)),
                "net": proxy.get("network") or "tcp",
                "type": "",
                "host": proxy.get("host", "") or "",
                "path": proxy.get("path", "") or "",
                "tls": "tls" if (proxy.get("tls") or proxy.get("skip-cert-verify")) else ""
            }
            return "vmess://" + base64.b64encode(json.dumps(vmess_obj, separators=(",", ":"), ensure_ascii=False).encode()).decode()
        # vless
        if t == "vless":
            server = proxy.get("server") or proxy.get("add")
            port = proxy.get("port")
            uuid = proxy.get("uuid") or proxy.get("id")
            name = proxy.get("name") or ""
            if not (server and port and uuid):
                return None
            q = {}
            if proxy.get("encryption"):
                q["encryption"] = proxy.get("encryption")
            network = proxy.get("network")
            if network:
                q["type"] = network
            if proxy.get("tls"):
                q["security"] = "tls"
            query = ("?" + urlencode(q)) if q else ""
            return f"vless://{uuid}@{server}:{port}{query}#{quote_plus(name)}"
        # trojan
        if t == "trojan":
            server = proxy.get("server") or proxy.get("address") or proxy.get("add")
            port = proxy.get("port")
            password = proxy.get("password") or proxy.get("pass")
            name = proxy.get("name") or ""
            if not (server and port and password):
                return None
            return f"trojan://{quote_plus(password)}@{server}:{port}#{quote_plus(name)}"
        # ss / shadowsocks
        if t == "ss":
            name = proxy.get("name") or ""
            method = proxy.get("cipher") or proxy.get("method") or proxy.get("encrypt")
            password = proxy.get("password") or proxy.get("pass")
            server = proxy.get("server") or proxy.get("address")
            port = proxy.get("port")
            if method and password and server and port:
                userinfo = f"{method}:{password}@{server}:{port}"
                return "ss://" + base64.b64encode(userinfo.encode()).decode() + "#" + quote_plus(name)
            return None
        # socks / socks5 / http / https
        if t in ("socks", "socks5", "http", "https"):
            server = proxy.get("server") or proxy.get("address") or proxy.get("add")
            port = proxy.get("port")
            user = proxy.get("username") or proxy.get("user")
            password = proxy.get("password") or proxy.get("pass")
            name = proxy.get("name") or ""
            if not (server and port):
                return None
            cred = ""
            if user and password:
                cred = quote_plus(str(user)) + ":" + quote_plus(str(password)) + "@"
            return f"{t}://{cred}{server}:{port}#{quote_plus(name)}"
        # hysteria / hysteria2 / hy / hy2
        if t in ("hysteria", "hysteria2", "hy", "hy2"):
            server = proxy.get("server") or proxy.get("address")
            port = proxy.get("port")
            password = proxy.get("password") or proxy.get("token") or proxy.get("psk")
            name = proxy.get("name") or ""
            if not (server and port):
                return None
            if password:
                return f"{t}://{quote_plus(str(password))}@{server}:{port}#{quote_plus(name)}"
            # 无 password 时仍可返回 basic URI
            return f"{t}://{server}:{port}#{quote_plus(name)}"
        # tuic
        if t == "tuic":
            server = proxy.get("server") or proxy.get("address")
            port = proxy.get("port")
            token = proxy.get("token") or proxy.get("password") or proxy.get("psk")
            name = proxy.get("name") or ""
            if not (server and port):
                return None
            if token:
                return f"tuic://{quote_plus(str(token))}@{server}:{port}#{quote_plus(name)}"
            return f"tuic://{server}:{port}#{quote_plus(name)}"
        # anytls / shadowtls / sn / snell
        if t in ("anytls", "shadowtls", "sn", "snell"):
            server = proxy.get("server") or proxy.get("address")
            port = proxy.get("port")
            password = proxy.get("password") or proxy.get("psk") or proxy.get("pass")
            name = proxy.get("name") or ""
            if not (server and port):
                return None
            if password:
                return f"{t}://{quote_plus(str(password))}@{server}:{port}#{quote_plus(name)}"
            return f"{t}://{server}:{port}#{quote_plus(name)}"
        # wireguard: 通常为一整段配置，无法简单拼成单行链接，返回 None（但保留 YAML）
        if t == "wireguard":
            return None
        # 其它不支持的类型直接返回 None（但仍会保存到 YAML）
        return None
    except Exception as e:
        logger.debug(f"proxies_dict_to_link 失败: {e} for {proxy}")
        return None


# ---------------------------
# 文件写入（合并覆盖，去重）
# ---------------------------
async def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def _make_unique_list_by_str(items: List[Any]) -> List[Any]:
    """简单根据字符串形式去重并保留顺序"""
    seen = set()
    out = []
    for it in items:
        s = json.dumps(it, sort_keys=True, ensure_ascii=False) if isinstance(it, (dict, list)) else str(it)
        if s not in seen:
            seen.add(s)
            out.append(it)
    return out


# 在文件顶部或合适位置添加（若已 import re 则无需重复）
_line_kv_pattern = re.compile(r'^\s*-\s*([A-Za-z0-9_\-]+)\s*:\s*(.+)$')

def _sanitize_yaml_text_simple(text: str) -> str:
    """
    对简单的错误行进行修复：
    - 将形如 "- key: some:with:colons ..." 的行改为 "- key: 'some:with:colons ...'"
    - 仅对简单单行键=值模式生效，复杂 YAML 结构不会尝试解析或改写。
    """
    out_lines = []
    for ln in text.splitlines():
        m = _line_kv_pattern.match(ln)
        if m:
            key = m.group(1)
            val = m.group(2).rstrip()
            # 如果值已经用引号包裹则不处理
            if (val.startswith("'") and val.endswith("'")) or (val.startswith('"') and val.endswith('"')):
                out_lines.append(ln)
            else:
                # 把单引号内部的单引号转为两个单引号以安全存入单引号包裹
                escaped = val.replace("'", "''")
                out_lines.append(f"- {key}: '{escaped}'")
        else:
            out_lines.append(ln)
    return "\n".join(out_lines)


# 把这个逻辑集成到 load_existing_yaml_list 函数：当 safe_load_all 失败时尝试 sanitize 再解析
async def load_existing_yaml_list(path: str) -> List[Dict[str, Any]]:
    """异步读取已有 YAML，返回列表（若为空则返回 []）。包含容错：解析失败时做简单修复后重试。"""
    if not os.path.exists(path):
        return []
    try:
        async with aiofiles.open(path, "r", encoding="utf-8") as f:
            text = await f.read()
            if not text.strip():
                return []
            try:
                docs = list(yaml.safe_load_all(text))
            except Exception as e:
                # 初次解析失败，尝试做简单修复并重试
                logger.warning(f"第一次尝试解析 YAML 失败 {path}: {e}. 正在对文件做简单 sanitize 后重试。")
                fixed_text = _sanitize_yaml_text_simple(text)
                try:
                    docs = list(yaml.safe_load_all(fixed_text))
                    # 如果修复成功，覆盖原文件（可选，便于后续直接正确读取）
                    try:
                        async with aiofiles.open(path, "w", encoding="utf-8") as fw:
                            await fw.write(fixed_text)
                        logger.info(f"已对 {path} 做简单修复并覆盖写入（请确认内容）。")
                    except Exception:
                        logger.debug("尝试写回已修复的 YAML 文件失败（忽略）。")
                except Exception as e2:
                    logger.warning(f"修复后仍无法解析 YAML 文件 {path}: {e2}")
                    return []
            combined = []
            for d in docs:
                if isinstance(d, list):
                    combined.extend(d)
                elif isinstance(d, dict):
                    proxies = d.get("proxies")
                    if isinstance(proxies, list):
                        combined.extend(proxies)
            return combined
    except Exception as e:
        logger.warning(f"读取 YAML 文件失败 {path}: {e}")
        return []

async def load_existing_txt_set(path: str) -> Set[str]:
    """读取已有 txt 行，返回集合"""
    s = set()
    if not os.path.exists(path):
        return s
    try:
        async with aiofiles.open(path, "r", encoding="utf-8") as f:
            async for line in f:
                line = line.strip()
                if line:
                    s.add(line)
    except Exception as e:
        logger.warning(f"读取 txt 文件失败 {path}: {e}")
    return s


# ---------- Robust normalization helper ----------
def _normalize_proxies_items(proxies_list: List[Any]) -> List[Dict[str, Any]]:
    """
    将输入条目规范化为 dict：
    - dict 保留
    - str 尝试 parse_node_line -> dict
    - 其它类型转换为 {"type":"unknown","raw": str(item)}
    """
    normalized: List[Dict[str, Any]] = []
    for item in proxies_list:
        try:
            if isinstance(item, dict):
                normalized.append(item)
            elif isinstance(item, str):
                parsed = parse_node_line(item)
                if parsed and isinstance(parsed, dict):
                    normalized.append(parsed)
                else:
                    normalized.append({"type": "unknown", "raw": item})
            else:
                # 其他类型（例如 bytes etc.），保留字符串化形式
                normalized.append({"type": "unknown", "raw": str(item)})
        except Exception as e:
            # 万一解析抛异常，仍保留字符串化的原始
            logger.debug(f"_normalize_proxies_items: parse error for item={item}: {e}")
            normalized.append({"type": "unknown", "raw": str(item)})
    return normalized


async def _save_group(proto: str, proxies: List[Dict[str, Any]]):
    """
    保存单个组：proto -> pool/{proto}.yaml, pool/{proto}.txt
    - 使用 per-file asyncio.Lock 避免并发写冲突
    - YAML: 读出已有 -> 合并去重 -> 覆盖写入
    - TXT: 只把可以生成单行链接的项追加写入（写前再读取去重）
    """
    yaml_path = os.path.join(POOL_DIR, f"{proto}.yaml")
    txt_path = os.path.join(POOL_DIR, f"{proto}.txt")
    # 使用同一把锁保护 yaml/txt 的写入
    lock = await get_lock_for(txt_path + ".lock")
    async with lock:
        # 确保目录存在
        await ensure_dir(POOL_DIR)

        # 读取现有 YAML 内容并合并
        existing_yaml = await load_existing_yaml_list(yaml_path)
        # 合并并去重（保持顺序）
        combined = existing_yaml + proxies
        combined = _make_unique_list_by_str(combined)

        try:
            async with aiofiles.open(yaml_path, "w", encoding="utf-8") as f:
                dump_text = yaml.safe_dump(combined, allow_unicode=True, sort_keys=False)
                await f.write(dump_text)
        except Exception as e:
            logger.warning(f"[{proto}] 写入 YAML 失败 {yaml_path}: {e}")

        # TXT：先读取已有，再把能转成链接的追加进去
        existing_txt = await load_existing_txt_set(txt_path)
        new_links = []
        for p in proxies:
            try:
                link = proxies_dict_to_link(p)  # 有可能返回 None
                if link and link not in existing_txt:
                    new_links.append(link)
            except Exception as e:
                logger.debug(f"[{proto}] 转换为链接失败: {e} - item={mask_sensitive(p)}")
        if new_links:
            try:
                async with aiofiles.open(txt_path, "a", encoding="utf-8") as f:
                    for l in new_links:
                        await f.write(l.strip() + "\n")
                logger.info(f"({proto}) 新增 {len(new_links)} 条节点 -> {txt_path}")
            except Exception as e:
                logger.warning(f"[{proto}] 写入 TXT 失败 {txt_path}: {e}")


async def save_proxies_grouped(proxies_list: List[Any]):
    """
    更健壮的按 type 分组并保存到 pool/{type}.yaml 与 pool/{type}.txt
    - 首先对输入条目做归一化（将字符串解析为 dict / 标记为 unknown）
    - 然后按 type 分组并并行调用 _save_group
    """
    await ensure_dir(POOL_DIR)

    # 归一化输入项：把 str -> parse_node_line 或 {"type":"unknown","raw":str}
    normalized: List[Dict[str, Any]] = []
    for item in proxies_list:
        try:
            if isinstance(item, dict):
                normalized.append(item)
            elif isinstance(item, str):
                parsed = parse_node_line(item)
                if parsed and isinstance(parsed, dict):
                    normalized.append(parsed)
                else:
                    normalized.append({"type": "unknown", "raw": item})
            else:
                normalized.append({"type": "unknown", "raw": str(item)})
        except Exception as e:
            logger.debug(f"save_proxies_grouped: 归一化单项失败，保留原始 -> {e}")
            normalized.append({"type": "unknown", "raw": str(item)})

    # 按 type 分组
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for p in normalized:
        t_raw = p.get("type") or p.get("protocol") or "unknown"
        t = (t_raw or "unknown")
        if not isinstance(t, str):
            t = str(t)
        t = t.lower().strip()

        # 规范化同义词（如 shadowsocks -> ss）
        if t in ("shadowsocks",):
            t = "ss"
        if t in ("ssocks",):
            t = "socks"

        grouped.setdefault(t, []).append(p)

    # 并行保存每个分组
    tasks = []
    for t, items in grouped.items():
        tasks.append(_save_group(t, items))
    # 使用 gather 执行所有 group 保存，并收集异常
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for i, res in enumerate(results):
        if isinstance(res, Exception):
            logger.warning(f"save_proxies_grouped: 保存分组任务第 {i} 个发生异常: {res}")
    



# ---------------------------
# 订阅内容处理逻辑
# ---------------------------
async def handle_subscription_content(session: aiohttp.ClientSession, url: str, semaphore: asyncio.Semaphore):
    """
    处理单个订阅：
    - 下载
    - 根据 Content-Type 与内容尝试解析：Clash YAML / JS proxies / 整段 base64 / 逐行 base64 / 行级节点
    - 保存结果
    """
    # 规范 URL（处理 HTML 实体与多余空白）
    url = str(url).strip()
    url = html.unescape(url)       # 将 &amp; 等 HTML 实体还原为正常字符
    # 可选：若缺少 scheme，则默认补 https://（根据你的需要启用）
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    async with semaphore:
        logger.info(f"开始处理订阅：{url}")
        text, content_type = await fetch_with_user_agents_and_proxies(session, url)
        if not text:
            logger.warning(f"订阅下载为空：{url}")
            return

        # 优先根据 Content-Type 做判断（若有）
        parsed_proxies: List[Dict[str, Any]] = []

        # 如果看起来像 YAML 或 JSON 或 content-type 指示
        if content_type and ("yaml" in content_type or "yml" in content_type or "application/x-yaml" in content_type or "text/yaml" in content_type or "application/json" in content_type):
            parsed_proxies = parse_clash_proxies(text)
            if parsed_proxies:
                logger.info(f"从 YAML/JSON 成功解析到 {len(parsed_proxies)} 个 proxies (content-type hint).")
                await save_proxies_grouped(parsed_proxies)
                return

        # 尝试整体 base64 解码（但排除明显的 HTML）
        if not (content_type and "text/html" in content_type):
            if is_probably_base64(text):
                decoded_whole = try_decode_base64_whole(text)
                if decoded_whole:
                    # 先尝试作为 Clash YAML
                    parsed_proxies = parse_clash_proxies(decoded_whole)
                    if parsed_proxies:
                        logger.info(f"整体 base64 解码并解析到 {len(parsed_proxies)} 个 proxies.")
                        await save_proxies_grouped(parsed_proxies)
                        return
                    # 若不是 YAML，尝试按行解析节点
                    lines = [ln.strip() for ln in decoded_whole.splitlines() if ln.strip()]
                    parsed = []
                    for ln in lines:
                        p = parse_node_line(ln)
                        if p:
                            parsed.append(p)
                    if parsed:
                        logger.info(f"整体 base64 解码后按行识别到 {len(parsed)} 个节点.")
                        await save_proxies_grouped(parsed)
                        return
                # 若整体失败，尝试逐行 base64 解码
                decoded_lines = try_decode_base64_per_line(text)
                if decoded_lines:
                    parsed = []
                    for dl in decoded_lines:
                        # each dl 可能包含若干行
                        for ln in dl.splitlines():
                            if ln.strip():
                                p = parse_node_line(ln.strip())
                                if p:
                                    parsed.append(p)
                    if parsed:
                        logger.info(f"逐行 base64 解码并识别到 {len(parsed)} 个节点.")
                        await save_proxies_grouped(parsed)
                        return

        # 尝试作为 Clash YAML（即便 content-type 没有提示）
        parsed_proxies = parse_clash_proxies(text)
        if parsed_proxies:
            logger.info(f"从 YAML 解析到 {len(parsed_proxies)} 个 proxies.")
            await save_proxies_grouped(parsed_proxies)
            return

        # 尝试从 JS 中提取 proxies 数组
        js_proxies = extract_proxies_from_js(text)
        if js_proxies:
            logger.info(f"从 JS 中抽取到 {len(js_proxies)} 个 proxies.")
            await save_proxies_grouped(js_proxies)
            return

        # 逐行识别节点链接/base64行
        parsed = []
        for ln in text.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            p = parse_node_line(ln)
            if p:
                parsed.append(p)
        if parsed:
            logger.info(f"逐行识别到 {len(parsed)} 个节点（文本模式）。")
            await save_proxies_grouped(parsed)
            return

        # 最后，尝试通过远端转换服务（并发受限）
        converted = await try_remote_convert(session, url)
        if converted:
            logger.info(f"远端转换服务返回 {len(converted)} 条节点。")
            await save_proxies_grouped(converted)
            return

        logger.warning(f"未识别订阅内容（既不是 YAML、也非 base64、也非行级节点）：{url}")


# ---------------------------
# 远端转换（保守调用、受限）—— 使用 CHECK_NODE_URL_TEMPLATE 构造 GET 地址
# ---------------------------
async def try_remote_convert(session: aiohttp.ClientSession, url: str) -> List[Dict[str, Any]]:
    """
    调用外部转换服务，把订阅转换成节点行
    - 使用 CHECK_NODE_URL_TEMPLATE 构造每个域的 GET 请求
    - 受 REMOTE_CONVERT_SEMAPHORE 控制并按 CHECK_URL_LIST 轮询
    - 返回解析到的 proxies dict 列表
    """
    if not CHECK_URL_LIST:
        return []
    sem = asyncio.Semaphore(REMOTE_CONVERT_SEMAPHORE)
    results: List[Dict[str, Any]] = []

    async def _call_convert(domain: str):
        async with sem:
            try:
                encoded_url = quote_plus(url)
                full = CHECK_NODE_URL_TEMPLATE.format(domain=domain, target=TARGET, url=encoded_url)
                timeout = aiohttp.ClientTimeout(total=25)
                headers = {"User-Agent": USER_AGENTS[0] if USER_AGENTS else "python-httplib"}
                async with session.get(full, timeout=timeout, headers=headers) as resp:
                    text = await resp.text(errors="ignore")
                    # 尝试把结果当作节点文本逐行解析；也可能直接是 YAML
                    parsed = parse_clash_proxies(text)
                    if parsed:
                        results.extend(parsed)
                        return
                    # 否则逐行识别
                    for ln in text.splitlines():
                        ln = ln.strip()
                        if not ln:
                            continue
                        p = parse_node_line(ln)
                        if p:
                            results.append(p)
            except Exception as e:
                logger.debug(f"远端转换失败 domain={domain}: {e}")

    tasks = [_call_convert(d) for d in CHECK_URL_LIST]
    await asyncio.gather(*tasks)
    # 去重
    unique = _make_unique_list_by_str(results)
    return unique


# ---------------------------
# Telegram 渠道抓取（提取订阅链接与内嵌节点）
# ---------------------------
async def extract_links_from_telegram(session: aiohttp.ClientSession, channel: str) -> List[str]:
    """
    从 t.me/s/{channel} 页面抓取可能的订阅链接与内嵌节点。
    - 过滤规则包括：图片/zip/rar 等、telegram.org 资源、TG 内部域、以及 BLOCKED_URL_PATTERNS 中的黑名单。
    - 返回外部链接列表（已经做了 html.unescape 与 strip）。
    """
    # 黑名单正则（大小写不敏感）。你给的两条已经包含，稍作增强以匹配 query 的情况。
    BLOCKED_URL_PATTERNS = [
        re.compile(r'\.(?:apk|apks|exe|jpg)(?:$|\?)', re.I),  # 文件扩展名（考虑 query 情况）
        re.compile(r'\b(?:[\w-]+\.)*telesco\.pe\b', re.I),     # telesco.pe 及其子域
        # 你可以在这里继续添加其它要屏蔽的模式，例如：
        # re.compile(r'\bexample-bad-domain\.com\b', re.I),
    ]

    url = channel
    try:
        text, content_type = await fetch_with_user_agents_and_proxies(session, url)
        if not text:
            return []

        found = set()
        for m in RE_URL_COMPILED.finditer(text):
            u = m.group(0)
            # 先做 HTML 实体反转与去空白
            u = html.unescape(u).strip()

            # 额外跳过非常短的或明显无效的项
            if not u or len(u) < 8:
                continue

            # 过滤图片、压缩包等（旧逻辑保留）
            if any(ext in u.lower() for ext in (".png", ".jpg", ".jpeg", ".gif", ".zip", ".rar")):
                logger.debug(f"过滤掉资源链接（扩展名）: {u}")
                continue

            # 过滤 telegram.org 静态资源
            if "telegram.org" in u:
                logger.debug(f"过滤掉 telegram.org 资源: {u}")
                continue

            # 黑名单模式匹配 -> 直接跳过
            blocked = False
            for patt in BLOCKED_URL_PATTERNS:
                try:
                    if patt.search(u):
                        logger.debug(f"Blocked by pattern {patt.pattern}: {u}")
                        blocked = True
                        break
                except Exception:
                    # 防止某些异常正则出问题
                    continue
            if blocked:
                continue

            # 若目标域是 TG 域（t.me/tx.me/...）通常是内部跳转，跳过
            try:
                parsed = urlparse(u)
                netloc = (parsed.netloc or "").lower()
                if netloc:
                    if any(netloc.endswith(d) for d in TG_DOMAINS):
                        logger.debug(f"过滤掉 TG 内部链接: {u}")
                        continue
                # 把剩下的外部链接作为可能的订阅加入
                found.add(u)
            except Exception:
                continue

        return list(found)
    except Exception as e:
        logger.debug(f"extract_links_from_telegram 错误 {channel}: {e}")
        return []



# ---------------------------
# 主流程入口
# ---------------------------
async def main():
    # 读取 pool.yaml 中的 subscriptions / tgchannels
    if not os.path.exists(POOL_YAML_TEMPLATE):
        logger.error(f"缺少 {POOL_YAML_TEMPLATE}，请先创建配置。示例内容：\nsubscriptions:\n  - https://example.com/sub\ntgchannels:\n  - https://t.me/s/example_channel")
        return

    try:
        with open(POOL_YAML_TEMPLATE, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    except Exception as e:
        logger.error(f"读取 {POOL_YAML_TEMPLATE} 失败: {e}")
        return

    subscriptions = cfg.get("subscriptions") or []
    tgchannels = cfg.get("tgchannels") or []

    # 如果 tgchannels 中是裸名，自动补全为 https://t.me/s/<name>
    fixed_tgchannels = []
    for ch in tgchannels:
        s = str(ch).strip()
        if s.startswith("http://") or s.startswith("https://"):
            fixed_tgchannels.append(s)
        else:
            fixed_tgchannels.append(f"https://t.me/s/{s}")
    tgchannels = fixed_tgchannels

    # 先从 Telegram 渠道抓取额外订阅
    async with aiohttp.ClientSession() as session:
        extra_subs = []
        # 自动补全 telegram 频道裸名为 t.me 链接（放在 main() 里读取之后）
        fixed = []
        for ch in tgchannels:
            if re.match(r"^https?://", str(ch)):
                fixed.append(ch)
            else:
                fixed.append(f"https://t.me/s/{ch}")
        tgchannels = fixed
        if tgchannels:
            logger.info(f"开始抓取 {len(tgchannels)} 个 Telegram 渠道以提取订阅链接...")
            tasks = [extract_links_from_telegram(session, ch) for ch in tgchannels]
            results = await asyncio.gather(*tasks)
            for r in results:
                extra_subs.extend(r)
            # 将额外提取的加入 subscriptions
            for s in extra_subs:
                if s not in subscriptions:
                    subscriptions.append(s)
            logger.info(f"从 Telegram 提取到 {len(extra_subs)} 个候选链接（去重后总订阅数 {len(subscriptions)})")

        # 并发处理订阅
        sem = asyncio.Semaphore(MAX_CONCURRENT_DOWNLOADS)
        tasks = [handle_subscription_content(session, s, sem) for s in subscriptions]
        results = await asyncio.gather(*tasks,return_exceptions=True)
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                logger.warning(f"订阅处理任务 {i} 抛出异常: {r}")
        
        
        
        
        
        
    logger.info("处理完成。所有结果保存在 pool/ 目录下。")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("用户中断。")
