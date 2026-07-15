from __future__ import annotations

import io
import re
from typing import Any, Dict, List, Optional, Tuple

from charset_normalizer import from_bytes

# [+] 声明 mc_lanb_firewall 中的 kept_data
# [+] 将 keeped 改为 kept(keep的过去式、过去分词)
kept_data: dict[str, Any]


def on_updated(timestamp: float): ...
def will_update(timestamp: float, new_code: str): ...


def auto_decode_bytes(
    data: bytes,
    fallback_encodings: tuple = ("utf-8", "gbk", "ascii"),
    allow_encodings: tuple = (),
):
    if not data:
        return "", "utf-8"
    result = from_bytes(data).best()

    if result and (not allow_encodings or result.encoding in allow_encodings):
        return result.output().decode("utf-8"), result.encoding
    for falledback_encoding in fallback_encodings:
        try:
            text = data.decode(falledback_encoding)
            return text, falledback_encoding
        except:
            pass
    return (
        data.decode(fallback_encodings[0], errors="backslashreplace"),
        fallback_encodings[0],
    )


# [=] currect 改为 current
def current_ip(ip: str, iptype: str = "unknown"):
    assert iptype in {"ipv4/v8", "ipv4", "ipv8", "ipv6", "unknown"}

    if iptype in {"ipv4/v8", "ipv4", "ipv8"}:
        achars = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "."}
    elif iptype == "ipv6":
        achars = {
            "0",
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "8",
            "9",
            "a",
            "b",
            "c",
            "d",
            "e",
            "f",
            ":",
        }
    else:
        achars = {
            "0",
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "8",
            "9",
            ".",
            "a",
            "b",
            "c",
            "d",
            "e",
            "f",
            ":",
        }

    return "".join([char for char in ip if char in achars])


def parse_mc_lanpacket(text: str | bytes | tuple | list):
    if type(text) in {tuple, list}:
        text = "".join(text)
    elif type(text) == bytes:
        text = auto_decode_bytes(text)
    else:
        try:
            text = str(text)
        except:
            return (None, None, None)

    motd_start = text.find("[MOTD]")
    if motd_start == -1:
        return (None, None, None)
    content_begin = motd_start + 6
    motd_end = text.find("[/MOTD]", content_begin)
    if motd_end == -1:
        motd = text[content_begin:]
    else:
        motd = text[content_begin:motd_end]

    ad_start = text.find("[AD]", motd_end if motd_end != -1 else 0)
    ad = None
    if ad_start != -1:
        ad_content_begin = ad_start + 4
        ad_end = text.find("[/AD]", ad_content_begin)
        if ad_end == -1:
            ad = text[ad_content_begin:]
        else:
            ad = text[ad_content_begin:ad_end]
        if not ad:
            ad = None

    fml_start = text.find("[FML]")
    fml = None
    if fml_start != -1:
        fml_content_begin = fml_start + 5
        fml_end = text.find("[/FML]", fml_content_begin)
        if fml_end == -1:
            fml = text[fml_content_begin:]
        else:
            fml = text[fml_content_begin:fml_end]
        if not fml:
            fml = None

    return (motd, ad, fml)


GLOBAL_STD_ANSI_COLOR_MAPPINGS = {
    "0": "30",
    "1": "34",
    "2": "32",
    "3": "36",
    "4": "31",
    "5": "35",
    "6": "33",
    "7": "37",
    "8": "90",
    "9": "94",
    "a": "92",
    "b": "96",
    "c": "91",
    "d": "95",
    "e": "93",
    "f": "97",
}

GLOBAL_HEX_COLOR_MAPPINGS = {
    "0": "000000",
    "1": "0000AA",
    "2": "00AA00",
    "3": "00AAAA",
    "4": "AA0000",
    "5": "AA00AA",
    "6": "FFAA00",
    "7": "AAAAAA",
    "8": "555555",
    "9": "5555FF",
    "a": "55FF55",
    "b": "55FFFF",
    "c": "FF5555",
    "d": "FF55FF",
    "e": "FFFF55",
    "f": "FFFFFF",
}

GLOBAL_EX_COLOR_MAPPINGS = {
    "g": "DDD605",
    "h": "E3D4D1",
    "i": "CECACA",
    "j": "443A3B",
    "m": "971607",
    "n": "B4684D",
    "p": "DEB12D",
    "q": "47A036",
    "s": "2CBAA8",
    "t": "21497B",
    "u": "9A5CC6",
    "v": "EB7114",
    "w": "8CB3FF",
}

GLOBAL_STYLE_MAPPINGS = {  # 猜猜为啥不写 r 的格式
    "l": "1",
    "o": "3",
    "n": "4",
    "k": "8",
    "m": "9",
}  # 因为 r 的格式是 恢复默认 默认的颜色由函数传入的参数决定


def rich_parse_mc_style(text: str, color_prefix: str = "§") -> str:
    from rich.style import Style
    from rich.text import Text

    COLOR_MAP: Dict[str, Tuple[int, int, int]] = {
        "0": (0, 0, 0),  # 黑色
        "1": (0, 0, 170),  # 深蓝色
        "2": (0, 170, 0),  # 深绿色
        "3": (0, 170, 170),  # 湖蓝色
        "4": (170, 0, 0),  # 深红色
        "5": (170, 0, 170),  # 紫色
        "6": (255, 170, 0),  # 金色
        "7": (170, 170, 170),  # 灰色
        "8": (85, 85, 85),  # 深灰色
        "9": (85, 85, 255),  # 蓝色
        "a": (85, 255, 85),  # 绿色
        "b": (85, 255, 255),  # 天蓝色
        "c": (255, 85, 85),  # 红色
        "d": (255, 85, 255),  # 粉红色
        "e": (255, 255, 85),  # 黄色
        "f": (255, 255, 255),  # 白色
    }

    # 格式代码 -> Rich 样式属性映射
    FORMAT_MAP: Dict[str, str] = {
        "l": "bold",  # 粗体
        "o": "italic",  # 斜体
        "n": "underline",  # 下划线
        "m": "strike",  # 删除线
        # 'k' 混淆，无法在 Rich 中完美模拟，此处忽略
        # 'r' 重置，在解析器中特殊处理
    }

    def mc_to_rich(text: str, color_prefix: str = "§") -> Text:
        """
        将包含 Minecraft 样式代码的字符串转换为 rich.Text 对象。

        支持的颜色代码: §0-9, §a-f
        支持的格式代码: §l (粗体), §o (斜体), §n (下划线), §m (删除线)
        支持重置: §r

        Args:
            text: 包含 Minecraft 样式代码的字符串
            color_prefix: 颜色代码前缀，默认为 "§"，也可设为 "&"

        Returns:
            rich.Text 对象，包含相应的样式

        Example:
            >>> mc_to_rich("§cHello §lWorld§r!")
            >>> mc_to_rich("&a&lGreen Bold Text", color_prefix="&")
        """
        if not text:
            return Text("")

        # 构建正则表达式：匹配前缀 + 单个字符 (0-9a-fklmnor)
        pattern = re.compile(
            rf"{re.escape(color_prefix)}([0-9a-fk-lmnor])", re.IGNORECASE
        )

        result = Text()
        current_color: Optional[Tuple[int, int, int]] = None
        current_styles: List[str] = []

        # 记录当前正在累积的普通文本
        pending_text = ""
        last_end = 0

        for match in pattern.finditer(text):
            start, end = match.span()
            code = match.group(1).lower()

            # 添加匹配之前的普通文本（用当前样式）
            if start > last_end:
                pending_text += text[last_end:start]

            # 如果有待处理的文本，用当前样式添加到结果
            if pending_text:
                _append_styled_text(result, pending_text, current_color, current_styles)
                pending_text = ""

            # 处理样式代码
            if code == "r":
                # 重置所有样式
                current_color = None
                current_styles = []
            elif code in COLOR_MAP:
                # 颜色代码
                current_color = COLOR_MAP[code]
            elif code in FORMAT_MAP:
                # 格式代码 (粗体、斜体等)
                style_attr = FORMAT_MAP[code]
                if style_attr not in current_styles:
                    current_styles.append(style_attr)
            # 'k' (混淆) 被忽略，因为 Rich 无法模拟

            last_end = end

        # 添加剩余的文本
        if last_end < len(text):
            pending_text += text[last_end:]

        if pending_text:
            _append_styled_text(result, pending_text, current_color, current_styles)

        return result

    def _append_styled_text(
        text_obj: Text,
        content: str,
        color: Optional[Tuple[int, int, int]],
        styles: List[str],
    ) -> None:
        """将带样式的文本追加到 rich.Text 对象中"""
        if not content:
            return

        # 构建 Rich 样式
        style_kwargs = {}

        if color is not None:
            r, g, b = color
            style_kwargs["color"] = f"rgb({r},{g},{b})"

        for style_attr in styles:
            if style_attr == "bold":
                style_kwargs["bold"] = True
            elif style_attr == "italic":
                style_kwargs["italic"] = True
            elif style_attr == "underline":
                style_kwargs["underline"] = True
            elif style_attr == "strike":
                style_kwargs["strike"] = True

        style = Style(**style_kwargs) if style_kwargs else None
        text_obj.append(content, style=style)

    return mc_to_rich(text, color_prefix).markup


def parse_mc_style(
    text: str,
    enable_color: bool = True,
    enable_bedrock_ex_color: bool = True,
    enable_true_color: bool = True,
    enable_style: bool = True,
    enable_reset: bool = True,
    always_hex_color: bool = True,
    using_gray_default: bool = False,
    auto_reset_ansi_back: bool = True,
    pre_allocate_ex_bufsize: int = 256,
):
    max_idx = len(text) - 1
    buf = io.StringIO()

    buf.seek(
        len(text)
        + (3 if auto_reset_ansi_back else 0)
        + int(max(0, pre_allocate_ex_bufsize))
    )  # 可见我也是为了最大兼容性煞费苦心
    buf.write("")  # 触发预分配空间
    buf.seek(0)

    GLOBAL_COLOR_MAPPINGS = (
        GLOBAL_HEX_COLOR_MAPPINGS.copy()
        if always_hex_color
        else GLOBAL_STD_ANSI_COLOR_MAPPINGS.copy()
    )
    if always_hex_color:
        for key in GLOBAL_COLOR_MAPPINGS.keys():
            hexstr = GLOBAL_COLOR_MAPPINGS[key]
            r, g, b = int(hexstr[:2], 16), int(hexstr[2:4], 16), int(hexstr[4:], 16)
            GLOBAL_COLOR_MAPPINGS[key] = f"38;2;{r};{g};{b}"
    color_keys = set(GLOBAL_COLOR_MAPPINGS.keys()) if enable_color else set()
    ex_color_keys = (
        set(GLOBAL_EX_COLOR_MAPPINGS.keys()) if enable_bedrock_ex_color else set()
    )
    style_keys = set(GLOBAL_STYLE_MAPPINGS.keys()) if enable_style else set()

    will_skipped_char_cnt = 0

    if using_gray_default:
        buf.write(f'\033[0;{GLOBAL_COLOR_MAPPINGS["7"]}m')  # 像原版客户端一样的默认灰色

    for idx, char in enumerate(text):
        if will_skipped_char_cnt > 0:
            will_skipped_char_cnt -= 1
            continue

        if char != "§" or idx + 1 > max_idx:
            buf.write(char)
            continue

        next_char = text[idx + 1]
        if next_char in color_keys:
            buf.write(f"\033[0;{GLOBAL_COLOR_MAPPINGS[next_char]}m")
            will_skipped_char_cnt += 1
        elif next_char in style_keys:
            buf.write(f"\033[{GLOBAL_STYLE_MAPPINGS[next_char]}m")
            will_skipped_char_cnt += 1
        elif next_char in ex_color_keys:
            hexstr = GLOBAL_EX_COLOR_MAPPINGS[next_char]
            r, g, b = int(hexstr[:2], 16), int(hexstr[2:4], 16), int(hexstr[4:], 16)
            buf.write(f"\033[0;38;2;{r};{g};{b}m")
            will_skipped_char_cnt += 1
        elif next_char == "r" and enable_reset:
            buf.write(
                f'\033[0;{GLOBAL_COLOR_MAPPINGS["7"]}m'
                if using_gray_default
                else "\033[0m"
            )
            will_skipped_char_cnt += 1
        elif enable_true_color and next_char == "x" and idx + 13 <= max_idx:
            stylestr = text[idx + 2 : idx + 14]
            hexstr = stylestr[1:13:2]  # 从1开始 直到12(包含)个字符 步长为2
            r, g, b = int(hexstr[:2], 16), int(hexstr[2:4], 16), int(hexstr[4:], 16)
            buf.write(f"\033[0;38;2;{r};{g};{b}m")
            will_skipped_char_cnt += 13
        else:
            buf.write(char)

    if auto_reset_ansi_back:
        buf.write("\033[0m")  # 保底恢复颜色

    return buf.getvalue()
