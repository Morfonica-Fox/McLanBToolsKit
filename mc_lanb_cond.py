from __future__ import annotations

import bisect
from collections import deque
import importlib
import itertools
import logging
import time

# [+] 修复未解析的特性
from typing import Any

import pydivert

import mc_lanb_advtools as utils

# [+] 声明 mc_lanb_firewall 中的 kept_data
# [+] 将 keeped 改为 kept(keep的过去式、过去分词)
kept_data: dict[str, Any]


class PPTCounter:
    def __init__(self, ctr_id: Any, max_record_time: float = 60.0):
        kept_data.setdefault("ppt_counter:deques", {})
        kept_data["ppt_counter:deques"].setdefault(ctr_id, deque())
        self.max_record_time = max_record_time
        self.records = kept_data["ppt_counter:deques"][ctr_id]
        self.first_trig = None

    def _clean_expired(self):
        current_time = time.time()
        expire_time = current_time - self.max_record_time

        idx = bisect.bisect_right(self.records, expire_time)
        if idx > 0:
            self.records = deque(itertools.islice(self.records, idx, None))

    def trig(self):
        current_time = time.time()
        self.first_trig = self.first_trig or current_time
        self.records.append(current_time)
        self._clean_expired()

    def get_per_time(self, custom_time: float) -> int:
        if custom_time <= 0:
            return 0

        current_time = time.time()
        self._clean_expired()
        start_time = current_time - custom_time
        idx = bisect.bisect_left(self.records, start_time)
        return len(self.records) - idx

    # [-] 删除 get_all 函数, 其返回值和申明返回值冲突，并且未被使用
    # def get_all(self) -> list:
    #     self._clean_expired()
    #     return len(self.records)

    def clear(self):
        self.records.clear()
        self.first_trig = None


def color_gradient(val: int, max_val: int, pad_ex: int = 0) -> str:
    padder = " " * (len(str(max_val)) - len(str(val)) + pad_ex)

    if val == 0:
        r, g, b = 140, 140, 140
        return f"\033[0;38;2;{r};{g};{b}m{val}\033[0m" + padder

    if val > max_val:
        return f"\033[1;38;2;255;255;255;48;2;200;0;0m{val}\033[0m" + padder

    ratio: float = val / max_val

    hue: float = 180 - (ratio * 180)
    hue = max(0, round(hue))

    c = 1.0
    x = c * (1 - abs((hue / 60) % 2 - 1))
    m = 0.0

    if 0 <= hue < 60:
        r, g, b = c, x, 0
    elif 60 <= hue < 120:
        r, g, b = x, c, 0
    elif 120 <= hue < 180:
        r, g, b = 0, c, x
    elif 180 <= hue < 240:
        r, g, b = 0, x, c
    else:
        r, g, b = 0, 0, 0

    r = round((r + m) * 255)
    g = round((g + m) * 255)
    b = round((b + m) * 255)

    return f"\033[0;38;2;{r};{g};{b}m{val}\033[0m" + padder


def lerp_color(color1, color2, t):
    """
    在 RGB 颜色间进行线性插值。
    :param color1: 起始颜色 (R, G, B)，每个分量 0-255
    :param color2: 结束颜色 (R, G, B)
    :param t: 插值因子，0.0 ~ 1.0（0 返回 color1，1 返回 color2）
    :return: 插值后的 (R, G, B) 元组
    """
    return tuple(int(c1 + (c2 - c1) * t) for c1, c2 in zip(color1, color2))


def rich_color_gradient(val: int, max_val: int) -> str:
    """
    与 color_gradient 完全相同的颜色逻辑，但返回 Rich 标记字符串。
    性能优化：模块级导入 Style/Text，局部变量绑定，避免重复计算。
    """
    from rich.style import Style
    from rich.text import Text

    # 1. 判断边界情况
    if val == 0:
        r, g, b = 140, 140, 140
        bold = False
        bg_r = bg_g = bg_b = None
    elif val > max_val:
        r, g, b = 255, 255, 255
        bold = True
        bg_r, bg_g, bg_b = 200, 0, 0
    else:
        # 2. 普通渐变：色相从 180° 到 0°（青色 → 红色）
        ratio = val / max_val
        hue = 180 - ratio * 180
        hue = max(0, round(hue))

        # 3. HSL 转 RGB
        c = 1.0
        x = c * (1 - abs((hue / 60) % 2 - 1))
        m = 0.0
        if 0 <= hue < 60:
            r, g, b = c, x, 0
        elif 60 <= hue < 120:
            r, g, b = x, c, 0
        elif 120 <= hue < 180:
            r, g, b = 0, c, x
        elif 180 <= hue < 240:
            r, g, b = 0, x, c
        else:
            r, g, b = 0, 0, 0

        r = round((r + m) * 255)
        g = round((g + m) * 255)
        b = round((b + m) * 255)

        bold = False
        bg_r = bg_g = bg_b = None

    # 4. 构建 Rich 样式（只构建一次，避免重复）
    style_kwargs = {"color": f"rgb({r},{g},{b})"}
    if bold:
        style_kwargs["bold"] = True
    if bg_r is not None:
        style_kwargs["bgcolor"] = f"rgb({bg_r},{bg_g},{bg_b})"

    style = Style(**style_kwargs)
    return Text(str(val), style=style).markup


def handler(
    packet: pydivert.Packet,
    wd_object: pydivert.WinDivert,
    logger: logging.Logger,
    rich_enable: bool,
):
    # [=] oringal_data -> original_data
    original_data, coding = utils.auto_decode_bytes(
        packet.payload, allow_encodings=("utf-8", "gbk", "ascii")
    )
    coding = coding.lower() + (5 - len(coding)) * " "
    src_ip, dst_ip = packet.src_addr, packet.dst_addr
    text, port, fml_data = utils.parse_mc_lanpacket(original_data)

    broadcast_counters = kept_data.setdefault("broadcast_counters", {})
    ip_counters = kept_data.setdefault("ip_counters", {})

    sid = (src_ip, port, dst_ip)

    result = True
    max_per_1dot5_sec = 5
    max_per_min = 84
    ip_max_per_1dot5_sec = max_per_1dot5_sec * 8
    ip_max_per_min = max_per_min * 8

    if broadcast_counters.get(sid, None) is None:
        broadcast_counters[sid] = PPTCounter(sid)
    broadcast_counters[sid].trig()
    if ip_counters.get(src_ip, None) is None:
        ip_counters[src_ip] = PPTCounter(src_ip)
    ip_counters[src_ip].trig()

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    f_src_ip = src_ip + " " * (15 - len(src_ip))
    f_dst_ip = dst_ip + " " * (15 - len(dst_ip))
    f_coding = coding + " " * (5 - len(coding))
    f_port = str(port) + " " * (5 - len(str(port)))
    f_per_1dot5_sec = color_gradient(
        round(broadcast_counters[sid].get_per_time(1.5)),
        max_val=max_per_1dot5_sec,
        pad_ex=2,
    )
    f_per_min = color_gradient(
        round(broadcast_counters[sid].get_per_time(60.0)), max_val=max_per_min, pad_ex=2
    )
    f_ip_per_1dot5_sec = color_gradient(
        round(ip_counters[src_ip].get_per_time(1.5)),
        max_val=ip_max_per_1dot5_sec,
        pad_ex=2,
    )
    f_ip_per_min = color_gradient(
        round(ip_counters[src_ip].get_per_time(60.0)), max_val=ip_max_per_min, pad_ex=2
    )
    f_text = utils.parse_mc_style(
        text, using_gray_default=True
    )  # .replace('\033', '\\033')

    if (
        broadcast_counters[sid].get_per_time(1.5) > max_per_1dot5_sec
        or broadcast_counters[sid].get_per_time(60.0) > max_per_min
    ):
        result = False
    elif (
        ip_counters[src_ip].get_per_time(1.5) > ip_max_per_1dot5_sec
        or ip_counters[src_ip].get_per_time(60.0) > ip_max_per_min
    ):
        result = False

    packet.dst_addr = "255.255.255.255"  # 修复 (Neo)Forge 客户端收不到广播包的问题

    # try: kept_data['packet_logger_term'].stdout(p_info)
    # except: pass
    if result:
        wd_object.send(packet)

    # [=] 显示条件 和 拦截条件分离，方便阅读
    if not result:
        if rich_enable:
            is_table = False
            if is_table:
                # alpha version: Table display
                from rich import print
                from rich.table import Table

                print("\n\n")

                table = Table(show_header=True, box=None, padding=(0, 2), width=100)
                table.add_column("src_ip", style="bold cyan", justify="center")
                table.add_column("dst_ip", style="bold cyan", justify="center")
                table.add_column("coding", style="bold cyan", justify="center")
                table.add_column("port", style="bold cyan", justify="center")
                table.add_column("S-PP1.5s", style="bold cyan", justify="center")
                table.add_column("S-PPM", style="bold cyan", justify="center")
                table.add_column("IP-PP1.5s", style="bold cyan", justify="center")
                table.add_column("IP-PPM", style="bold cyan", justify="center")
                table.add_column("MOTD", style="bold cyan", justify="center")

                table.add_row(
                    src_ip,
                    dst_ip,
                    coding,
                    str(port),
                    rich_color_gradient(
                        val=round(broadcast_counters[sid].get_per_time(1.5), 2),
                        max_val=max_per_1dot5_sec,
                    ),
                    rich_color_gradient(
                        val=round(broadcast_counters[sid].get_per_time(60.0), 2),
                        max_val=max_per_min,
                    ),
                    rich_color_gradient(
                        val=round(ip_counters[src_ip].get_per_time(1.5), 2),
                        max_val=ip_max_per_1dot5_sec,
                    ),
                    rich_color_gradient(
                        val=round(ip_counters[src_ip].get_per_time(60.0), 2),
                        max_val=ip_max_per_min,
                    ),
                    utils.rich_parse_mc_style(text),
                )

                print(table)
            else:

                from rich import print
                from rich.text import Text

                def rich_ljust(s: str, width: int, fillchar: str = " ") -> str:
                    t = Text.from_markup(s)
                    visible_len = len(t.plain)
                    if visible_len >= width:
                        return s

                    t.append(fillchar * (width - visible_len))
                    return t.markup

                KEY_WIDTH = 14
                VALUE_WIDTH = 15

                val_s_pp = round(broadcast_counters[sid].get_per_time(1.5), 2)
                styled_s_pp = rich_color_gradient(
                    val=val_s_pp, max_val=max_per_1dot5_sec
                )
                aligned_s_pp = rich_ljust(styled_s_pp, VALUE_WIDTH)

                val_s_ppm = round(broadcast_counters[sid].get_per_time(60.0), 2)
                styled_s_ppm = rich_color_gradient(val=val_s_ppm, max_val=max_per_min)
                aligned_s_ppm = rich_ljust(styled_s_ppm, VALUE_WIDTH)

                val_ip_pp = round(ip_counters[src_ip].get_per_time(1.5), 2)
                styled_ip_pp = rich_color_gradient(
                    val=val_ip_pp, max_val=ip_max_per_1dot5_sec
                )
                aligned_ip_pp = rich_ljust(styled_ip_pp, VALUE_WIDTH)

                val_ip_ppm = round(ip_counters[src_ip].get_per_time(60.0), 2)
                styled_ip_ppm = rich_color_gradient(
                    val=val_ip_ppm, max_val=ip_max_per_min
                )
                aligned_ip_ppm = rich_ljust(styled_ip_ppm, VALUE_WIDTH)

                motd_styled = utils.rich_parse_mc_style(text)
                motd_aligned = rich_ljust(motd_styled, VALUE_WIDTH + 10)

                lines = []
                lines.append(f"{'src_ip'.ljust(KEY_WIDTH)} = {src_ip:<{VALUE_WIDTH}}")
                lines.append(f"{'dst_ip'.ljust(KEY_WIDTH)} = {dst_ip:<{VALUE_WIDTH}}")
                lines.append(f"{'coding'.ljust(KEY_WIDTH)} = {coding:<{VALUE_WIDTH}}")
                lines.append(f"{'port'.ljust(KEY_WIDTH)} = {str(port):<{VALUE_WIDTH}}")
                lines.append(f"{'S-PP1.5s'.ljust(KEY_WIDTH)} = {aligned_s_pp}")
                lines.append(f"{'S-PPM'.ljust(KEY_WIDTH)} = {aligned_s_ppm}")
                lines.append(f"{'IP-PP1.5s'.ljust(KEY_WIDTH)} = {aligned_ip_pp}")
                lines.append(f"{'IP-PPM'.ljust(KEY_WIDTH)} = {aligned_ip_ppm}")
                lines.append(f"{'MOTD'.ljust(KEY_WIDTH)} = {motd_aligned}")

                # 用换行符连接
                p_info = "\n".join(lines)

                logger.info(p_info)
        else:
            p_info = (
                f""" \
\033[0;96m{timestamp} \
\033[0;32m{f_per_1dot5_sec} \
\033[0;32m{f_per_min} \
\033[0;32m{f_ip_per_1dot5_sec} \
\033[0;32m{f_ip_per_min} \
\033[0;1;94m{f_src_ip} \
\033[0;33m ▶ \
\033[0;1;94m{f_dst_ip} \
\033[0;1;35m{f_port} \
\033[0;31m{f_coding}"""
                + ("\033[0;92m[Allow →]" if result else "\033[0;91m[Block ✘]")
                + f"\033[0m {f_text}\033[0m"
            )

            logger.info(p_info)


def will_update(timestamp: float):
    # try:
    # kept_data['packet_logger_term'].free()
    # del kept_data['packet_logger_term']  # 清理终端对象
    # except: pass
    print("will update", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))


def on_updated(timestamp: float):
    global utils
    print("on updated", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    utils = importlib.reload(utils)
    # if kept_data.get('packet_logger_term', None) is None:
    # kept_data['packet_logger_term'] = Terminal('Mc LanB Firewall: Packet Logger Terminal')
    # kept_data['packet_logger_term'].alloc(configs={'enable_input': False})


__all__ = ["handler"]
