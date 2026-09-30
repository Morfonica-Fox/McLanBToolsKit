# Copyright (c) [2026] [Morfonica_Fox]
# [McLanBToolsKit] is licensed under Mulan PubL v2.
# You can use this software according to the terms and conditions of the Mulan PubL v2.
# You may obtain a copy of Mulan PubL v2 at:
#         http://license.coscl.org.cn/MulanPubL-2.0
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PubL v2 for more details.

from __future__ import annotations

__all__ = ["handler"]

import importlib
#import itertools
import sys
import time
#import atomics
import ctypes
from collections import deque
from pathlib import Path
import numpy as np
from typing import Literal

import pydivert

import mc_lanb_advtools as utils
import qpc_time_lib as qpctime

script_dir = Path(__file__).parent.resolve()  # 支持Embedding版本Python!
sys.path.insert(0, str(script_dir))  # Embedding版默认不从脚本所在目录导入库


banned_ips = {"26.19.87.179"}
kept_data = {
    "ppt_counter:data": {},
    "broadcast_counters": {},
    "ip_counters": {},
}

class PPTCounter:
    def __init__(self, ctr_id, max_record_time: float | int = 60.0, utime: float | int = 1.5):
        max_record_time = self.standardisation_time(max_record_time)
        utime = self.standardisation_time(utime)
        if utime > max_record_time:
            raise ValueError('unit time should be less than max record time')
        self.utime = utime
        self.buckets_count = max_record_time // utime
        self.max_record_time = self.buckets_count * utime # 修正逻辑 故意这样干的 因为业务最后还是会丢弃超过窗口的数据 这里向下取整没问题
        self.dataref = dataref = kept_data["ppt_counter:data"].setdefault(ctr_id, [None, None, None])
        if dataref[0] is None: dataref[0] = self.buckets = [0] * self.buckets_count
        if dataref[1] is None: dataref[1] = self.buckets_last_update_time = [0] * self.buckets_count
        self.base_time = dataref[2]
        
    def standardisation_time(self, tm: int | float) -> int:
        if not isinstance(tm, int): 
            tm = int(tm * qpctime.QPC_FREQ)
        return tm
    
    def sum_history_window(self, current_time: int | float) -> int:
        self.clean_old_data(current_time=current_time)
        return sum(self.buckets)
    
    def maxium_history_window(self, current_time: int | float) -> int:
        self.clean_old_data(current_time)
        return max(self.buckets)

    def average_history_window(self, current_time: int | float) -> float:
        self.clean_old_data(current_time=current_time)
        return sum(self.buckets) / self.buckets_count
    
    def trigged_this_utime(self, current_time: int | float) -> int | None:
        if self.base_time is None: return
        bucket_idx = (current_time - self.base_time) // self.utime % self.buckets_count
        self.clean_single_bucket_old_data(bucket_idx=bucket_idx, current_time=current_time)
        return self.buckets[bucket_idx]
    
    def clean_old_data(self, current_time: int | float) -> None:
        if self.base_time is None: return
        current_time = self.standardisation_time(current_time)
        for i, (val, last_update_time) in enumerate(zip(self.buckets, self.buckets_last_update_time)):
            if current_time - last_update_time > self.max_record_time:
                self.buckets[i] = 0
                self.buckets_last_update_time[i] = current_time
    
    def clean_single_bucket_old_data(self, bucket_idx: int, current_time: int | float) -> None:
        if self.base_time is None: return
        current_time = self.standardisation_time(current_time)
        if current_time - self.buckets_last_update_time[bucket_idx] > self.max_record_time:
            self.buckets[bucket_idx] = 0
    
    def trig(self, current_time: int | float) -> None:
        current_time = self.standardisation_time(current_time)
        if self.base_time is None:
            self.base_time = current_time - (self.utime >> 1)
            self.dataref[2] = self.base_time
        idx = (current_time - self.base_time) // self.utime % self.buckets_count
        if current_time - self.buckets_last_update_time[idx] > self.max_record_time:
            self.buckets[idx] = 0
        self.buckets_last_update_time[idx] = current_time
        self.buckets[idx] += 1

    def reset(self) -> None:
        for i in range(len(self.buckets)):
            self.buckets[i] = 0
            self.buckets_last_update_time[i] = 0
        self.base_time = None
        self.dataref[2] = None
    

def color_gradient(val: int, max_val: int, pad_ex: int = 2) -> str:
    padder = " " * (len(str(max_val)) - len(str(val)) + pad_ex)

    if val == 0:
        r, g, b = 140, 140, 140
        return f"\033[0;38;2;{r};{g};{b}m{val}\033[0m" + padder

    if val > max_val:
        return f"\033[1;38;2;255;255;255;48;2;200;0;0m{val}\033[0m" + padder

    ratio = val / max_val

    hue = 180 - (ratio * 180)
    hue = max(0, hue)

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

hard_blacklist = set()

def handler(packet: pydivert.Packet, wd_object: pydivert.WinDivert):
    global hard_blacklist
    assert packet.payload is not None

    original_data, coding = utils.auto_decode_bytes(
        packet.payload,
        allow_encodings=("utf-8", "gbk", "ascii"),
    )
    coding = f"{coding.lower(): <5}"
    src_ip, dst_ip = packet.src_addr, packet.dst_addr
    try:
        motd, port, fml_data = utils.parse_mc_lanpacket(original_data)
    except ValueError:
        return

    broadcast_counters = kept_data["broadcast_counters"]
    ip_counters = kept_data["ip_counters"]

    sid = (src_ip, port, dst_ip)

    result = True
    max_per_1dot5_sec = 2
    max_per_min = 42
    ip_max_per_1dot5_sec = max_per_1dot5_sec * 8
    ip_max_per_min = max_per_min * 8
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    f_src_ip = f"{src_ip: <15}"
    f_dst_ip = f"{dst_ip: <15}"
    f_coding = f"{coding: <5}"
    f_port = f"{port: <5}"
    
    tp = packet._wd_addr.Timestamp
    broadcast_counters: dict[str, PPTCounter]
    ip_counters: dict[str, PPTCounter]
    
    if port.isdigit() and (0 <= int(port) <= 65535):
        if broadcast_counters.get(sid, None) is None:
            broadcast_counters[sid] = PPTCounter(sid)
        broadcast_counters[sid].trig(tp)
        b_ut = broadcast_counters[sid].trigged_this_utime(tp)
        b_pm = broadcast_counters[sid].maxium_history_window(tp)
        f_per_1dot5_sec = color_gradient(
            round(b_ut),
            max_val=max_per_1dot5_sec,
            pad_ex=2,
        )
        f_per_min = color_gradient(
            round(b_pm),
            max_val=max_per_min,
            pad_ex=2,
        )
    else:
        b_ut = -1
        b_pm = -1
        f_per_1dot5_sec = "?  "
        f_per_min = "?   "
    
    if ip_counters.get(src_ip, None) is None:
        ip_counters[src_ip] = PPTCounter(src_ip)
    ip_counters[src_ip].trig(tp)
    i_ut = ip_counters[src_ip].trigged_this_utime(tp)
    i_pm = ip_counters[src_ip].maxium_history_window(tp)
    f_ip_per_1dot5_sec = color_gradient(
        round(i_ut),
        max_val=ip_max_per_1dot5_sec,
        pad_ex=2,
    )
    f_ip_per_min = color_gradient(
        round(ip_counters[src_ip].sum_history_window(tp)),
        max_val=ip_max_per_min,
        pad_ex=2,
    )
    
    f_motd = utils.parse_mc_style(
        motd, using_gray_default=True
    )  # .replace('\033', '\\033')

    try:
        if (
            b_ut > max_per_1dot5_sec
            or b_pm > max_per_min
        ):
            result = False
    except:
        pass
    if (
        i_ut > ip_max_per_1dot5_sec
        or i_pm > ip_max_per_min
    ):
        result = False
    if not (port.isdigit() and 0 <= int(port) <= 65535):
        result = False
    if src_ip in banned_ips:
        result = False

    p_info = (
        f"""\
\033[0;96m{timestamp} \
\033[0;32m{f_per_1dot5_sec} \
\033[0;32m{f_per_min} \
\033[0;32m{f_ip_per_1dot5_sec} \
\033[0;32m{f_ip_per_min} \
\033[0;1;94m{f_src_ip}\
\033[0;33m ▶ \
\033[0;1;94m{f_dst_ip} \
\033[0;1;35m{f_port[:5]} \
\033[0;31m{f_coding} """
        + ("\033[0;92m[A →]" if result else "\033[1;38;2;251;242;219;48;2;200;0;0m[B ✘]")
        + f"\033[0m {f_motd}\033[0m"
    )
    
    # 修复 (Neo)Forge 客户端收不到广播包的问题
    packet.dst_addr = "255.255.255.255"

    print(p_info)

    if result:
        wd_object.send(packet)


def will_update(timestamp: float):  # noqa: ARG001
    # try:
    # kept_data['packet_logger_term'].free()
    # del kept_data['packet_logger_term']  # 清理终端对象
    # except: pass
    print("will update", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))


def on_updated(timestamp: float):  # noqa: ARG001
    global utils, qpctime, hard_blacklist
    print("on updated", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    utils = importlib.reload(utils)
    qpctime = importlib.reload(qpctime)
    # if kept_data.get('packet_logger_term', None) is None:
    # kept_data['packet_logger_term'] = Terminal('Mc LanB Firewall: Packet Logger Terminal')
    # kept_data['packet_logger_term'].alloc(configs={'enable_input': False})
    
    temp_ip_blacklist_file = Path("./temp_ip_blacklist.txt")
    temp_ip_blacklist_file.touch()
    
    with temp_ip_blacklist_file.open("r", encoding="utf-8") as f:
        hard_blacklist = set([f.strip() for f in f.readlines()])
        # banned_ips？
    