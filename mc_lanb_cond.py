from __future__ import annotations
import pydivert
import mc_lanb_advtools as utils
import time
#from muilt_terminal_util import Terminal
from collections import deque
import time
import bisect
import itertools
import importlib

kept_data: dict

class PPTCounter:
    def __init__(self, ctr_id: Any, max_record_time: float = 60.0):
        kept_data.setdefault('ppt_counter:deques', {})
        kept_data['ppt_counter:deques'].setdefault(ctr_id, deque())
        self.max_record_time = max_record_time
        self.records = kept_data['ppt_counter:deques'][ctr_id]
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

    def get_all(self) -> list:
        self._clean_expired()
        return len(self.records)

    def clear(self):
        self.records.clear()
        self.first_trig = None

def color_gradient(val: int, max_val: int, pad_ex: int = 0) -> str:
    padder = ' ' * (len(str(max_val)) - len(str(val)) + pad_ex)
    
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

banned_ips = {'26.19.87.179'}

def handler(packet: pydivert.Packet, wd_object: pydivert.WinDivert):
    original_data, coding = utils.auto_decode_bytes(packet.payload, allow_encodings=('utf-8', 'gbk', 'ascii'))
    coding                = coding.lower() + (5-len(coding)) * ' '
    src_ip, dst_ip        = packet.src_addr, packet.dst_addr
    text, port, fml_data  = utils.parse_mc_lanpacket(original_data)
    
    broadcast_counters = kept_data.setdefault('broadcast_counters', {})
    ip_counters = kept_data.setdefault('ip_counters', {})
    
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
    
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

    f_src_ip           = src_ip    + ' '*(15-len(src_ip))
    f_dst_ip           = dst_ip    + ' '*(15-len(dst_ip))
    f_coding           = coding    + ' '*(5 -len(coding))
    f_port             = str(port) + ' '*(5 -len(str(port)))
    f_per_1dot5_sec    = color_gradient(round(broadcast_counters[sid].get_per_time(1.5) ), max_val=max_per_1dot5_sec, pad_ex=2)
    f_per_min          = color_gradient(round(broadcast_counters[sid].get_per_time(60.0)), max_val=max_per_min,       pad_ex=2)
    f_ip_per_1dot5_sec = color_gradient(round(ip_counters[src_ip].get_per_time(1.5) ), max_val=ip_max_per_1dot5_sec,  pad_ex=2)
    f_ip_per_min       = color_gradient(round(ip_counters[src_ip].get_per_time(60.0)), max_val=ip_max_per_min,        pad_ex=2)
    f_text             = utils.parse_mc_style(text, using_gray_default=True)#.replace('\033', '\\033')
    
    if broadcast_counters[sid].get_per_time(1.5) > max_per_1dot5_sec or broadcast_counters[sid].get_per_time(60.0) > max_per_min:
        result = False
    if ip_counters[src_ip].get_per_time(1.5) > ip_max_per_1dot5_sec or ip_counters[src_ip].get_per_time(60.0) > ip_max_per_min:
        result = False
    
    p_info = f"""\
\033[0;96m{timestamp} \
\033[0;32m{f_per_1dot5_sec} \
\033[0;32m{f_per_min} \
\033[0;32m{f_ip_per_1dot5_sec} \
\033[0;32m{f_ip_per_min} \
\033[0;1;94m{f_src_ip}\
\033[0;33m ▶ \
\033[0;1;94m{f_dst_ip} \
\033[0;1;35m{f_port} \
\033[0;31m{f_coding} """  + ('\033[0;92m[Allow →]' if result else '\033[0;91m[Block ✘]') + f"\033[0m {f_text}\033[0m"

    packet.dst_addr = '255.255.255.255' # 修复 (Neo)Forge 客户端收不到广播包的问题
    #if src_ip in banned_ips:
    #11    result = False
    
    #try: kept_data['packet_logger_term'].stdout(p_info)
    #except: pass
    print(p_info)
    if result:
        wd_object.send(packet)

def will_update(timestamp: float):
    #try:
        #kept_data['packet_logger_term'].free()
        #del kept_data['packet_logger_term']  # 清理终端对象
    #except: pass
    print('will update', time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()))

def on_updated(timestamp: float):
    global utils
    print('on updated', time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()))
    utils = importlib.reload(utils)
    #if kept_data.get('packet_logger_term', None) is None:
        #kept_data['packet_logger_term'] = Terminal('Mc LanB Firewall: Packet Logger Terminal')
        #kept_data['packet_logger_term'].alloc(configs={'enable_input': False})

__all__ = ['handler']
