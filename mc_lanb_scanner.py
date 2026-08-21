# Copyright (c) [2026] [Morfonica_Fox]
# [McLanBToolsKit] is licensed under Mulan PubL v2.
# You can use this software according to the terms and conditions of the Mulan PubL v2.
# You may obtain a copy of Mulan PubL v2 at:
#         http://license.coscl.org.cn/MulanPubL-2.0
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PubL v2 for more details.

import asyncio
import ctypes
import ctypes.wintypes
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pydivert
from mcstatus import JavaServer

script_dir = Path(__file__).resolve().parent
if str(script_dir) not in sys.path:
    sys.path.insert(0, str(script_dir))
# [fix] 修复 python 3.12.x 下无法从源码所在目录导入库的问题

from mc_lanb_advtools import (
    auto_decode_bytes,
    parse_mc_lanpacket,
    parse_mc_style,
)
from mc_lanb_firewall import already_holded_multicast, start_mcast_hold_daemon
from threadingsafe_structs import *

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


class LargeInt(ctypes.Structure):
    _fields_ = [("QuadPart", ctypes.c_int64)]


def get_raw_qpc() -> int:
    counter = ctypes.c_uint64(0)
    kernel32.QueryPerformanceCounter(ctypes.byref(counter))
    return counter.value


def get_qpc_frequency() -> int:
    freq = ctypes.c_uint64(0)
    kernel32.QueryPerformanceFrequency(ctypes.byref(freq))
    return freq.value


GetSystemTimePreciseAsFileTime = kernel32.GetSystemTimePreciseAsFileTime
GetSystemTimePreciseAsFileTime.argtypes = [
    ctypes.POINTER(ctypes.wintypes.FILETIME)
]


def get_qpc_anchor():
    qpc = LargeInt()
    ft = ctypes.wintypes.FILETIME()
    freq = LargeInt()

    kernel32.QueryPerformanceFrequency(ctypes.byref(freq))
    GetSystemTimePreciseAsFileTime(ctypes.byref(ft))
    kernel32.QueryPerformanceCounter(ctypes.byref(qpc))

    ft_q = (ft.dwHighDateTime << 32) | ft.dwLowDateTime
    return qpc.QuadPart, ft_q, freq.QuadPart


QPC_ANCHOR, FT_ANCHOR, QPC_FREQ = get_qpc_anchor()


def qpc_to_filetime(qpc_tick: int) -> int:
    delta = qpc_tick - QPC_ANCHOR
    delta_100ns = delta * 10_000_000 // QPC_FREQ
    return FT_ANCHOR + delta_100ns


FILETIME_UNIX_OFFSET = (
    11644473600 * 10_000_000
)  # 1601‑01‑01 →1970‑01‑01，100ns单位


def filetime_to_unix_ns(ft_100ns: int) -> int:
    unix_100ns = ft_100ns - FILETIME_UNIX_OFFSET
    return unix_100ns * 100  # 100ns → ns


def qpc_to_utc_datetime(qpc_tick: int) -> datetime:
    ft = qpc_to_filetime(qpc_tick)
    unix_ns = filetime_to_unix_ns(ft)
    sec = unix_ns // 1_000_000_000
    ns = unix_ns % 1_000_000_000
    return datetime.fromtimestamp(sec, tz=timezone.utc).replace(
        microsecond=ns // 1000
    )


wdobj: pydivert.WinDivert | None = None
servers = concurrent_dict()
qpc_freq = get_qpc_frequency()
timeout_server_offline = int(4.5 * qpc_freq)
scan_delay_per_server = int(12 * qpc_freq)
# struct of server: hash: [timestamp, last_scan_timestamp, motd, server_obj, player_info]
# struct of player_info: [player_]


def hash_server(
    src_ip: bytes | str,
    port: bytes,
) -> tuple:
    return (src_ip.encode("utf-8") if type(src_ip) == str else src_ip), port


def log_servers():
    global wdobj, servers, servers_lock
    serversL = servers
    # xxxL: localvar xxx
    # 局部变量访问加速
    with pydivert.WinDivert(
        "inbound and udp and udp.DstPort == 4445", flags=pydivert.Flag.SNIFF
    ) as wd:
        wdobj = wd
        for packet in wd:
            motd, port, fml_data = parse_mc_lanpacket(
                auto_decode_bytes(packet.payload)[0]
            )
            # decoded_motd, coding = auto_decode_bytes(motd, allow_encodings=('utf-8', 'gbk', 'ascii'))
            # styled_motd          = parse_mc_style(decoded_motd)
            src_ip, dst_ip = packet.src_addr, packet.dst_addr
            timestamp = packet._wd_addr.Timestamp

            if not port.isdigit():
                continue

            server = serversL.get(
                hash_server(src_ip, port),
                [
                    timestamp,
                    -1,
                    motd,
                    JavaServer(host=src_ip, port=int(port)),
                    [0, []],
                ],
            )
            server[0] = timestamp
            server[2] = motd
            serversL.put(hash_server(src_ip, port), server)


log_servers_thread = threading.Thread(target=log_servers, daemon=True)
log_servers_thread.start()


def cleanup_servers():
    global servers
    serversL = servers
    last_bucket_index = 0
    will_delete_servers_hashes = []
    while True:
        last_bucket_index, items, geted = serversL.items_inaccurate(
            last_bucket_index
        )
        if not geted:
            continue
        try:
            will_delete_servers_hashes.clear()
            now_timestamp = get_raw_qpc()
            for server_hash, (
                timestamp,
                last_scan_timestamp,
                motd,
                server_obj,
                player_info,
            ) in items:
                if now_timestamp - timestamp > timeout_server_offline:
                    will_delete_servers_hashes.append(server_hash)
            for server_hash in will_delete_servers_hashes:
                serversL.rmv_inaccurate(server_hash)
        # except: pass
        finally:
            pass


cleanup_servers_thread = threading.Thread(target=cleanup_servers, daemon=True)
cleanup_servers_thread.start()


async def scan_server(server_info_ref: list[int, list[str]]):
    player_info_ref = server_info_ref[4]
    server_obj: JavaServer = server_info_ref[3]
    status = await server_obj.async_status()
    player_info_ref[0] = status.players.online
    player_info_ref[1] = status.players.sample
    server_info_ref[1] = get_raw_qpc()


async def scan_servers():
    global servers
    serversL = servers
    tasks = []
    last_bucket_index = 0
    while True:
        tasks.clear()
        last_bucket_index, items, geted = serversL.items_inaccurate(
            last_bucket_index
        )
        if not geted:
            continue
        now_timestamp = get_raw_qpc()
        for server_hash, server_info in items:
            if now_timestamp - server_info[1] <= scan_delay_per_server:
                continue
            tasks.append(scan_server(server_info))
        await asyncio.gather(*tasks, return_exceptions=True)


def scan_servers_wrapper():
    asyncio.run(scan_servers())


async_scan_servers_thread = threading.Thread(
    target=scan_servers_wrapper, daemon=True
)
async_scan_servers_thread.start()


def advance_style_top_server(
    src_ip, port, last_scan_timestamp, motd, player_count, player_sample
):
    return f"""\
\033[1;48;2;220;0;0m\033[38;2;255;255;255m╔════════════ Top 1. {src_ip}:{port} \033[22;3;38;2;180;180;180m(last_scan: {qpc_to_utc_datetime(last_scan_timestamp)}) ════════════\033[0m
\033[1;48;2;220;0;0m\033[38;2;255;255;255m║\033[0m {parse_mc_style(motd)}\033[0m
\033[1;48;2;220;0;0m\033[38;2;255;255;255m║\033[0m \033[1;38;2;255;172;0m{player_count} players online, sample: {[player.name for player in player_sample]}\033[0m
"""


start_mcast_hold_daemon()
already_holded_multicast.wait()

print_res = []
players_delta_max = 256
block_server_ignore_sample_count = 10
# de_repeat = set()
while True:
    sys.stdout.buffer.write(b"\033[H\033[2J\033[3J")
    print_res.clear()
    # de_repeat.clear()
    for k, v in servers.to_dict().items():
        # if k in de_repeat: continue
        print_res.append((k, v))
        # de_repeat.add(k)
    print_res.sort(key=lambda x: x[1][4][0], reverse=True)

    is_first = True
    for (src_ip, port), (
        timestamp,
        last_scan_timestamp,
        motd,
        server_obj,
        (player_count, player_sample),
    ) in print_res:
        if player_sample is None:
            continue
        if (
            player_count - len(player_sample) > players_delta_max
            and len(player_sample) < block_server_ignore_sample_count
        ):
            continue
        try:
            server_addr = src_ip.decode("utf-8") + ":" + port
            server_addr += " " * max(0, 21 - len(server_addr))
            if is_first:
                sys.stdout.buffer.write(
                    advance_style_top_server(
                        src_ip,
                        port,
                        last_scan_timestamp,
                        motd,
                        player_count,
                        player_sample,
                    ).encode("utf-8")
                )
                is_first = False
            else:
                sys.stdout.buffer.write(
                    f"{server_addr}- {parse_mc_style(motd)} - {player_count} - {[player.name for player in player_sample]}\n".encode(
                        "utf-8"
                    )
                )
        # except: pass
        finally:
            pass

    sys.stdout.buffer.flush()
    sys.stdout.flush()
    time.sleep(0.05)
