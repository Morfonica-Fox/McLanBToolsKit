import ctypes
from ctypes import wintypes

# 懒得改这个适配扫描器了 改了又一堆bug 之后再改吧

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

class LargeInt(ctypes.Structure):
    _fields_ = [("QuadPart", ctypes.c_int64)]

# QPC读取
def get_raw_qpc() -> int:
    li = LargeInt()
    kernel32.QueryPerformanceCounter(ctypes.byref(li))
    return li.QuadPart

def get_qpc_frequency() -> int:
    li = LargeInt()
    kernel32.QueryPerformanceFrequency(ctypes.byref(li))
    return li.QuadPart

# 绑定 GetSystemTimePreciseAsFileTime
GetSystemTimePreciseAsFileTime = kernel32.GetSystemTimePreciseAsFileTime
GetSystemTimePreciseAsFileTime.argtypes = [ctypes.POINTER(wintypes.FILETIME)]
GetSystemTimePreciseAsFileTime.restype = wintypes.BOOL

def get_qpc_anchor() -> tuple[int, int, int]:
    qpc = LargeInt()
    ft = wintypes.FILETIME()
    freq = LargeInt()
    kernel32.QueryPerformanceFrequency(ctypes.byref(freq))
    kernel32.QueryPerformanceCounter(ctypes.byref(qpc))
    GetSystemTimePreciseAsFileTime(ctypes.byref(ft))
    ft_q = (ft.dwHighDateTime << 32) | ft.dwLowDateTime
    return qpc.QuadPart, ft_q, freq.QuadPart

QPC_ANCHOR, FT_ANCHOR, QPC_FREQ = get_qpc_anchor()

def qpc_to_filetime(qpc_tick: int) -> int:
    delta = qpc_tick - QPC_ANCHOR
    delta_100ns = delta * 10_000_000 // QPC_FREQ
    return FT_ANCHOR + delta_100ns