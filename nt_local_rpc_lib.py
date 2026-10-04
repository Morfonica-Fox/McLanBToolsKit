# Copyright (c) [2026] [Morfonica_Fox]
# [McLanBToolsKit] is licensed under Mulan PubL v2.
# You can use this software according to the terms and conditions of the Mulan PubL v2.
# You may obtain a copy of Mulan PubL v2 at:
#         http://license.coscl.org.cn/MulanPubL-2.0
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PubL v2 for more details.

# 注意: 本库**完全**没有任何权限校验逻辑, 请勿在安全要求场景使用本库
# (手动Markdown加粗 qwq)
# Notice: This library has **no** permission verification logic at all, please do not use this library in security scenarios
# (Manual Markdown Bold qwq)

# import pickle
# from collections import deque
import ctypes
import json
import marshal
import queue
import threading
from ctypes import wintypes
from typing import Optional

import atomics


# fmt: off
class errs(Exception): pass  # noqa: N801, N818
class SecurityCheckException(errs): pass
# fmt: on


class WIN32_FIND_DATAW(ctypes.Structure):  # noqa: N801
    _fields_ = [
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", wintypes.FILETIME),
        ("ftLastAccessTime", wintypes.FILETIME),
        ("ftLastWriteTime", wintypes.FILETIME),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("dwReserved0", wintypes.DWORD),
        ("dwReserved1", wintypes.DWORD),
        ("cFileName", ctypes.c_wchar * 260),
        ("cAlternateFileName", ctypes.c_wchar * 14),
    ]


class SECURITY_ATTRIBUTES(ctypes.Structure):  # noqa: N801
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", wintypes.BOOL),
    ]


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

ERROR_NO_MORE_FILES = 18

# fmt: off
INVALID_HANDLE_VALUE       = wintypes.HANDLE(-1).value
PIPE_ACCESS_INBOUND        = 0x01
PIPE_ACCESS_OUTBOUND       = 0x02
PIPE_ACCESS_DUPLEX         = 0x03
PIPE_REJECT_REMOTE_CLIENTS = 0x08
PIPE_TYPE_BYTE             = 0x00
PIPE_TYPE_MESSAGE          = 0x04
PIPE_READMODE_BYTE         = 0x00
PIPE_READMODE_MESSAGE      = 0x02
PIPE_WAIT                  = 0x00
PIPE_NOWAIT                = 0x01
PIPE_UNLIMITED_INSTANCES   = 255
BUFSIZE                    = 4096
TIMEOUT                    = 5000
GENERIC_READ               = 0x80000000
GENERIC_WRITE              = 0x40000000
OPEN_EXISTING              = 3
FILE_ATTRIBUTE_NORMAL      = 0x80
# fmt: on

kernel32.FindFirstFileW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(WIN32_FIND_DATAW)]
kernel32.FindFirstFileW.restype = wintypes.HANDLE

kernel32.FindNextFileW.argtypes = [wintypes.HANDLE, ctypes.POINTER(WIN32_FIND_DATAW)]
kernel32.FindNextFileW.restype = wintypes.BOOL

kernel32.FindClose.argtypes = [wintypes.HANDLE]
kernel32.FindClose.restype = wintypes.BOOL

# 函数原型
kernel32.CreateNamedPipeW.argtypes = [
    ctypes.c_wchar_p,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.c_void_p,
]
kernel32.CreateNamedPipeW.restype = wintypes.HANDLE

kernel32.ConnectNamedPipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
kernel32.ConnectNamedPipe.restype = wintypes.BOOL

kernel32.ReadFile.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.c_void_p,
]
kernel32.ReadFile.restype = wintypes.BOOL

kernel32.WriteFile.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.c_void_p,
]
kernel32.WriteFile.restype = wintypes.BOOL

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

kernel32.CreateFileW.argtypes = [
    ctypes.c_wchar_p,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
kernel32.CreateFileW.restype = wintypes.HANDLE

kernel32.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
kernel32.DisconnectNamedPipe.restype = wintypes.BOOL

kernel32.LocalFree.argtypes = [ctypes.c_void_p]

advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(wintypes.DWORD),
]


def build_local_only_security_attributes():
    sddl = r"D:(A;;GA;;;S-1-2-0)"
    sd_ptr = ctypes.c_void_p()

    ret = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(sd_ptr), None
    )
    if ret == 0:
        raise OSError(
            f"ConvertStringSecurityDescriptorToSecurityDescriptorW failed, err={ctypes.get_last_error()}"
        )

    sa = SECURITY_ATTRIBUTES()
    sa.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
    sa.bInheritHandle = False
    sa.lpSecurityDescriptor = sd_ptr.value
    return sa, sd_ptr


def free_security_descriptor(sd_ptr: ctypes.c_void_p):
    if sd_ptr.value is not None and sd_ptr.value != 0:
        res = kernel32.LocalFree(sd_ptr)
        if res is not None and (err_code := ctypes.get_last_error()) != 0:
            raise OSError(f"LocalFree failed, err={err_code}")
        sd_ptr.value = 0


def create_named_pipe_server(pipe_name: str) -> wintypes.HANDLE:
    sa, sd_ptr = build_local_only_security_attributes()
    h_pipe = kernel32.CreateNamedPipeW(
        pipe_name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        BUFSIZE,
        BUFSIZE,
        TIMEOUT,
        ctypes.byref(sa),
    )
    if h_pipe == INVALID_HANDLE_VALUE:
        err = ctypes.get_last_error()
        free_security_descriptor(sd_ptr)
        raise OSError(f"CreateNamedPipe failed, err={err}")
    free_security_descriptor(sd_ptr)
    return h_pipe


def connect_pipe_server(h_pipe: wintypes.HANDLE) -> bool:
    ok = kernel32.ConnectNamedPipe(h_pipe, None)
    if not ok:
        err = ctypes.get_last_error()
        if err != 535:  # ERROR_PIPE_CONNECTED
            raise OSError(f"ConnectNamedPipe failed, err={err}")
    return True


def pipe_read(h_pipe: wintypes.HANDLE, buf_size=BUFSIZE) -> int | bytearray:
    buf = ctypes.create_string_buffer(buf_size)
    bytes_read = wintypes.DWORD()
    ok = kernel32.ReadFile(h_pipe, buf, buf_size, ctypes.byref(bytes_read), None)
    if not ok:
        err = ctypes.get_last_error()
        if err == 109:
            return 109
        raise OSError(f"ReadFile failed, err={err}")
    return bytearray(buf.raw[: bytes_read.value])


def pipe_write(h_pipe: wintypes.HANDLE, data: bytes) -> int:
    bytes_written = wintypes.DWORD()
    ok = kernel32.WriteFile(h_pipe, data, len(data), ctypes.byref(bytes_written), None)
    if not ok:
        err = ctypes.get_last_error()
        if err == 109:
            return 109
        raise OSError(f"WriteFile failed, err={err}")
    return bytes_written.value


def open_named_pipe_client(pipe_name: str) -> wintypes.HANDLE:
    h_pipe = kernel32.CreateFileW(
        pipe_name,
        GENERIC_READ | GENERIC_WRITE,
        0,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if h_pipe == INVALID_HANDLE_VALUE:
        raise OSError(f"CreateFileW pipe client fail, err={ctypes.get_last_error()}")
    return h_pipe


def enum_named_pipes() -> list[str]:
    find_data = WIN32_FIND_DATAW()
    h_find = kernel32.FindFirstFileW(r"\\.\pipe\*", ctypes.byref(find_data))
    if h_find == wintypes.HANDLE(-1).value:
        err = ctypes.get_last_error()
        if err == ERROR_NO_MORE_FILES:
            return []
        raise OSError(f"FindFirstFileW failed err={err}")
    pipes = []
    while True:
        name = find_data.cFileName
        if name not in (".", ".."):
            pipes.append(name)
        ok = kernel32.FindNextFileW(h_find, ctypes.byref(find_data))
        if not ok:
            err = ctypes.get_last_error()
            if err == ERROR_NO_MORE_FILES:
                break
            kernel32.FindClose(h_find)
            raise OSError(f"FindNextFileW err={err}")
    kernel32.FindClose(h_find)
    return pipes


def close_handle(h):
    kernel32.CloseHandle(h)


class rpc_server:  # noqa: N801
    def __init__(self, service_name: str, thread_name: Optional[str] = None):
        self._service_name = service_name
        self._pipe_name = f"\\\\.\\pipe\\{service_name}"
        self._thread_name = thread_name if thread_name else f"rpc_server_{service_name}"
        self._command_queue = queue.SimpleQueue()
        self._handle = None
        self._is_stopped = False
        print(
            f"RPC server started, service name: {service_name}, thread name: {self._thread_name}"
        )

    def recivier_thread(self):
        try:
            while not self._is_stopped:
                self._handle = h = create_named_pipe_server(self._pipe_name)
                buf = bytearray()
                connect_pipe_server(h)
                while not self._is_stopped:
                    data = pipe_read(h)
                    if data == 109:
                        break
                    buf.extend(data)
                    pos = buf.find(b"\n")
                    if pos != -1:
                        command = buf[:pos]  # 排除\n
                        del buf[: pos + 1]
                        self._command_queue.put(json.loads(command.decode("utf-8")))
                try:
                    close_handle(h)
                except Exception:
                    pass
        finally:
            try:
                close_handle(h)  # type: ignore
            except Exception:
                pass

    def command_exec_frame(self):
        try:
            command: dict = self._command_queue.get()
            opcode = command.get("opcode", None)
            will_return = None
            match opcode:
                case "eval":
                    is_bytecode = command.get("is_bytecode", False)
                    expression = command.get("expression", "")
                    request_result = command.get("result", False)
                    local_namespace = command.get("local_namespace", {})
                    is_async = command.get("is_async", False)
                    is_deamon = command.get("is_daemon", False)

                    if is_bytecode:
                        expression = marshal.loads(expression)

                    if is_async:
                        threading.Thread(
                            target=eval,
                            args=(expression, globals(), local_namespace),
                            name=f"{self._thread_name}.eval_async",
                            daemon=is_deamon,
                        ).start()
                    else:
                        result = eval(expression, globals(), local_namespace)
                        if request_result:
                            will_return = {"result": local_namespace}

                case "exec":
                    is_bytecode = command.get("is_bytecode", False)
                    expression = command.get("expression", "")
                    request_result = command.get("result", False)
                    local_namespace = command.get("local_namespace", {})
                    is_async = command.get("is_async", False)
                    is_deamon = command.get("is_daemon", False)

                    if is_bytecode:
                        expression = marshal.loads(expression)

                    if is_async:
                        threading.Thread(
                            target=exec,
                            args=(expression, globals(), local_namespace),
                            name=f"{self._thread_name}.exec_async",
                            daemon=is_deamon,
                        ).start()
                    else:
                        exec(expression, globals(), local_namespace)
                        if request_result:
                            will_return = {"result": local_namespace}

                case "func_call":
                    root_object = command.get("root_object", {})
                    path_chain = command.get("path_chain", [])
                    args = command.get("args", [])
                    kwargs = command.get("kwargs", {})
                    request_result = command.get("result", False)
                    async_call = command.get("async_call", False)

                    now_namespace = globals()[root_object]
                    for name in path_chain:
                        now_namespace = getattr(now_namespace, name)

                    if async_call:
                        threading.Thread(
                            target=now_namespace,
                            args=args,
                            kwargs=kwargs,
                            name=f"{self._thread_name}.func_call_async",
                            daemon=is_deamon,
                        ).start()
                    else:
                        result = now_namespace(*args, **kwargs)
                        if request_result:
                            will_return = {"result": result}

                case "obj_write":
                    root_object = command.get("root_object", {})
                    path_chain = command.get("path_chain", [])
                    data = command.get("data", {})

                    now_namespace = globals()[root_object]
                    for name in path_chain[:-1]:
                        now_namespace = getattr(now_namespace, name)

                    setattr(now_namespace, path_chain[-1], data)

                case "obj_read":
                    root_object = command.get("root_object", {})
                    path_chain = command.get("path_chain", [])

                    now_namespace = globals()[root_object]
                    for name in path_chain[:-1]:
                        now_namespace = getattr(now_namespace, name)

                    obj = getattr(now_namespace, path_chain[-1])
                    will_return = {"obj": obj}

                case "obj_del":
                    root_object = command.get("root_object", {})
                    path_chain = command.get("path_chain", [])

                    now_namespace = globals()[root_object]
                    for name in path_chain[:-1]:
                        now_namespace = getattr(now_namespace, name)

                    delattr(now_namespace, path_chain[-1])

            if will_return is not None:
                will_return.update({
                    "service_name": self._service_name,
                    "op_id": command.get("op_id", None),
                })
                pipe_write(self._handle, json.dumps(will_return))
                pipe_write(self._handle, b"\n")

        except:
            pass
        finally:
            pass
        # 调试用 注释掉except则异常能被捕获并抛栈

    def command_exec_thread(self):
        while not self._is_stopped:
            self.command_exec_frame()

    def start_recivier(self):
        self.thread_recivier = threading.Thread(
            target=self.recivier_thread,
            name=self._thread_name + " recivier",
            daemon=True,
        )
        self.thread_recivier.start()

    def start_command_exec(self):
        self.thread_command_exec = threading.Thread(
            target=self.command_exec_thread,
            name=self._thread_name + " command exec",
            daemon=True,
        )
        self.thread_command_exec.start()

    def stop(self):
        self._is_stopped = True
        close_handle(self._handle)
        self.thread_recivier.join()
        self.thread_command_exec.join()
        self.thread_recivier = None
        self.thread_command_exec = None
        self._is_stopped = False
        self._handle = None


class rpc_client:  # noqa: N801
    def __init__(self, service_name: str):
        self._service_name = service_name
        self._pipe_name = f"\\\\.\\pipe\\{service_name}"
        self._handle = None
        self._results_callback = None
        self._reply_events = {}
        self._buf_events = {}
        # 思考良久 环形缓冲区太难做了喵...
        self._is_stopped = False
        self._next_op_id = atomics.atomic(width=8, atype=atomics.UINT)
        # 应该没有人的代码会让超过 1844'6744'0737'0955'1615 (比 Elon Musk 历史最高纸面身价还高) 个操作积压在队列里不消费吧
        # 真有人能写出那种代码...... Ta可能需要考虑用rust 因为python拖Ta代码性能了
        # 不过没事 这个类型自带溢出环绕 除非真的有那么多操作积压不消费 否则可以放心使用
        # (手动喵)

    def attach(self):
        self._handle = open_named_pipe_client(self._pipe_name)

    def detach(self):
        if self._handle is not None:
            close_handle(self._handle)
            self._handle = None

    def basic_write(self, command: dict):
        command["op_id"] = self._next_op_id.fetch_add(1)
        pipe_write(self._handle, json.dumps(command).encode("utf-8") + b"\n")

    def register_results_callback(self, callback):
        if not callable(callback):
            raise ValueError("callback must be callable")
        self._results_callback = callback

    def unregist_results_callback(self):
        self._results_callback = None

    def get_next_op_id(self):
        # 警告!!! 为调试API 请严防 TOCTOU 攻击 生产环境严禁使用
        return self._next_op_id.load()

    def set_next_op_id(self, op_id, ignore_overflow_check: bool = False):
        # 警告!!! 为调试API 如果队列有未消费的结果 那么设置此值可能会导致旧结果被新结果覆盖
        if not ignore_overflow_check and len(self._buf_events) > 0:
            raise SecurityCheckException("队列有未消费的结果且尝试设置下一个op_id")
        self._next_op_id.store(op_id)

    def reader_thread(self):
        buf = bytearray()
        while not self._is_stopped:
            buf.extend(pipe_read(self._handle))
            pos = buf.find(b"\n")
            if pos != -1:
                result = json.loads(buf[:pos])  # 排除\n
                del buf[: pos + 1]
                if self._results_callback is not None:
                    self._results_callback(result)
                self._buf_events[result["op_id"]] = result
                self._reply_events.setdefault(result["op_id"], threading.Event()).set()

    def wait_for_result(self, op_id):
        self._reply_events.setdefault(op_id, threading.Event()).wait()
        # 防止看不懂 接下来是解释喵
        # 如果reader_thread先读到结果了 那么reader_thread新建event并且置为true 函数进入wait通过直接继续
        # 如果函数先开始等待了 那么函数进入wait会阻塞 直到reader_thread置event为true 函数继续
        del self._reply_events[op_id]
        return self._buf_events.pop(op_id, None)

    def exec(self, command, is_compiled=False, is_async=False, is_daemon=False):
        if is_compiled:
            command = marshal.dumps(command)
        pipe_write(
            self._handle,
            json.dumps({
                "op_id": (op_id := self._next_op_id.fetch_add(1)),
                "opcode": "exec",
                "is_bytecode": is_compiled,
                "expression": command,
                "result": True,
                "local_namespace": {},
                "is_async": is_async,
                "is_daemon": is_daemon,
            }).encode("utf-8")
            + b"\n",
        )
        return op_id


if __name__ == "__main__":
    import sys

    if len(sys.argv) == 1:
        rpc_server_0 = rpc_server("AliciaSoftware.BasicLibrary.NTLocalRPCLib.Test")
        rpc_server_0.start_recivier()
        input()
    elif sys.argv[1] == "client":
        rpc_client_0 = rpc_client("AliciaSoftware.BasicLibrary.NTLocalRPCLib.Test")
        rpc_client_0.attach()
        while True:
            cmd = input("> ")
            if cmd == "!!exit":
                break
            op_id = rpc_client_0.exec(cmd)
            print(f"op_id: {op_id}")
            print(rpc_client_0.wait_for_result(op_id))
        rpc_client_0.detach()
