from __future__ import annotations

import os
os.chdir(os.path.dirname(__file__))

import io
import sys
import time
import ctypes
import struct
import socket
import importlib
import threading
import subprocess

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from mc_lanb_advtools import *

import pydivert

import mc_lanb_cond
mc_lanb_cond.kept_data = {}

def install_whl_package(whl_filename: str):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    whl_path = os.path.join(current_dir, whl_filename)
    if not os.path.exists(whl_path):
        return False

    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", whl_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT
        )
        return True
    except subprocess.CalledProcessError:
        return False

def enable_vt_console():
    if sys.platform == "win32":
        kernel32 = ctypes.windll.kernel32
        h = kernel32.GetStdHandle(-11)
        if h == -1:
            return False
        mode = ctypes.c_uint()
        if not kernel32.GetConsoleMode(h, ctypes.byref(mode)):
            return False
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        new_mode = mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
        if not kernel32.SetConsoleMode(h, new_mode):
            return False
        return True

enable_vt_console()

def mc_lan_multicast_hold(mc_mcast_group: str = '224.0.2.60', mc_mcast_port: int = 4445):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except: pass

    sock.bind(("0.0.0.0", mc_mcast_port))

    mreq = struct.pack("4sl", socket.inet_aton(mc_mcast_group), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    while True:
        try:
            sock.recvfrom(1024)
        except socket.error:
            pass

def start_mcast_hold_daemon():
    t = threading.Thread(target=mc_lan_multicast_hold, daemon=True)
    t.start()

#block_ips = [
#    "26.90.118.155",
#    "26.184.50.214"
#]

start_mcast_hold_daemon()

def reload():
    global mc_lanb_cond
    mc_lanb_cond.will_update(time.time())
    mc_lanb_cond = importlib.reload(mc_lanb_cond)
    mc_lanb_cond.on_updated(time.time())

reload()

class CodeEventHandler(FileSystemEventHandler):
    def __init__(self, 
                 #condition: ExecutebleCondition
                 ):
        #self._condition = condition
        self.last_updated_time = -1
    
    def on_modified_bak(self, event):
        if time.time() - self.last_updated_time < 0.1:
            return
        fpath, encoding, clear_namespace = self._condition.binder
        if event.src_path != fpath: return
        with open(fpath, 'r', encoding=encoding) as f:
            self._condition.set_code(f.read(), clear_namespace=clear_namespace)
        self.last_updated_time = time.time()
    
    def on_modified(self, event):
        if time.time() - self.last_updated_time < 0.1: return
        reload()

class ExecutebleCondition: # 已废弃
    _code: str
    _namespace: dict
    _compiled_source_code: str
    _id: str
    _binder: tuple[str, str, bool] | None
    _observer: Observer | None # type: ignore
    _handler: CodeEventHandler | None
    default_cond_fallback: bool
    auto_clear_namespace: bool
    
    def __init__(self):
        self._code = ''
        self._id = f'ExecutebleCondition at {id(self)}'
        self._namespace = {'kept_data': {}}
        self._binder = None
        self._observer = None
        self._handler = None
        self.default_cond_fallback = False
    
    def __getitem__(self, key: str):
        return self.get_data(key)
    
    @property
    def namespace(self):
        return self._namespace
    
    @namespace.setter
    def namespace(self, namespace: dict):
        self._namespace = namespace
    
    def injection(self, injection_namespace: dict):
        self._namespace.update(injection_namespace)
    
    @namespace.deleter
    def namespace(self):
        kept_data = self._namespace.get('kept_data', {})
        self._namespace = {'kept_data': kept_data}
    
    def clear_namespace(self):
        kept_data = self._namespace.get('kept_data', {})
        self._namespace.clear() # clear func 与 del func 效果不一样(字典id会变)
        self._namespace['kept_data'] = kept_data
        
    @property
    def id(self):
        return self._id
    
    def set_code(self, code: str, clear_namespace: bool = None, injection_namespace: dict = {}, update: bool = True, ):
        self._code = code
        
        if not update: return
        
        if clear_namespace is None: clear_namespace = self.auto_clear_namespace
        if clear_namespace: self.clear_namespace()
        self._namespace.update(injection_namespace)
        self._namespace['last_updated_time'] = time.time()
        
        try:
            try:
                cb = self._namespace.get('will_update', None)
                if callable(cb): cb(time.time(), code)
            except Exception as e: print(f"\033[0;1;31m[!] 由 {self._id} 输出日志: 通知条件判断代码即将更新时出错: {e}\033[0m")
            
            exec(compile(self._code, self._id, 'exec'), self._namespace, self._namespace)
            self._compiled_source_code = self._code
            
            try:
                cb = self._namespace.get('on_updated', None)
                if callable(cb): cb(time.time())
            except Exception as e: print(f"\033[0;1;31m[!] 由 {self._id} 输出日志: 通知条件判断代码被更新时出错: {e}\033[0m")
        #except Exception as e:
        #    print(f"\033[0;1;31m[!] 由 {self._id} 输出日志: 初始化条件判断代码出错: {e}\033[0m")
        finally: pass
    
    @property
    def code(self):
        return self._code
    
    @code.setter
    def code(self, code: str):
        self.set_code(code)
    
    @property
    def compiled_code(self):
        return self._compiled_code
    
    def format_exception(self, exception: BaseException):
        source_code = self._code
        stack_string_buffer = io.StringIO('\033[0;31mTraceback (most recent call last):\033[0m\n')
        tb = exception.__traceback__
        source_code_lines = source_code.split('\n')
        
        if tb is not None:
            while tb:
                filename = tb.tb_frame.f_code.co_filename
                if filename != self._id:
                    tb = tb.tb_next
                    continue
                
                name = tb.tb_frame.f_code.co_name
                lineno = tb.tb_lineno
                line = source_code_lines[lineno-1]
                stack_string_buffer.write(f'\033[0;31m  File \033[0;35m"{filename}"\033[0;31m, line \033[0;36m{lineno}\033[0;31m, in \033[0;33m{name}\033[0m\n    \033[0;38;2;255;108;145m{line}\033[0m\n')
                
                tb = tb.tb_next
        stack_string_buffer.write(f'\033[0;38;2;255;168;205m{type(exception).__name__}: {str(exception)}\033[0m')
        
        return stack_string_buffer.getvalue()
    
    def get_data(self, name: str, default=None, force_get: bool = False):
        if name in self._namespace.get('__all__', []) or force_get: return self._namespace.get(name, default)
        else:                                                       return default
    
    def bind_to(self, file_path: str, encoding: str = 'utf-8', clear_namespace: bool = None):
        if clear_namespace is None: clear_namespace = self.default_cond_fallback
        self._binder = (os.path.abspath(file_path), encoding, clear_namespace)
        self._handler = CodeEventHandler(self)
        self._observer = Observer()
        self._observer.schedule(self._handler, os.path.dirname(self._binder[0]), recursive=False)
        self._observer.start()
        with open(file_path, 'r', encoding=self._binder[1]) as f: self.set_code(f.read(), clear_namespace=self._binder[2])
    
    bind = bind_to
    
    def unbind(self):
        if not self._binder: return
        self._observer.stop()
        self._observer.join()
        self._observer = None
        self._handler = None
        self._binder = None
    
    bind_cancel = cancel_bind = unbind
    
    @property
    def is_bound(self):
        return self._binder is not None
    
    is_bound_to = is_bound_to_file = is_bound_to_path = is_bound_to_file_path = is_bound
    was_bound = was_bound_to = was_bound_to_file = was_bound_to_path = was_bound_to_file_path = is_bound
    
    @property
    def binder(self):
        return self._binder

#condition = ExecutebleCondition()
#condition.bind_to('mc_lanb_cond.py')
#condition.auto_clear_namespace   = True
#condition.forceget_on_dictlike   = True

def main():
    filter_str = f"inbound and udp and udp.DstPort == 4445"
    print('\033[0;1;33m' + '将使用指定的 WFL 过滤器启动UDP局域网广播包捕获: ', filter_str, end='\033[0m\n')
    
    obs = Observer()
    hdr = CodeEventHandler()
    obs.schedule(hdr, os.path.dirname(__file__), recursive=False)
    obs.start()
    
    reload()

    try:
        with pydivert.WinDivert(filter_str) as w:
            while True:
                pkt: pydivert.Packet = w.recv()
                try:
                    mc_lanb_cond.handler(pkt, w)
                    #condition['handler'](pkt, w)
                except Exception as e:
                    #print(condition.format_exception(e))
                    pass
                #finally:
                #    pass
                #print(f"[{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))}] 已拦截：{pkt.src_addr} -> {pkt.dst_addr} UDP")
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()