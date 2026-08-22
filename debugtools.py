import sys
import threading
import traceback
from typing import BinaryIO
from types import FrameType


def wrapper_core_thread(func, thread_name):
    try:
        func()
    finally:
        with open("debug_stack.txt", "wb") as f:
            dump_all_thread_stacks(f)
        log_debug_exception(f"{thread_name} exited!")


def dump_all_thread_stacks(output_buffer: BinaryIO = sys.stdout.buffer):
    """
    打印所有活跃线程：线程名、tid、完整调用栈、每帧局部变量、全局变量
    :param limit_var_length: 变量repr最大输出长度，避免打印巨大对象
    """
    output_buffer.write(f"======== DUMP ALL THREADS | Time: {threading.get_ident()} main tid ========\n".encode("utf-8"))  # fmt: skip

    thread_map: dict[int, threading.Thread] = {
        t.ident: t for t in threading.enumerate() if t.ident is not None
    }
    # 获取所有线程的帧快照；注意：仅Python层，C阻塞时帧为旧状态
    thread_frames: dict[int, FrameType] = sys._current_frames()

    for tid, frame in thread_frames.items():
        thread = thread_map.get(tid)
        thread_name = thread.name if thread else f"<unknown-thread-{tid}>"
        is_daemon = thread.daemon if thread else "?"

        output_buffer.write(f"\n-------- Thread TID={tid} | Name={thread_name} | daemon={is_daemon} --------\n".encode("utf-8"))  # fmt: skip
        if frame is None:
            output_buffer.write(
                "    [NO PYTHON FRAME] (thread blocked inside C code)\n".encode(
                    "utf-8"
                )
            )
            continue

        # 遍历栈帧，从当前往调用者回溯
        for frame_info in traceback.extract_stack(frame):
            pass

        # 手动遍历帧
        current_frame = frame
        frame_idx = 0
        while current_frame is not None:
            fi = traceback.FrameSummary(
                current_frame.f_code.co_filename,
                current_frame.f_lineno,
                current_frame.f_code.co_name,
            )
            output_buffer.write(f"\n  Frame[{frame_idx}] {fi.filename}:{fi.lineno} | func:{fi.name}\n".encode("utf-8"))  # fmt: skip
            frame_idx += 1

            # 局部变量
            output_buffer.write("      -- Locals:\n".encode("utf-8"))
            for k, v in current_frame.f_locals.items():
                try:
                    rep = repr(v)
                    output_buffer.write(f"        {k:<25} = {rep}\n".encode("utf-8"))  # fmt: skip
                except Exception as e:
                    output_buffer.write(f"        {k:<25} = <repr failed: {e!r}>\n".encode("utf-8"))  # fmt: skip

            # 全局变量
            output_buffer.write("      -- Globals:\n".encode("utf-8"))
            for k, v in current_frame.f_globals.items():
                if k == "__builtins__":
                    continue
                try:
                    rep = repr(v)
                    output_buffer.write(f"        {k:<25} = {rep}\n".encode("utf-8"))  # fmt: skip
                except Exception as e:
                    output_buffer.write(f"        {k:<25} = <repr failed: {e!r}>\n".encode("utf-8"))  # fmt: skip

            current_frame = current_frame.f_back

    output_buffer.flush()


def log_debug_exception(prompt: str, exit: bool = True, exit_code=1):
    print(f"\033[1;38;2;255;0;0mFATAL Debug Exception! {prompt}\033[0m")
    if exit:
        sys.exit(exit_code)
