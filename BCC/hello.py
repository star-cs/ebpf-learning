#!/usr/bin/env python3

from bcc import BPF

b = BPF(src_file="hello.c")

# 处将 BPF 程序挂载到内核探针，其中 do_sys_openat2() 是系统调用 openat()  在内核中的实现
b.attach_kprobe(event="do_sys_openat2", fn_name="hello_world")

# 读取内核调试文件 /sys/kernel/debug/tracing/trace_pipe 的内容，并打印到标准输出中
b.trace_print()
