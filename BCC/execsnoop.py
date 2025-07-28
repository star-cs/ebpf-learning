from bcc import BPF
from bcc.utils import printb

b = BPF(src_file="execsnoop.c")

print("%-6s %-16s %-3s %s" % ("PID", "COMM", "RET", "ARGS"))

# 3) 定义性能事件打印函数
def print_event(cpu, data, size):
    # event data struct is generated from "struct data_t" by bcc
    event = b["events"].event(data)
    printb(b"%-6d %-16s %-3d %-16s" % (event.pid, event.comm, event.retval, event.argv))

# 4) loop with callback to print_event
# 当内核有新数据写入缓冲区时，自动触发此回调
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()