#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

// 系统头文件先于本地
#include "execsnoop.h"
#include "execsnoop.skel.h"

// Handler for libbpf errors and debug info callback.
static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args)
{
#ifdef DEBUGBPF
    return vfprintf(stderr, format, args);
#else
    return 0;
#endif
}

// Handler for lost events.
void handle_lost_events(void* ctx, int cpu, __u64 lost_cnt)
{
    fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

// Heandler for print arguments (args are separated by '\0').
static void print_args(const struct event* e)
{
    int args_counter = 0;

    for (int i = 0; i < e->args_size && args_counter < e->args_count; i++)
    {
        char c = e->args[i];
        if (c == '\0')
        {
            args_counter++;
            putchar(' ');
        }
        else
        {
            putchar(c);
        }
    }
    if (e->args_count > TOTAL_MAX_ARGS)
    {
        fputs(" ...", stdout);
    }
}

// Handler for each perf event.
void handle_event(void* ctx, int cpu, void* data, __u32 data_sz)
{
    const struct event* e = data;
    printf("%-16s %-6d %3d ", e->comm, e->pid, e->retval);
    print_args(e);
    putchar('\n');
}

// Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything it needs.
static void bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new))
    {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }
}

int main(int argc, char** argv)
{
    // 定义BPF程序和性能事件缓冲区
    struct execsnoop_bpf* skel;
    struct perf_buffer*   pb = NULL;
    int                   err;

    // 1. 设置调试输出函数
    libbpf_set_print(libbpf_print_fn);

    // 2. 增大 RLIMIT_MEMLOCK(默认值通常太小,不足以存入BPF映射的内容)
    bump_memlock_rlimit();

    // 3. 初始化 BPF
    skel = execsnoop_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // 4. 加载BPF字节码
    err = execsnoop_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    // 5. 挂载BPF字节码到跟踪点
    err = execsnoop_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    struct perf_buffer_opts pb_opts = {
        .sample_cb = handle_event,
        .lost_cb   = handle_lost_events,
    };
    // 6. 配置性能事件回调函数
    pb  = perf_buffer__new(bpf_map__fd(skel->maps.events), 64, &pb_opts);
    err = libbpf_get_error(pb);
    if (err)
    {
        pb = NULL;
        fprintf(stderr, "failed to open perf buffer: %d\n", err);
        goto cleanup;
    }

    printf("%-16s %-6s %3s %s\n", "COMM", "PID", "RET", "ARGS");

    // 7. 从缓冲区中循环读取数据
    while ((err = perf_buffer__poll(pb, 100)) >= 0)
        ;
    printf("Error polling perf buffer: %d\n", err);

cleanup:
    perf_buffer__free(pb);
    execsnoop_bpf__destroy(skel);
    return err != 0;
}