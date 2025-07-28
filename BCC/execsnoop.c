#include <linux/fs.h>
#include <linux/sched.h>

#define ARGSIZE           64
#define TOTAL_MAX_ARGS    5
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)
#define LAST_ARG          (FULL_MAX_ARGS_ARR - ARGSIZE)

// 1 映射
struct data_t
{
    u32          pid;
    char         comm[TASK_COMM_LEN];
    int          retval;
    unsigned int args_size;
    char         argv[FULL_MAX_ARGS_ARR];
};

BPF_PERF_OUTPUT(events); // 定义了一个名为events的性能事件映射，内核与用户态间的实时数据通道

BPF_HASH(tasks, u32, struct data_t); // 定义了一个哈希映射,其键为 32 位的进程  PID,而值则是进程基本信息 data_t。

// 3 辅助函数,从参数数组中读取字符串参数(限定最长  ARGSIZE)
static int __buf_read_arg_str(struct data_t* data, const char* ptr)
{
    if (data->args_size >= LAST_ARG)
    {
        return -1;
    }
    // bpf_probe_read_user_str() 返回的是包含字符串结束符 \0
    // 的长度。为了拼接所有的字符串,在计算已读取参数长度的时候,需要把 \0 排除在外。
    int ret = bpf_probe_read_user_str(&data->argv[data->args_size], ARGSIZE, ptr);

    if (ret > ARGSIZE || ret < 0)
    {
        return -1;
    }

    data->args_size += (ret - 1);
    return 0;
}

// 2定义跟踪点的处理函数
// BCC 会将所有的参数放入 args 这个变量中,这样使用 args-><参数名> 就可以访问跟踪点的参数值。
/**
$ bpftrace -lv tracepoint:syscalls:sys_enter_execve
tracepoint:syscalls:sys_enter_execve
    int __syscall_nr
    const char * filename
    const char *const * argv
    const char *const * envp
*/
TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    // variables definitions
    unsigned int ret  = 0;
    const char** argv = (const char**)(args->argv);

    // get the pid and comm
    struct data_t data = {};
    u32           pid  = bpf_get_current_pid_tgid();
    data.pid           = pid;
    // bpf_get_current_comm 获取当前正在执行代码的进程名称
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // get the binary name (first argment)
    if (__bpf_read_arg_str(&data, (const char*)argv[0]) < 0)
    {
        goto out;
    }
    // get other arguments (skip first arg because it has already been read)
#pragma unroll
    for (int i = 1; i < TOTAL_MAX_ARGS; i++)
    {
        if (__bpf_read_arg_str(&data, (const char*)argv[i]) < 0)
        {
            goto out;
        }
    }

out:
    // store the data in hash map
    tasks.update(&pid, &data);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_execve)
{
    // 从哈希映射中查询进程基本信息
    u32            pid  = bpf_get_current_pid_tgid();
    struct data_t* data = tasks.lookup(&pid);

    // 填充返回值并提交到性能事件映射中
    if (data != NULL)
    {
        data->retval = args->ret;
        events.perf_submit(args, data, sizeof(struct data_t));

        // clean up the hash map
        tasks.delete(&pid);
    }
    return 0;
}