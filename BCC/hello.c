/*
 * @Author: star-cs
 * @Date: 2025-07-28 16:36:16
 * @LastEditTime: 2025-07-28 16:58:05
 * @FilePath: /ebpf-learning/01/hello.c
 * @Description:
 */
int hello_world(void* ctx)
{
    bpf_trace_printk("Hello, World!");
    return 0;
}