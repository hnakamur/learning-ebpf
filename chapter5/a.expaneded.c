# 0 "chapter5/a.c"
# 0 "<built-in>"
# 0 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 0 "<command-line>" 2
# 1 "chapter5/a.c"
# 24 "chapter5/a.c"
int hello(struct pt_regs *ctx); extern _Bool LINUX_HAS_SYSCALL_WRAPPER __kconfig; static __always_inline typeof(hello(0)) ____hello(struct pt_regs *ctx, const char *pathname); typeof(hello(0)) hello(struct pt_regs *ctx) { struct pt_regs *regs = LINUX_HAS_SYSCALL_WRAPPER ? (struct pt_regs *)PT_REGS_PARM1(ctx) : ctx;
# 24 "chapter5/a.c"
#pragma GCC diagnostic push
# 24 "chapter5/a.c"

# 24 "chapter5/a.c"
#pragma GCC diagnostic ignored "-Wint-conversion"
# 24 "chapter5/a.c"
 if (LINUX_HAS_SYSCALL_WRAPPER) return ____hello(___bpf_syswrap_args(const char *pathname)); else return ____hello(___bpf_syscall_args(const char *pathname));
# 24 "chapter5/a.c"
#pragma GCC diagnostic pop
# 24 "chapter5/a.c"
 } static __always_inline typeof(hello(0)) ____hello(struct pt_regs *ctx, const char *pathname)
{
   struct data_t data = {};
   struct user_msg_t *p;

   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

   bpf_get_current_comm(&data.command, sizeof(data.command));
   bpf_probe_read_user_str(&data.path, sizeof(data.path), pathname);

   p = bpf_map_lookup_elem(&my_config, &data.uid);
   if (p != 0) {
      bpf_probe_read_kernel_str(&data.message, sizeof(data.message), p->message);
   } else {
      bpf_probe_read_kernel_str(&data.message, sizeof(data.message), message);
   }

   bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
   return 0;
}
