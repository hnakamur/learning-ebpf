#define BPF_KSYSCALL(name, args...)					    \
name(struct pt_regs *ctx);						    \
extern _Bool LINUX_HAS_SYSCALL_WRAPPER __kconfig;			    \
static __always_inline typeof(name(0))					    \
____##name(struct pt_regs *ctx, ##args);				    \
typeof(name(0)) name(struct pt_regs *ctx)				    \
{									    \
	struct pt_regs *regs = LINUX_HAS_SYSCALL_WRAPPER		    \
			       ? (struct pt_regs *)PT_REGS_PARM1(ctx)	    \
			       : ctx;					    \
	_Pragma("GCC diagnostic push")					    \
	_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")		    \
	if (LINUX_HAS_SYSCALL_WRAPPER)					    \
		return ____##name(___bpf_syswrap_args(args));		    \
	else								    \
		return ____##name(___bpf_syscall_args(args));		    \
	_Pragma("GCC diagnostic pop")					    \
}									    \
static __always_inline typeof(name(0))					    \
____##name(struct pt_regs *ctx, ##args)

#define BPF_KPROBE_SYSCALL BPF_KSYSCALL

int BPF_KPROBE_SYSCALL(hello, const char *pathname)
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
