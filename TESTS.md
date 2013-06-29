ZDTM statistics
===============

+ static/pipe00
+ static/pipe01
+ static/cwd00
+ static/env00
+ static/maps00
+ static/mprotect00
+ static/mtime_mmap
+ static/sleeping00
+ static/write_read00
+ static/write_read01
+ static/write_read02
+ static/write_read10
+ static/wait00
+ static/vdso00
+ static/file_shared
+ static/sched_prio00
- static/sched_policy00
	- fails because not allowed in openvz
+ static/timers
- static/futex
	- fails
- static/futex-rl
	- fails
+ static/xids00
+ static/groups
- static/pthread00
	-fails
- static/pthread01
	- fails
+ static/umask00
+ static/cmdlinenv00

sh test/zdtm-cpt2.sh start static/pipe00 static/pipe01 static/cwd00 static/env00  static/maps00 static/mprotect00 static/mtime_mmap static/sleeping00 static/write_read00 static/write_read01 static/write_read02 static/write_read10 static/wait00 static/vdso00 static/file_shared static/sched_prio00 static/timers static/xids00 static/groups static/umask00 static/cmdlinenv00

Not yet run
-----------

streaming/pipe_loop00
streaming/pipe_shared00
transition/file_read
static/sockets00
static/sockets01
static/sock_opts00
static/sock_opts01
static/sockets_spair
static/sockets_dgram
static/socket_queues
static/sk-unix-unconn
static/pid00
static/pstree
static/caps00
static/cmdlinenv00
static/socket_listen
static/socket_listen6
static/packet_sock
static/socket_udp
static/sock_filter
static/socket6_udp
static/socket_udplite
static/selfexe00
static/unlink_fstat00
static/unlink_fstat02
static/unlink_fstat03
static/eventfs00
static/signalfd00
static/inotify00
static/fanotify00
static/unbound_sock
static/fifo-rowo-pair
static/fifo-ghost
static/fifo
static/fifo_wronly
static/zombie00
static/rlimits00
transition/fork
static/pty00
static/pty01
static/pty04
static/tty02
static/tty03
static/child_opened_proc
static/cow01
static/fpu00
static/fpu01
static/mmx00
static/sse00
static/sse20
static/fdt_shared
static/file_locks00
static/file_locks01
static/sigpending
static/sigaltstack
static/sk-netlink
static/proc-self
static/file_fown
static/socket-ext
static/socket-tcp
static/socket-tcp6
streaming/socket-tcp
streaming/socket-tcp6
static/socket-tcpbuf
static/socket-tcpbuf6
static/pty03
static/mountpoints
ns/static/session00
ns/static/session01
static/ipc_namespace
static/shm
static/msgque
static/sem
transition/ipc
static/sigpending
static/sk-netlink
