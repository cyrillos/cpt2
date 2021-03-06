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
+ static/posix_timers
+ static/futex
+ static/futex-rl
+ static/xids00
+ static/groups
+ static/pthread00
+ static/pthread01
+ static/umask00
+ static/cmdlinenv00
+ static/pid00
+ static/pstree
- static/caps00
	[root@ovz criu]# sh test/zdtm-cpt2.sh stop static/caps00
	13:53:53.457:   730: /proc/sys/kernel/cap_last_cap is not available
	13:58:23.005:   730: FAIL: caps00.c:151: Fail: 5 (errno = 11 (Resource temporarily unavailable))
+ static/selfexe00
+ static/eventfs00
- static/signalfd00
	[root@ovz criu]# sh test/zdtm-cpt2.sh stop static/signalfd00
	13:59:21.146:   836: FAIL: signalfd00.c:53: ghost signal (errno = 11 (Resource temporarily unavailable))
+ static/inotify00
- static/fanotify00
	- can not start it on openvz kernel
+ static/fifo-rowo-pair
- static/fifo-ghost
	- need to implement
+ static/fifo
+ static/fifo_wronly
+ static/zombie00
+ static/rlimits00
+ static/cow01
+ static/fpu00
+ static/fpu01
+ static/mmx00
+ static/sse00
+ static/sse20
+ static/fdt_shared
- static/sigpending
	- fails because openvz kernel does not check for si_code < 0 on
	  checkpoint, but copies data field by field. Instead in vanilla
	  kernel if si_code < 0 then the pending signal structure is copied
	  as a whole by once preserving all data (even that which is in padding)
+ static/unlink_fstat00
+ static/unlink_fstat02
- static/unlink_fstat03
	- fails because test migrates from simfs to bind mounting, otherwise
	  works as expected
+ static/child_opened_proc
+ static/file_fown
- static/file_locks00
	- fails in openvz
- static/file_locks01
	- fails in openvz

-- static/proc-self
-- static/mountpoints

+ static/sockets00
+ static/sockets_dgram
+ static/sockets01
+ static/socket_listen
+ static/sk-unix-unconn
+ static/sockets_spair
+ static/socket_queues
+ static/socket_udp
+ static/unbound_sock
+ static/socket-ext
+ static/socket-tcp
+ static/socket-tcp6
+ static/sigaltstack
+ static/socket-tcpbuf
+ static/socket-tcpbuf6
+ static/socket_listen6
+ static/socket6_udp

- static/packet_sock
	- fails in openvz. First -- 2.6.32 doesn not
	  support PACKET_FANOUT we use in our tests,
	  second -- it seems openvz simply does not
	  support it completely.

 - static/sk-netlink
	- fails because openvz doesnot support it.
 - static/socket_udplite
	- openvz does not support IPPROTO_UDPLITE socket creation
	  (Can not create socket (errno = 97 (Address family not supported by protocol)))

 - static/sock_opts00
	- openvz refuses to start it with SO_MARK option

 - static/sock_opts01
	- openvz refuses to start it with SO_BINDTODEVICE to eth0 option

 - static/sock_filter
	- openvz refuses to start it with ENOPROTOOPT

 - static/msgque
   static/sem
   static/shm
   static/utsname
	- openvz fails to restore even after suspend/resume

sh test/zdtm-cpt2.sh start static/pipe00 static/pipe01 static/cwd00 static/env00 static/maps00 static/mprotect00 static/mtime_mmap static/sleeping00 static/write_read00 static/write_read01 static/write_read02 static/write_read10 static/wait00 static/vdso00 static/file_shared static/sched_prio00 static/timers static/xids00 static/groups static/umask00 static/cmdlinenv00 static/futex static/futex-rl static/pthread00 static/pthread01 static/pid00 static/pstree static/selfexe00 static/eventfs00 static/inotify00 static/fifo-rowo-pair static/fifo static/fifo_wronly static/zombie00 static/rlimits00 static/cow01 static/fpu00 static/fpu01 static/mmx00 static/sse00 static/sse20 static/fdt_shared static/unlink_fstat00 static/unlink_fstat02 static/child_opened_proc static/file_fown static/sockets00 static/sockets_dgram static/sockets01 static/socket_listen static/sk-unix-unconn static/sockets_spair static/socket_queues static/socket_udp static/unbound_sock static/socket-ext static/sigaltstack static/posix_timers
sh test/zdtm-cpt2.sh start static/socket-tcpbuf static/socket-tcpbuf6 static/socket_listen6 static/socket6_udp

In progress
-----------

sh test/zdtm-cpt2.sh start static/signalfd00 static/fifo-ghost

Not yet run
-----------

streaming/pipe_loop00
streaming/pipe_shared00
transition/file_read
transition/fork
static/pty00
static/pty01
static/pty04
static/tty02
static/tty03
streaming/socket-tcp
streaming/socket-tcp6
static/pty03
ns/static/session00
ns/static/session01
static/ipc_namespace
transition/ipc
