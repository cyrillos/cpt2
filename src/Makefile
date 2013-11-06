obj-y	+= main.o
obj-y	+= convert.o
obj-y	+= log.o
obj-y	+= io.o
obj-y	+= fdset.o
obj-y	+= string.o
obj-y	+= context.o
obj-y	+= image.o
obj-y	+= protobuf.o
obj-y	+= obj.o
obj-y	+= read.o
obj-y	+= ns.o
obj-y	+= task.o
obj-y	+= net.o
obj-y	+= files.o
obj-y	+= mm.o
obj-y	+= tty.o
obj-y	+= fsnotify.o
obj-y	+= sig.o
obj-y	+= epoll.o
obj-y	+= libnetlink.o
obj-y	+= timers.o
obj-y	+= socket.o
obj-y	+= util.o

obj-y	+= protobuf-desc.o
obj-y	+= image-desc.o

cflags-y += -iquote include

PROTOBUF_GEN := scripts/protobuf-gen.sh
$(obj)/protobuf-desc.c: $(obj)/include/protobuf-desc-gen.h
$(obj)/include/protobuf-desc-gen.h: $(PROTOBUF_GEN) $(obj)/include/protobuf-desc.h
	$(E) "  GEN     " $@
	$(Q) $(SH) $(PROTOBUF_GEN) $(obj)/include/protobuf-desc.h > $@

cleanup-y += $(obj)/include/protobuf-desc-gen.h

ifneq ($(MAKECMDGOALS),clean)
incdeps := y
endif
