#ifndef __CPT2_PROTOBUF_H__
#define __CPT2_PROTOBUF_H__

#include <sys/types.h>

#include "compiler.h"
#include "protobuf-desc.h"
#include "log.h"

#define pb_pksize(__obj, __proto_message_name)						\
	(__proto_message_name ##__get_packed_size(__obj) + sizeof(u32))

#define pb_repeated_size(__obj, __member)						\
	((size_t)(sizeof(*(__obj)->__member) * (__obj)->n_ ##__member))

extern int pb_native_write_one(int fd, void *obj, int type);

#define pb_write_one(fd, obj, type)				\
	({							\
		int __ret = pb_native_write_one(fd, obj, type);	\
		if (__ret)					\
			pr_err("Failed writing PB object\n");	\
		__ret;						\
	})

#endif /* __CPT2_PROTOBUF_H__ */
