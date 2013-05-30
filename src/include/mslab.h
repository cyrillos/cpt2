/*
 * Trivial memory slab.
 */
#ifndef __CR_MSLAB_H__
#define __CR_MSLAB_H__

#include <string.h>

#include "compiler.h"
#include "xmalloc.h"

typedef struct mslab_s {
	unsigned long	size;
	unsigned long	left;

	void		*start __aligned(8);
	void		*tail  __aligned(8);
} mslab_t;

static inline void mslab_reset(mslab_t *m)
{
	m->tail = m->start;
	m->left = m->size;
}

/* Cast local memory area to be a memory slab */
static inline mslab_t *mslab_cast(void *where, unsigned long size)
{
	mslab_t *m = where;

	m->start = m + sizeof(*m);
	m->size = size - sizeof(*m);
	mslab_reset(m);

	return m;
}

static inline unsigned long mslab_tail_room(mslab_t *m)
{
	return m->left;
}

static inline unsigned long mslab_payload_size(mslab_t *m)
{
	return m->size - m->left;
}

static inline void *mslab_tail_pointer(mslab_t *m)
{
	return m->tail;
}

static inline void *mslab_payload_pointer(mslab_t *m)
{
	return m->start;
}

static inline mslab_t *mslab_alloc(unsigned long size)
{
	mslab_t *m = xmalloc(size + sizeof(*m));

	if (m) {
		m->start = m + sizeof(*m);
		m->size = size;
		mslab_reset(m);
	}

	return m;
}

static inline void mslab_free(mslab_t *m)
{
	xfree(m);
}

static inline void *mslab_put(mslab_t *m, unsigned long size)
{
	if (mslab_tail_room(m) >= size) {
		void *this = mslab_tail_pointer(m);

		m->tail += size;
		m->left -= size;

		return this;
	}

	return NULL;
}

#endif /* __CR_MSLAB_H__ */
