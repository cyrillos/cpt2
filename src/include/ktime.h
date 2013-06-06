#ifndef __CPT2_KTIME_H__
#define __CPT2_KTIME_H__

#include <sys/time.h>

#include "asm/int.h"

/*
 * This one should be obtained from the image.
 */
extern u16 image_HZ;
#define HZ					image_HZ

#define NSEC_PER_USEC				1000L
#define NSEC_PER_SEC				1000000000L

#define cputime_to_timeval(__ct,__val)		jiffies_to_timeval(__ct,__val)

#define SH_DIV(nom, den, lsh)			\
	((((nom) / (den)) << (lsh)) + ((((nom) % (den)) << (lsh)) + (den) / 2) / (den))

#define PIT_TICK_RATE				1193182UL
#define CLOCK_TICK_RATE				PIT_TICK_RATE

#define LATCH					((CLOCK_TICK_RATE + HZ / 2) / HZ)
#define ACTHZ					(SH_DIV(CLOCK_TICK_RATE, LATCH, 8))
#define TICK_NSEC				(SH_DIV(1000000UL * 1000, ACTHZ, 8))

/* FIXME Valid only for BITS_PER_LONG == 64 */
static inline u64 div_u64_rem(u64 dividend, u32 divisor, u32 *remainder)
{
	*remainder = dividend % divisor;
	return dividend / divisor;
}

static inline s64 div_s64_rem(s64 dividend, s32 divisor, s32 *remainder)
{
	*remainder = dividend % divisor;
	return dividend / divisor;
}

static inline void jiffies_to_timeval(const unsigned long jiffies, struct timeval *value)
{
	if (jiffies) {
		u32 rem;

		value->tv_sec	= div_u64_rem((u64)jiffies * TICK_NSEC, NSEC_PER_SEC, &rem);
		value->tv_usec	= rem / NSEC_PER_USEC;
	} else
		value->tv_sec = value->tv_usec = 0;
}

static inline struct timespec ns_to_timespec(const s64 nsec)
{
	struct timespec ts;
	s32 rem;

	if (!nsec)
		return (struct timespec){0, 0};

	ts.tv_sec = div_s64_rem(nsec, NSEC_PER_SEC, &rem);
	if (rem < 0) {
		ts.tv_sec--;
		rem += NSEC_PER_SEC;
	}
	ts.tv_nsec = rem;

	return ts;
}

static inline struct timeval ns_to_timeval(const s64 nsec)
{
	struct timeval tv;

	if (nsec) {
		struct timespec ts = ns_to_timespec(nsec);
		tv.tv_sec = ts.tv_sec;
		tv.tv_usec = (long)ts.tv_nsec / 1000;
	} else
		tv.tv_sec = tv.tv_usec = 0;

	return tv;
}

#endif /* __CPT2_KTIME_H__ */
