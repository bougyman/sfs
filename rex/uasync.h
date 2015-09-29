/* 
  Micro Async library 
  
  A lightweight library for callbacks.  Less robust than the
  C++ callbacks, but more efficient for applications needing
  low overhead startup costs. 

*/

#ifndef _UASYNC_H_
#define _UASYNC_H_ 1

/* Enable stress-tests. */
/* #define SMALL_LIMITS 1 */

#include <config.h>
#include <sys/types.h>
#include <stdlib.h>

#ifndef HAVE_U_INT16_T
typedef unsigned short u_int16_t;
#endif /* !HAVE_U_INT16_T */

#if __GNUC__ >= 2
/* The __attribute__ keyword helps make gcc -Wall more useful, but
 * doesn't apply to other C compilers.  You don't need to worry about
 * what __attribute__ does (though if you are curious you can consult
 * the gcc info pages). */
#define __attribute__(x)
#endif /* __GNUC__ != 2 */

/* 1 + highest file descriptor number expected */
#define FD_MAX 64

/* The number of TCP connections we will use.  This can be no higher
 * than FD_MAX, but we reserve a few file descriptors because 0, 1,
 * and 2 are already in use as stdin, stdout, and stderr.  Moreover,
 * libc can make use of a few file descriptors for functions like
 * gethostbyname. */
#define NCON_MAX FD_MAX - 8

void fatal (const char *msg, ...)
     __attribute__ ((noreturn, format (printf, 1, 2)));
void make_async (int);

#ifndef DMALLOC
/* Malloc-like functions that don't fail. */
void *xrealloc (void *, size_t);
#ifndef xmalloc
#define xmalloc(size) xrealloc (0, size)
#endif /* !xmalloc */
#ifndef xfree
#define xfree(ptr) xrealloc (ptr, 0)
#endif /* !xfree */
#ifndef bzero
#define bzero(ptr, size) memset (ptr, 0, size)
#endif /* !bzero */
#endif /* !DMALLOC */

void cb_add (int, int, void (*fn) (void *), void *arg);
void cb_free (int, int);
void cb_check (void);

void relay (int fd);

/* XXX - some OSes don't put the __attribute__ ((noreturn)) on exit. */
void abort (void) __attribute__ ((noreturn));
void exit (int) __attribute__ ((noreturn));

#endif /* !_UASYNC_H_ */
