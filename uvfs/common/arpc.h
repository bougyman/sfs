/* $Id: arpc.h,v 1.13 1999/10/06 06:56:40 dm Exp $ */

/*
 * User level VFS driver (OS independent code)
 * Copyright 1999 Michael Kaminsky <kaminsky@lcs.mit.edu>.
 * Copyright 1998, 1999 David Mazieres <dm@uun.org>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project (for instance by leaving this copyright notice
 * intact).
 */

#ifndef _KERN_ARPC_H_INCLUDED
#define _KERN_ARPC_H_INCLUDED

#include <config.h>

#if defined (__linux__)

#undef GFP_KERNEL
#include <linux/time.h>
#include <errno.h>
#ifndef EBADRPC
#define EBADRPC   EBADMSG
#endif
#include <linux/uio.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/param.h>
#include <asm/byteorder.h>

#ifndef min
#define min(a,b) (((a)<(b))?(a):(b))
#endif

enum uio_rw { UIO_READ, UIO_WRITE };
enum uio_seg {
        UIO_USERSPACE,          /* from user data space */
        UIO_SYSSPACE            /* from system space */
};
struct uio {
        struct  iovec *uio_iov;
        int     uio_iovcnt;
        off_t   uio_offset;
        size_t  uio_resid;
        enum    uio_seg uio_segflg;
        enum    uio_rw uio_rw;
        struct  proc *uio_procp;
};
int uiomove(caddr_t buf, int howmuch, struct uio *uiop);

void *kmalloc(unsigned int size, int priority);
void kfree(void * obj);
#define GFP_KERNEL      0x15
#define xmalloc(size) kmalloc (size, GFP_KERNEL)
#define xfree kfree
#define bcopy(s, d, l) memcpy (d, s, l)
#define bzero(p, s) memset (p, 0, s)
#define printf(fmt,arg...) printk(KERN_WARNING fmt,##arg)
#endif /* __linux__ */

#if defined (__OpenBSD__)
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/time.h>

#define memmove(d, s, l) bcopy (s, d, l)
#define memcpy(d, s, l) bcopy (s, d, l)
#define xmalloc(size) malloc (size, M_TEMP, M_WAITOK)
static inline void
xfree (void *ptr)
{
  free (ptr, M_TEMP);
}
#endif /* __OpenBSD__ */

#include "types.h"
#include "xdr.h"
#include "auth.h"

#include "queue.h"

typedef void *iovbase_t;
#ifndef offsetof
#define offsetof(type, member) ((size_t)(&((type *)0)->member))
#endif /* !offsetof */

#define MAXMSGSIZE 0x2100

#undef warn
#undef mem_alloc
#undef mem_free
#undef assert

#define warn printf
#define mem_alloc xmalloc
#define mem_free(ptr, size) xfree (ptr)
#define assert(x)							\
  if (!(x)) panic (__FUNCTION__ ": assertion '" #x "' failed\n");
#define xdr_free(proc, obj) xdr_free (proc, (char *) obj)

static inline bool_t
xdr_putlongref (XDR *x, long l)
{
  return xdr_putlong (x, &l);
}

struct krpcreq;
TAILQ_HEAD (krpctq, krpcreq);

struct krpcreply;
TAILQ_HEAD (krpcreplyq, krpcreply);

#define RPC_EXTERN extern
#define RPC_CONSTRUCT(a, b)
#define RPC_UNION_NAME(n) u

/* Dispatch tables in .i files */
#define RPCGEN_ACTION(x) 0
struct rpcgen_table {
  char *(*proc)();
  xdrproc_t xdr_arg;
  unsigned len_arg;
  xdrproc_t xdr_res;
  unsigned len_res;
};

struct rpc_program {
  u_int32_t progno;
  u_int32_t versno;
  const struct rpcgen_table *tbl;
  size_t nproc;
};

struct krpcq;
typedef struct svccb {
  struct krpcq *q;
  u_int32_t xid;
  u_int32_t prog;
  u_int32_t vers;
  u_int32_t proc;
  void *buf;
  XDR *xdrs;
} svccb;

typedef enum krpcq_state { READLEN, READDAT } krpcq_state;

typedef struct krpcq {
  struct krpcreplyq replyq;
  struct krpctq inq;
  void (*readcb) (void *);
  void *readarg;
  /* for server-side rpc dispatch */
  const struct rpc_program *rpcprog;
  int (*callback) (void *, struct svccb *);
  void *arg;
  /* for copyout */
  size_t out_pos;
  struct krpcreq *out_rq;
  struct krpcreply *out_rp;
  /* for copyin*/
  krpcq_state in_state;
  u_int32_t in_lenbuf;
  size_t in_msgsize;
  char *in_msgbuf;
  size_t in_pos;
  /* status */
  int active;
} krpcq;

int uiopeek (char *, int, struct uio *);
void xdruio_create (XDR *, struct uio *, enum xdr_op);

void krpc_init (krpcq *, void (*readcb)(void *), void *readarg);
void krpc_activate (krpcq *);
void krpc_deactivate (krpcq *);
int krpc_copyout (krpcq *, struct uio *);
int krpc_copyin (krpcq *, struct uio *);
int krpc_callraw (krpcq *, int prog, int vers, int proc,
		  void *in, xdrproc_t inproc,
		  void *out, xdrproc_t outproc);
int krpc_callit (krpcq *, const struct rpc_program *,
		 u_int32_t proc, void *in, void *out);
void krpc_server_alloc (krpcq *, const struct rpc_program *,
			int (*) (void *, svccb *), void *arg);
void krpc_seteof (krpcq *);
void krpc_flush (krpcq *);
int krpc_reply (svccb *sbp, void *resp, xdrproc_t proc);

#endif /* !_KERN_ARPC_H_INCLUDED */
