/* $Id: krpc.c,v 1.17 1999/10/06 07:49:29 cblake Exp $ */

/*
 * User level VFS driver (kernel rpc)
 * Copyright 1999 Michael Kaminsky <kaminsky@lcs.mit.edu>.
 * Copyright 1998, 1999 David Mazieres <dm@uun.org>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project (for instance by leaving this copyright notice
 * intact).
 */

#if defined (__linux__)
#include <linux/kernel.h>
#define _LINUX_SUNRPC_MSGPROT_H_
#include <linux/fs.h>
#undef LIST_HEAD		/* Linux's list.h conflict with queue.h */
#include <linux/sched.h>
#endif /* __linux__ */

#if defined (__OpenBSD__)
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#endif /* __OpenBSD__ */

#include "arpc.h"
#include "clnt.h"
#include "rpc_msg.h"
#include "xdr_suio.h"

#define seterr_reply _seterr_reply
void _seterr_reply (struct rpc_msg *, struct rpc_err *);

#define RQHSIZE 31

typedef struct krpcreq {
  union {
    TAILQ_ENTRY (krpcreq) rqu_qlink;
    LIST_ENTRY (krpcreq) rqu_hlink;
  } rq_u;
#define rq_qlink rq_u.rqu_qlink
#define rq_hlink rq_u.rqu_hlink
  u_int32_t rq_xid;
  void *rq_buf;
  size_t rq_buflen;
  krpcq *rq_rpcq;
  int rq_err;
#define EFLUSH 1024
#ifdef __linux__
  struct wait_queue *sleepq;
#endif /* __linux__ */
} krpcreq;
LIST_HEAD (krpclist, krpcreq);

typedef struct krpcreply {
  TAILQ_ENTRY (krpcreply) rp_link;
  void *rp_buf;
  size_t rp_buflen;
} krpcreply;

static u_int32_t xidctr;
struct krpclist rqtab[RQHSIZE];

static void
krpcreq_free (krpcreq *rq)
{
  if (rq->rq_xid) {
    LIST_REMOVE (rq, rq_hlink);
  }
  else {
    TAILQ_REMOVE (&rq->rq_rpcq->inq, rq, rq_qlink);
  }
  if (rq->rq_buf != NULL)
    xfree (rq->rq_buf);
  xfree (rq);
}

static krpcreq *
krpc_lookup (u_int32_t xid)
{
  krpcreq *rq;
  for (rq = rqtab[xid % RQHSIZE].lh_first;
       rq && rq->rq_xid != xid;
       rq = rq->rq_hlink.le_next)
    ;
  return rq;
}

static void
krpc_setxid (krpcreq *rq)
{
  u_int32_t xid = xidctr;
  while (!++xid || krpc_lookup (xid))
    ;
  rq->rq_xid = xidctr = xid;
  *((u_int32_t *) rq->rq_buf + 1) = xid;
  LIST_INSERT_HEAD (&rqtab[xid % RQHSIZE], rq, rq_hlink);
}

#if 0
static void
krpc_unsetxid (krpcreq *rq)
{
  LIST_REMOVE (rq, rq_hlink);
  rq->rq_xid = 0;
  TAILQ_INSERT_HEAD (&rq->rq_rpcq->inq, rq, rq_qlink);
}
#endif

static bool_t
krpc_authunix (XDR *xdrs, uid_t cr_uid, gid_t cr_gid, int cr_ngroups,
	       gid_t cr_groups[NGROUPS])
{
  int i;

  if (!xdr_putlongref (xdrs, AUTH_UNIX)
      || !xdr_putlongref (xdrs, (5 + cr_ngroups) * 4)
      || !xdr_putlongref (xdrs, 0) /* Stamp */
      || !xdr_putlongref (xdrs, 0) /* Machinename */
      || !xdr_putlongref (xdrs, cr_uid) /* Uid */
      || !xdr_putlongref (xdrs, cr_gid) /* Gid */
      || !xdr_putlongref (xdrs, cr_ngroups))
    return FALSE;
  for (i = 0; i < cr_ngroups; i++)
    if (!xdr_putlongref (xdrs, cr_groups[i]))
      return FALSE;
  return TRUE;
}

static bool_t
krpc_authnone (XDR *xdrs)
{
  return (xdr_putlongref (xdrs, AUTH_NONE)
	  && xdr_putlongref (xdrs, 0));
}

int
krpc_marshallmsg (int progno, int versno, int procno,
		  void *inarg, xdrproc_t inproc,
		  void **bufp, size_t *lenp, u_int32_t msgtype)
{
  XDR x;
  u_int32_t *dp;

#ifdef KRPC_DEBUG
  warn ("doing krpc_marshallmsg\n");
#endif

  xdrsuio_create (&x, XDR_ENCODE);

  dp = (u_int32_t *) xdr_inline (&x, 7*4);
  if (!dp) {
    xdr_destroy (&x);
    return ENOMEM;
  }
  *dp++ = 0;
  *dp++ = 0;
  *dp++ = htonl (msgtype);
  *dp++ = htonl (RPC_MSG_VERSION);
  *dp++ = htonl (progno);
  *dp++ = htonl (versno);
  *dp++ = htonl (procno);

  if (msgtype == CALL &&
#if defined (__OpenBSD__)
      !krpc_authunix (&x, curproc->p_ucred->cr_uid, curproc->p_ucred->cr_gid,
		      curproc->p_ucred->cr_ngroups, 
		      curproc->p_ucred->cr_groups)
#elif defined (__linux__)
      !krpc_authunix (&x, current->uid, current->gid,
		      current->ngroups, current->groups)
#else
#warning Please define a way to retrieve the current process credentials for this OS
#endif
      ) {
    xdr_destroy (&x);
    return ENOMEM; 
  }
  if (!krpc_authnone (&x)) {
    xdr_destroy (&x);
    return ENOMEM; 
  }

  if (!inproc (&x, inarg)) {
    xdr_destroy (&x);
    return EBADRPC;
  }
  if (xsuio (&x)->uio_resid > MAXMSGSIZE) {
    xdr_destroy (&x);
    return E2BIG;
  }

  *lenp = xsuio (&x)->uio_resid;
  *(u_int32_t *)xsuio(&x)->uio_iov[0].iov_base = htonl((*lenp-4) | 0x80000000);
  *bufp = suio_flatten (xsuio (&x));

  xdr_destroy (&x);
  return 0;
}

int
krpc_mkcall (krpcq *q, void **bufp, size_t *lenp)
{
  int error = 0;
  krpcreq *rq = xmalloc (sizeof (*rq));

#ifdef KRPC_DEBUG
  warn ("doing krpc_mkcall...");
#endif

  bzero (rq, sizeof (*rq));
  rq->rq_buf = *bufp;
  rq->rq_buflen = *lenp;
  rq->rq_rpcq = q;
  rq->rq_err = ERESTART;
  rq->rq_xid = 0;
  TAILQ_INSERT_TAIL (&q->inq, rq, rq_qlink);

#ifdef KRPC_DEBUG
  warn ("sleeping.\n");
#endif

  q->readcb (q->readarg);
  while (!error && rq->rq_err == ERESTART) {
#if defined (__OpenBSD__)
    error = tsleep (rq, PVFS|PCATCH, "krpc", 0);
#elif defined (__linux__)
    interruptible_sleep_on (&rq->sleepq);
    if (signal_pending (current))
      error = ERESTART;
#else
#warning Please define a tsleep() equivalent for this OS
#endif
#ifdef KRPC_DEBUG
    warn ("waking up\n");
#endif
  }

  if (!error)
    error = rq->rq_err;

  if (!error) {
#ifdef KRPC_DEBUG
    warn ("no error in rpc call\n");
#endif
    *lenp = rq->rq_buflen;
    *bufp = rq->rq_buf;
    rq->rq_buf = NULL;
  }
#ifdef KRPC_DEBUG
  warn ("freeing rq\n");
#endif
  krpcreq_free (rq);
  return error;
}

int
krpc_copyout (krpcq *q, struct uio *u)
{
  int error;
  krpcreq *rq;
  size_t len;

#ifdef KRPC_DEBUG
  warn ("doing krpc_copyout: ");
#endif

  if (u->uio_rw != UIO_READ)
    panic ("krpc_copyout: u->uio_rw != UIO_READ");

  if (!q->active) {
    return ENXIO;
  }

  if (q->out_rq == NULL) { /* grab a new request */
    krpcreply *rp;
#ifdef KRPC_DEBUG
    warn ("new rq\n");
#endif

    while ((rp = TAILQ_FIRST (&q->replyq))) {
      warn ("reading call replies\n");
      len = min (rp->rp_buflen - q->out_pos, u->uio_resid);
      if (len && (error = uiomove (rp->rp_buf + q->out_pos, len, u)))
	return error;
      q->out_pos += len;
      if (q->out_pos == rp->rp_buflen) {
	TAILQ_REMOVE (&q->replyq, rp, rp_link);
	xfree (rp->rp_buf);
	xfree (rp);
      }
      else if (!len)
	return 0;
    }

    if (!(rq = q->inq.tqh_first))
      return EAGAIN;

#ifdef KRPC_DEBUG
    warn ("moving rq to rqtab\n");
#endif
    TAILQ_REMOVE (&q->inq, rq, rq_qlink);
    krpc_setxid (rq);

    q->out_rq = rq;
    q->out_pos = 0;
  }

  len = min(q->out_rq->rq_buflen - q->out_pos, u->uio_resid);
#ifdef KRPC_DEBUG
  warn ("uiomove up to userland...\n");
#endif
  if ((error = uiomove (q->out_rq->rq_buf + q->out_pos, len, u))) {
    warn ("error copyig to user space! \n");
    /* krpc_unsetxid (q->out_rq); */ /* XXX */
    return error;
  }

  q->out_pos += len;
  if (q->out_pos == q->out_rq->rq_buflen) {
    q->out_rq = NULL;
    q->out_pos = 0;
  }

  return 0;
}

int
krpc_reply (svccb *sbp, void *resp, xdrproc_t proc)
{
  void *buf;
  size_t len;
  int err;
  krpcreply *rp;

  err = krpc_marshallmsg (sbp->prog, sbp->vers, sbp->proc, 
			  resp, proc, &buf, &len, REPLY);
  if (err)
    return err;
  rp = xmalloc (sizeof (*rp));
  rp->rp_buf = buf;
  rp->rp_buflen = len;
  TAILQ_INSERT_TAIL (&sbp->q->replyq, rp, rp_link);
  return 0;
}

static int
krpc_getmsg (krpcq *q, void *msg, int len)
{
  XDR x;
  u_int32_t xid, msgtype, msgvers;
  int error = 0;

  xdrmem_create (&x, msg, len, XDR_DECODE);
  warn ("len = %d\n", len);
  if (!xdr_getbytes (&x, (char *) &xid, 4)) {
    warn ("xid failed\n");
    error = EINVAL;
  }
  else if (!xdr_u_int32_t (&x, &msgtype)) {
    warn ("msgtype failed\n");
    error = EINVAL;
  }
  else if (msgtype == REPLY) {
    krpcreq *rq = krpc_lookup (xid);
    warn ("getmsg.... reply\n");
    if (rq /* && rq != q->out_rq */) {
      xfree (rq->rq_buf);
      rq->rq_buf = msg;
      rq->rq_buflen = len;
      rq->rq_err = 0;
      msg = NULL;
#ifdef __linux__
      wake_up_interruptible (&rq->sleepq);
#else /* !__linux__ */
      wakeup (rq);
#endif /* !__linux__ */
    }
    else
      warn ("ignoring reply\n");
  }
  else if (msgtype == CALL) {
    u_int32_t authlen;
    svccb sb;
    sb.q = q;
    sb.xid = xid;

    if (!xdr_u_int32_t (&x, &msgvers)
	|| msgvers != RPC_MSG_VERSION
	|| !xdr_u_int32_t (&x, &sb.prog)
	|| !xdr_u_int32_t (&x, &sb.vers)
	|| !xdr_u_int32_t (&x, &sb.proc)
	|| !xdr_u_int32_t (&x, &authlen)
	|| (authlen && !xdr_inline (&x, (authlen + 3) & ~3))
	|| !xdr_u_int32_t (&x, &authlen)
	|| (authlen && !xdr_inline (&x, (authlen + 3) & ~3)))
      error = EINVAL;
    else {
      sb.buf = msg;
      sb.xdrs = &x;
      error = q->callback (q->arg, &sb);
    }
  }
  else
    error = EINVAL;

  xdr_destroy (&x);
  if (msg)
    xfree (msg);
  return error;
}

int
krpc_copyin (krpcq *q, struct uio *u)
{
  int error;
  int len;

  if (u->uio_rw != UIO_WRITE)
    panic ("krpc_copyin: u->uio_rw != UIO_WRITE");
  if (!q->active)
    return ENXIO;

  while (u->uio_resid) {
    if (q->in_state == READLEN) {
      len = min (u->uio_resid, 4 - q->in_pos);
      error = uiomove((char *)&q->in_lenbuf + q->in_pos, len, u);
      if (error)
	return error;
      q->in_pos += len;

      if (q->in_pos == 4) {
	q->in_pos = 0;
	q->in_msgsize = ntohl (q->in_lenbuf);
	if (!(q->in_msgsize & 0x80000000))
	  return ENOMEM;
	q->in_msgsize &= 0x7fffffff;
	if (q->in_msgsize > 0x10400)
	  return ENOMEM;
	q->in_state = READDAT;
	q->in_msgbuf = xmalloc (q->in_msgsize);
      }
    }
    else { /* READDAT */
      len = min (u->uio_resid, q->in_msgsize - q->in_pos);
      error = uiomove (q->in_msgbuf + q->in_pos, len, u);
      if (error)
	return error;
      q->in_pos += len;

      if (q->in_pos == q->in_msgsize) {
	error = krpc_getmsg (q, q->in_msgbuf, q->in_msgsize);
	q->in_state = READLEN;
	q->in_pos = 0;
	q->in_msgsize = 0;
	q->in_msgbuf = NULL;
      }
      return error;
    }
  }
  return 0;
}

int
krpc_callraw (krpcq *q, int prog, int vers, int proc,
	      void *in, xdrproc_t inproc,
	      void *out, xdrproc_t outproc)
{
  void *buf;
  size_t len;
  int error = 0;
  XDR x;
  struct rpc_msg rm;
  struct rpc_err re;

  if (!q->active) {
    return ENXIO;
  }

#ifdef KRPC_DEBUG
  warn ("doing rpc_callraw\n");
#endif

  if ((error = krpc_marshallmsg (prog, vers, proc, in, inproc, 
				 &buf, &len, CALL))
      || (error = krpc_mkcall (q, &buf, &len))) {
    if (error != EINTR && error != ERESTART) {
      krpc_deactivate (q);
      krpc_flush (q);
    }
    return error;
  }

#ifdef KRPC_DEBUG
  warn ("returning response to caller\n");
#endif
  xdrmem_create (&x, buf, len, XDR_DECODE);
  rm.acpted_rply.ar_verf = _null_auth; 
  rm.acpted_rply.ar_results.where = (char *) out;
  rm.acpted_rply.ar_results.proc = outproc;
  if (!xdr_replymsg (&x, &rm)) {
    xdr_free (outproc, out);
    error = ENXIO;
  }

  seterr_reply (&rm, &re);
  if (!error && re.re_status != RPC_SUCCESS) {
#ifdef KRPC_DEBUG
    warn ("seterr_reply failed with error = %d\n", re.re_status);
#endif
    xdr_free (outproc, out);
    error = EOPNOTSUPP;
  }

  xdr_destroy (&x);

  if (error) {
    krpc_deactivate (q);
    krpc_flush (q);
  }
  return error;
}

int
krpc_callit (krpcq *q, const struct rpc_program *rpcprog,
	     u_int32_t proc, void *in, void *out)
{
  int error;

  error = krpc_callraw (q, rpcprog->progno, rpcprog->versno, proc,
			in, rpcprog->tbl[proc].xdr_arg, 
			out, rpcprog->tbl[proc].xdr_res);
  return error;
}

void
krpc_activate (krpcq *q)
{
  q->active = 1;
}

void
krpc_deactivate (krpcq *q)
{
  warn ("krpc_deactivate\n");
  q->active = 0;
}

void
krpc_init (krpcq *q, void (*readcb)(void *), void *readarg)
{
  int i;

  TAILQ_INIT(&q->inq);
  TAILQ_INIT(&q->replyq);
  q->readcb = readcb;
  q->readarg = readarg;
  q->out_pos = 0;
  q->out_rq = NULL;
  q->in_state = READLEN;
  q->in_pos = 0;

  krpc_deactivate (q);

  /* XXX: We do this multiple times...is that OK? */
  for(i = 0; i < RQHSIZE; i++) {
    LIST_INIT(&rqtab[i]);
  }
}

void
krpc_server_alloc (krpcq *q, const struct rpc_program *rpcprog,
		   int (*cb) (void *, svccb *), void *arg)
{
  q->rpcprog = rpcprog;
  q->arg = arg;
  q->callback = cb;
}

void
krpc_flush (krpcq *q)
{
  int i;
  krpcreq *np;
  krpcreply *nr;

  warn ("krpc_flush\n");
#ifdef KRPC_DEBUG
  warn ("krpc_flush...");
#endif

  /* something pending in userland */
  if (q->out_rq != NULL) {
#ifdef KRPC_DEBUG
    warn ("rq in rqtab");
#endif
    q->out_rq->rq_err = EFLUSH;
#if defined (__OpenBSD__)
    wakeup (q->out_rq);
#elif defined (__linux__)
    wake_up_interruptible (&q->out_rq->sleepq);
#else
#warning Please defined an analog to wakeup() for this OS
#endif
    q->out_pos = 0;
    q->out_rq = NULL;
  }

#ifdef KRPC_DEBUG
  warn ("rqs in rqtab...");
#endif
  for(i = 0; i < RQHSIZE; i++) {
    for (np = rqtab[i].lh_first; np != NULL; np = np->rq_hlink.le_next) {
      if (np->rq_rpcq == q) {
#ifdef KRPC_DEBUG
	warn ("*");
#endif
	np->rq_err = EFBIG;
#if defined (__OpenBSD__)
	wakeup (np);
#elif defined (__linux__)
	wake_up_interruptible (&np->sleepq);
#else
#warning Please defined an analog to wakeup() for this OS
#endif
      }
    }
  }

#ifdef KRPC_DEBUG
  warn ("rqs in tailq...");
#endif
  for (np = TAILQ_FIRST(&q->inq); np != NULL; np = TAILQ_NEXT(np, rq_qlink)) {
#ifdef KRPC_DEBUG
    warn ("*");
#endif
    np->rq_err = EFBIG;
#if defined (__OpenBSD__)
    wakeup (np);
#elif defined (__linux__)
    wake_up_interruptible (&np->sleepq);
#else
#warning Please defined an analog to wakeup() for this OS
#endif
  }

  for (nr = TAILQ_FIRST (&q->replyq); nr; nr = TAILQ_NEXT (nr, rp_link)) {
    TAILQ_REMOVE (&q->replyq, nr, rp_link);
    xfree (nr->rp_buf);
    xfree (nr);
  }

#ifdef KRPC_DEBUG
  warn ("\n");
#endif
}
