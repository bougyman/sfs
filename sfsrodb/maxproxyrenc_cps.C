/*

Share the tcpconnection among the clients?  Then we can extend the test period to seconds.

Or trace single re-encs.


First RPC: {{6970,237757},
Last RPC: {{7081,167745},
So the timeline is 110 seconds, 929988 usec
We made 300 RPCs
means 1 RPC on average every .369766626  seconds
So just call delaycb
 */

/* $Id: maxproxyrenc_cps.C,v 1.2 2004/09/08 17:38:05 fubob Exp $ */

/* Use this program to simulate a herd of Chefs clients.  You
   can then test the maximum number of sustainable connections per
   second to a server.  Warning. this is almost as fast
   as a plain TCP connections.  Running longer than 1/2 second
   will likely use up resources.

   cat /sfstest/soco.lcs.mit.edu:5eeagvu4nq92g5rk9zd258738yudgcgk/manual/mod/mod_ssl/ssl_template.head-chapter.gif > /dev/null

*/

/*
 *
 * Copyright (C) 2004 Kevin Fu (fubob@mit.edu)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 */

#include "maxproxyrenc_cps.h"

u_int conncnt = 0;
char *hostname;
u_int64_t start_tm, end_tm;
//sfs_hash fh[10];

struct in_addr *ia;
int sfsro_port;

u_int32_t bigdeal =0;
u_int32_t reenc =0;
int countdown;

sfsro_proxyreenc trace[100];
int trace_size=100;
/*
char trace[][136] = {
  { 0x40, 0x00, 0x00, 0x00, 0xbb, 0x09, 0x2c, 0xee, 0x52, 0xb1, 0xa9, 0x43, 0x79, 0x27, 0x1a, 0xca, 0x50, 0xb6, 0xcd, 0xbe, 0xf2, 0x46, 0x94, 0x1b, 0x5d, 0xa5, 0xa2, 0x08, 0x33, 0xdd, 0x7f, 0x9c, 0xb5, 0x69, 0x59, 0x83, 0x4d, 0x1c, 0xca, 0x69, 0xbe, 0x30, 0x23, 0xe8, 0xfd, 0xf8, 0xf9, 0x5d, 0x3d, 0x30, 0x05, 0x87, 0xf5, 0xa7, 0xcb, 0xbd, 0x9c, 0x6b, 0xf8, 0x5b, 0xd8, 0xfe, 0xa5, 0x8e, 0x87, 0xc0, 0x11, 0xf0, 0x40, 0x00, 0x00, 0x00, 0x9e, 0x69, 0x62, 0x33, 0x57, 0x5d, 0x83, 0x8e, 0x71, 0x32, 0x2e, 0x25, 0x60, 0xf6, 0xa1, 0x08, 0x6a, 0x01, 0xfb, 0xbc, 0xa7, 0x99, 0xc9, 0x32, 0xc2, 0x68, 0x50, 0x53, 0x85, 0x94, 0xa7, 0x03, 0xa7, 0xc8, 0xe1, 0xb7, 0x13, 0x7a, 0x16, 0x25, 0xc4, 0x4a, 0x31, 0xaf, 0xcd, 0x08, 0x06, 0x95, 0xfe, 0xc8, 0xad, 0x56, 0x2c, 0x46, 0xaa, 0xef, 0x10, 0x49, 0x55, 0x51, 0xd2, 0xa1, 0xc0, 0x35 }
};
size_t trace_size = sizeof (trace) / sizeof (trace[0]);
*/

void
srvcon::fail (int err)
{
  warn << "connection failed" << strerror (errno) << "\n";
  delete this;
}


void
srvcon::init ()
{
  //  warn << "init\n";
  bigdeal++;
  tcpconnect (hostname, sfsro_port,
	      wrap (this, &srvcon::getsockres));
}

void
srvcon::getsockres (int fd)
{

  if (fd < 0) {
    timecb (timenow + 1, wrap (this, &srvcon::init));
    warn << "tcpconnect failed\n";
  } else {
    s = axprt_stream::alloc (fd);
    sfsroc = aclnt::alloc (s, sfsro_program_2);
    sfsroc->call (SFSROPROC2_PROXYREENC, &trace[0], &res,
		  wrap (this, &srvcon::proxyreenc, 0));
  }
}

void handler ();

void
srvcon::proxyreenc (int num, clnt_stat err)
{
  //  warn << "proxyreenc\n";
  num++;
  reenc++;

  if (err)
    fail (EIO);
  else if (num == 300) {
    conncnt++;
    countdown--;
    //    vNew srvcon ();
    delete this;
    if (!countdown)
      handler ();
  } else {
    delaycb (0, 369766626, wrap (this, &srvcon::proxyreenc2, num));
  }
}

void
srvcon::proxyreenc2 (int num)
{
  sfsroc->call (SFSROPROC2_PROXYREENC, &trace[0], &res,
		wrap (this, &srvcon::proxyreenc, num));
}


void
handler ()
{
  end_tm = get_time ();
  warn << "Time spent:      " << end_tm - start_tm << " usec\n";
  warn << "Number of conns: " << conncnt << "\n";
  warn << "Number of attempted connections: " << bigdeal << "\n";
  warn << "Connections/sec: " << conncnt*1000000/(end_tm - start_tm) << "\n";
  warn << "Number of succ proxy rencs: " << reenc << "\n";
  warn << "Proxy reenc/sec: " << reenc*1000000/(end_tm - start_tm) << "\n";

  //  XXXX print in one row.  Wall time, req/sec (req #), err/sec (err#), latency?    CPU time
  
  exit (0);
}

int
main (int argc, char **argv)
{
  setprogname (argv[0]);
  //  warn ("pid %d\n", getpid ());

  if (argc < 6 || argc > 7)
    fatal ("usage: %s <num simult conn> <server port> <server hostname> <fake HostID> <duration millisec> [<UDP broadcast trigger port>]\n", progname.cstr ());

  int numconn = atoi (argv[1]);
  countdown = numconn;

  sfsro_port = atoi (argv[2]);
  hostname = argv[3];
  //  hostid = argv[4];
  u_int64_t duration_tm = (1000 * atoi (argv[5])) % 1000000;
  u_int64_t duration_sec = (1000 * atoi (argv[5]))/ 1000000;
  
  if (duration_tm>= 1000000) {
    warn << "Duration too long.  Go away.\n";
    exit (-1);
  }

  warn << "Making " << duration_sec << " sec " << duration_tm
       << " microseconds worth of calls in windows of " << numconn 
       << " connections to " << hostname
    //       << ":" << hostid
       << "\n";    

  
  struct hostent *h;
  if ((h = gethostbyname (hostname)) == NULL) {
    warn << "gethostbyname failed\n";
    exit(-1);
  }


  ia = (struct in_addr *) h->h_addr;

  /*  carg.release = SFS_RELEASE;
  carg.service = SFS_SFS;
  carg.name = hostname;	
  if (!sfs_ascii2hostid (&carg.hostid, hostid)) {
    warn << "Can't decode hostid\n";
    exit (-1);
  }
  */

  sigcb (SIGALRM, wrap (handler));
  sigcb (SIGINT, wrap (handler));
  sigcb (SIGTERM, wrap (handler));

  struct itimerval itv;
  itv.it_value.tv_sec  = duration_sec;
  itv.it_value.tv_usec = duration_tm;

  // Trigger for remote synchronization

  if (argc == 7) {
    int udpsock = inetsocket (SOCK_DGRAM, atoi (argv[6]));
    if (udpsock < 0) {
      fatal ("socket");
    }
    
    int broadcast = 1;
    if (setsockopt (udpsock, SOL_SOCKET, SO_BROADCAST, &broadcast,
		    sizeof (broadcast)) < 0)
      fatal ("setsockopt: %m\n");
    
    char buf[1];
    // Block until triggered
    if (recvfrom (udpsock, buf, 1, 0, NULL, NULL) < 0) {
      fatal ("sendto: %m\n");
    }
  }

  
  int err;
  if ((err = setitimer (ITIMER_REAL, &itv, NULL)) != 0) {
    warn << "setitimer failed " << strerror (errno) << "\n";
    exit (-1);
  }

  for (int ii=0; ii<100; ii++) {
       trace[ii].data.setsize (136);
    //    trace[ii].data.setsize (72);

       /*    memcpy (trace[ii].data.base (),
"\x20\x00\x00\x00\xc4\x33\x05\xdc\x3a\x9e\x08\xef\xa5\xf4\xd9\xfe\x8b\x1a\xce\x30\x8e\x8f\x2d\xcb\xd3\x54\x7e\x8e\x2b\x78\x46\x8f\x0c\xf6\x17\xbd\x20\x00\x00\x00\x17\xed\xc4\x5f\xfb\x87\xd9\x24\x1f\x77\x5d\x59\x8d\x1c\x12\x54\x00\xa6\x51\xdb\x2b\x01\x2c\xa4\x8a\x95\x03\x24\xf0\x07\x01\x2e",
	    72);
       */

    memcpy (trace[ii].data.base (),
	    "\x40\x00\x00\x00\xbb\x09\x2c\xee\x52\xb1\xa9\x43\x79\x27\x1a\xca\x50\xb6\xcd\xbe\xf2\x46\x94\x1b\x5d\xa5\xa2\x08\x33\xdd\x7f\x9c\xb5\x69\x59\x83\x4d\x1c\xca\x69\xbe\x30\x23\xe8\xfd\xf8\xf9\x5d\x3d\x30\x05\x87\xf5\xa7\xcb\xbd\x9c\x6b\xf8\x5b\xd8\xfe\xa5\x8e\x87\xc0\x11\xf0\x40\x00\x00\x00\x9e\x69\x62\x33\x57\x5d\x83\x8e\x71\x32\x2e\x25\x60\xf6\xa1\x08\x6a\x01\xfb\xbc\xa7\x99\xc9\x32\xc2\x68\x50\x53\x85\x94\xa7\x03\xa7\xc8\xe1\xb7\x13\x7a\x16\x25\xc4\x4a\x31\xaf\xcd\x08\x06\x95\xfe\xc8\xad\x56\x2c\x46\xaa\xef\x10\x49\x55\x51\xd2\xa1\xc0\x35",
	    136);
  }

  start_tm = get_time();
  for (int i=0; i< numconn; i++) 
    vNew srvcon ();
  amain ();
}


