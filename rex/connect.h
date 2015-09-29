#ifndef _CONNECT_H_
#define _CONNECT_H_ 1

enum {
	STRUCT_UNUSED = 0,
	SERVER_DONTREAD = 2,
	CLIENT_DONTREAD = 4,
	CLIENT_DONTWRITE = 8,
	SERVER_DONTWRITE = 16,
	FULL_CLOSE = 30,
};

#define BUFSIZE 16*1024 /* Match the buffer size used by OpenSSH */

/* finger cuffs: connect two sockets */
struct cuff_state {
	int    client_fd;
	int    server_fd;
	int    state;
	char   client_buf[BUFSIZE];
	int    client_buf_bytes;
	int    client_buf_off;
	char   server_buf[BUFSIZE];
	int    server_buf_bytes;
	int    server_buf_off;
};

void server_read (void *arg);
void server_write (void *arg);
void client_read (void *arg);
void client_write (void *arg);

#endif /* !_CONNECT_H_ */
