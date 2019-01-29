#ifndef WS_SERVER_H

#include <stdio.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <signal.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <map>
#include <vector>
#include <openssl/sha.h>
#include "base64.h"
#include "fdinfo.h"
#include "recorder-signal.h"

#define __bswap_64(x) \
  x = (x>>56) | \
    ((x<<40) & 0x00FF000000000000) | \
    ((x<<24) & 0x0000FF0000000000) | \
    ((x<<8)  & 0x000000FF00000000) | \
    ((x>>8)  & 0x00000000FF000000) | \
    ((x>>24) & 0x0000000000FF0000) | \
    ((x>>40) & 0x000000000000FF00) | \
    (x<<56)

uint64_t hton64(uint64_t val)
{
	if (__BYTE_ORDER == __BIG_ENDIAN) return (val);
	else return __bswap_64(val);
}

uint64_t ntoh64(uint64_t val)
{
	if (__BYTE_ORDER == __BIG_ENDIAN) return (val);
	else return __bswap_64(val);
}

void sys_signal_handle(int signo);
void signal_handle(int fd);
void handshake_handle(int fd);
int request_handle(int listenfd, struct epoll_event *events, int nfds, int epfd);

#endif