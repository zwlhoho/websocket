#include "wsServer.h"

#define EVENT_BUF_SIZE  5
#define SERVER_PORT 18081
#define LISTENQUEUE 1024
#define RX_BUF_SIZE 4096
#define MASK_KEY_SIZE 4

typedef enum _CLIENT_STATE {
    CONNECTTED = 0,
    HANDSHAKING = 1,
    ESTABLISHED = 2
} CLIENT_STATE;

typedef enum {
	WSOC_CONTINUATION = 0x0,
	WSOC_TEXT = 0x1,
	WSOC_BINARY = 0x2,
	WSOC_CLOSE = 0x8,
	WSOC_PING = 0x9,
	WSOC_PONG = 0xA
} WS_OPCODE;

static int g_destory_flag = 0;
static std::map<int, CLIENT_STATE> g_clientState;
static std::string g_wsmagic("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");

void sys_signal_handle(int signo) {
    if (SIGINT == signo) {
        printf("Received signal INT!\n");
        g_destory_flag = 1;
    }
}

ssize_t read_data(int fd, char *buf, unsigned int buf_size) {
    ssize_t readlen = read(fd, (void *)buf, buf_size);
    return readlen;
}

ssize_t ws_write_frame(int fd, WS_OPCODE oc, void *data, size_t bytes) {
	uint8_t hdr[14] = { 0 };
	size_t hlen = 2;
	uint8_t *bp;
	ssize_t raw_ret = 0;

	if (ESTABLISHED != g_clientState[fd]) {
		return -1;
	}

	hdr[0] = (uint8_t)(oc | 0x80);

	if (bytes < 126) {
		hdr[1] = (uint8_t)bytes;
	} else if (bytes < 0x10000) {
		uint16_t *u16;

		hdr[1] = 126;
		hlen += 2;
		u16 = (uint16_t *) &hdr[2];
		*u16 = htons((uint16_t) bytes);
	} else {
		uint64_t *u64;

		hdr[1] = 127;
		hlen += 8;
		u64 = (uint64_t *) &hdr[2];
		*u64 = hton64(bytes);
	}

    bp = (uint8_t *) malloc(sizeof(uint8_t) * (hlen + bytes + 1));
    if (NULL == bp) {
        printf("memory alloc %ld bytes failed for write buffer!", hlen + bytes + 1);
        return -1;
    } 
	memcpy(bp, (void *) &hdr[0], hlen);
	memcpy(bp + hlen, data, bytes);

    raw_ret = write(fd, bp, hlen + bytes);
	if (raw_ret != (ssize_t) (hlen + bytes)) {
        free(bp);
		return raw_ret;
	}
    free(bp);
	return bytes;
}

std::vector<std::string> http_raw_data_format(const char *data) {
    std::string raw_data_str(data);
    std::vector<std::string> lines;
    std::size_t startIndex = 0;
    std::size_t spiltIndex = std::string::npos;
    
    while (std::string::npos != (spiltIndex = raw_data_str.find("\r\n", startIndex))) {
        std::string substr(raw_data_str.substr(startIndex, spiltIndex - startIndex ));
        lines.push_back(substr);
        startIndex = spiltIndex + strlen("\r\n");
    }
    return lines;
}

std::string ws_accept_generation(const char *str) {
    unsigned char digest[SHA_DIGEST_LENGTH + 1] = {0};
    SHA1((const unsigned char *)str, strlen(str), (unsigned char *)digest);
    Base64 base64;
    std::string digest_base64 = base64.Encode(digest, SHA_DIGEST_LENGTH);
    printf("digest_base64: %s\n", digest_base64.data());
    return digest_base64;
}

void handshake_handle(FDInfo *fdInfo) {
    int fd = fdInfo->GetFD();
    g_clientState[fd] = HANDSHAKING;
    
    char buf[RX_BUF_SIZE] = {0};
    ssize_t readlen = read_data(fd, buf, RX_BUF_SIZE - 1);
    std::vector<std::string> lines = http_raw_data_format(buf);
    bool connection_line = false;
    bool upgrade_line = false;
    std::string key = "";
    std::string response_header = "HTTP/1.1 101 Switching Protocols\r\nContent-Length: 0";
    for(size_t index = 0; index < lines.size(); index++) {
        if ( 0 == lines.at(index).compare("Connection: Upgrade") ) {
            connection_line = true;
            response_header += "\r\n";
            response_header += lines.at(index);
        } else if (0 == lines.at(index).compare("Upgrade: websocket")) {
            upgrade_line = true;
            response_header += "\r\n";
            response_header += lines.at(index);
        } else if ( 0 == lines.at(index).compare(0, strlen("Sec-WebSocket-Key: "), "Sec-WebSocket-Key: ")) {
            key = lines.at(index).substr(strlen("Sec-WebSocket-Key: "));
        }
    }
    if (connection_line && upgrade_line && !key.empty()) {
        printf("connection_line: %d, upgrade_line: %d, key: %s\n", connection_line, upgrade_line, key.data());
        std::string tmp_ws_accept = key + g_wsmagic;
        std::string ws_accept = ws_accept_generation(tmp_ws_accept.data());
        printf("ws_accept: %s\n", ws_accept.data());
        response_header += "\r\n";
        response_header += "Sec-Websocket-Accept: ";
        response_header += ws_accept;
        response_header += "\r\n\r\n";
        ssize_t write_len = write(fd, response_header.data(), response_header.length());
        printf("write_len: %ld\n", write_len);
    }

    g_clientState[fd] = ESTABLISHED;
}



void data_handle(FDInfo *fdInfo) {
    int fd = fdInfo->GetFD();
    char buf[RX_BUF_SIZE] = {0};
    char mask_key[MASK_KEY_SIZE] = {0};
    ssize_t readlen = read_data(fd, buf, 2);
    ssize_t need = 2;
    if (readlen < 2) {
        printf("data_handle, read len: %ld is less than min need: %ld\n", readlen, need);
        return ;
    }
    uint8_t opcode = (*((uint8_t *)buf)) & 0xF;
    printf("opcode: %d from fd: %d\n", opcode, fd);
    switch (opcode) {
        case WSOC_CONTINUATION:
        case WSOC_TEXT:         // data-frame
        case WSOC_BINARY:       // data-frame
	    case WSOC_PING:         // control-frame
	    case WSOC_PONG: {       // control-frame
                int fin = (buf[0] >> 7) & 1;
			    int mask = (buf[1] >> 7) & 1;
                unsigned payload_len = buf[1] & 0x7F;
                uint64_t next_need_read_bytes = 0;
                
                if (payload_len < 126) {
                    next_need_read_bytes += payload_len;
                } else if (126 == payload_len) {
                    memset(buf, 0, sizeof(buf));
                    readlen = read_data(fd, buf, 2);
                    if (2 != readlen) {
                        printf("read payload length error for payload_len: %d\n", payload_len);
                        printf("closing fd: %d\n", fd);
                        close(fd);
                        g_clientState.erase(fd);
                        return ;
                    } 
                    uint16_t *length16 = (uint16_t *)buf;
                    uint16_t real_payload_length16 = ntohs(*length16);
                    next_need_read_bytes += real_payload_length16;
                } else if (127 == payload_len) {
                    memset(buf, 0, sizeof(buf));
                    readlen = read_data(fd, buf, 8);
                    if (8 != readlen) {
                        printf("read payload length error for payload_len: %d\n", payload_len);
                        printf("closing fd: %d\n", fd);
                        close(fd);
                        g_clientState.erase(fd);
                        return ;
                    } 
                    uint64_t *length64 = (uint64_t *)buf;
                    uint64_t real_payload_length64 = ntoh64(*length64);
                    next_need_read_bytes += real_payload_length64;
                } else {
                    printf("payload_len: %u is invalid!\n", payload_len);
                    close(fd);
                    g_clientState.erase(fd);
                    return ;
                }
                
                if (mask) {
                    memset(buf, 0, sizeof(buf));
                    readlen = read_data(fd, buf, MASK_KEY_SIZE);
                    if (MASK_KEY_SIZE != readlen) {
                        printf("read mask key error for fd: %d\n", fd);
                        printf("closing fd: %d\n", fd);
                        close(fd);
                        g_clientState.erase(fd);
                        return ;
                    } 
                    memcpy((u_char *)mask_key, (u_char *)buf, MASK_KEY_SIZE);
                }
                if ((fdInfo->GetReadBufSize() - fdInfo->GetReadBufLen()) < next_need_read_bytes) {
                    fdInfo->AdjustReadBufSize(fdInfo->GetReadBufLen() + next_need_read_bytes + 1);
                }
                u_char *payload = (u_char *)fdInfo->GetReadBuf();
                if (NULL == payload) {
                    printf("memory alloc %lud bytes for payload failed!\n", next_need_read_bytes + 1);
                    printf("%s\n", strerror(errno));
                    printf("closing fd: %d\n", fd);
                    close(fd);
                    g_clientState.erase(fd);
                    return ;
                }
                memset(payload, 0, sizeof(u_char) * next_need_read_bytes + 1);
                readlen = read_data(fd, (char *)payload, next_need_read_bytes);
                if (next_need_read_bytes != readlen) {
                    printf("read payload error.need to read: %lud, real read: %ld\n", next_need_read_bytes, readlen);
                    printf("closing fd: %d\n", fd);
                    close(fd);
                    delete fdInfo;
                    g_clientState.erase(fd);
                    return ;
                } else {
                    fdInfo->SetReadBufLen(readlen);
                    size_t i = 0;
                    printf("payload: \n");
                    if (mask) {
                        for(i = 0; i < readlen; i++) {
                            payload[i] ^= mask_key[i % MASK_KEY_SIZE];
                        }
                    }
                    printf("Received: %s", (const char *)fdInfo->GetReadBuf());
                    printf("\n");
                }

                if (fin) {
                    recorder_signal_handle(fdInfo);
                }
                break;
            }
        case WSOC_CLOSE:        // control-frame
        default:
            printf("Closing fd: %d\n", fd);
            close(fd);
            delete fdInfo;
            g_clientState.erase(fd);
            break;
    } 
}

int request_handle(int listenfd, struct epoll_event *events, int nfds, int epfd) {
    struct epoll_event ev = {0};
    FDInfo *fdInfo = NULL;
    for( int index = 0; index < nfds; index++) {
        if ((listenfd == events[index].data.fd) && (EPOLLIN & events[index].events)) {
            printf("Received connectting request.....\n");
            struct sockaddr_in clientaddr = {0};
            socklen_t clientaddrLen = sizeof(clientaddr);
            int clientfd = accept(listenfd, (sockaddr *)&clientaddr, &clientaddrLen);

            if (-1 == clientfd) {
                printf("Accept for fd: %d failed!\n %s\n", listenfd, strerror(errno));
                close(listenfd);
                close(epfd);
                return -1;
            }
            fdInfo = new FDInfo(clientfd);
            ev.data.ptr = (void *)fdInfo;
            ev.events = EPOLLIN | EPOLLET;
            epoll_ctl(epfd, EPOLL_CTL_ADD, clientfd, &ev);
            g_clientState.insert(std::pair<int, CLIENT_STATE>(clientfd, CONNECTTED));

            printf("Accepted connection from: %s:%d, fd: %d\n", inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port), clientfd);
        } else if(EPOLLIN & events[index].events) {
            fdInfo = (FDInfo *)events[index].data.ptr;
            int fd = fdInfo->GetFD();
            CLIENT_STATE client_state = g_clientState[fd];
            printf("client: %d state: %d\n", fd, client_state);
            switch(client_state) {
                case CONNECTTED:
                    handshake_handle(fdInfo);
                    break;
                case ESTABLISHED:
                    data_handle(fdInfo);
                    break;
                default:
                    printf("state is invalid!\n");
                    break;
            }
        }
    }
    return 0;
}

int main(int argc, const char *argv[]) {
    int epfd = 0;
    int nfds = 0;
    int index = 0;
    int listenfd = 0;
    struct epoll_event ev;
    struct epoll_event events[EVENT_BUF_SIZE];

    struct sockaddr_in serveraddr;

    signal(SIGINT, sys_signal_handle);
    if (!initMediaServer()) {
        printf("Error for init mediaserver!\n");
        return -1;
    }

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == listenfd) {
        printf("Create socket error!\n %s", strerror(errno));
        return -1;
    }
    printf("Create socket succeed! listen fd: %d\n", listenfd);

    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(SERVER_PORT);
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    if ( -1 ==  bind(listenfd, (sockaddr *)&serveraddr, sizeof(serveraddr))) {
        printf("Bind listen fd: %d to sock addr failed!\n%s\n", listenfd, strerror(errno));
        close(listenfd);
        return -1;
    }    

    epfd = epoll_create(1);
    ev.data.fd = listenfd;
    ev.events = EPOLLIN | EPOLLET;
    epoll_ctl(epfd, EPOLL_CTL_ADD, listenfd, &ev);
    if (-1 == listen(listenfd, LISTENQUEUE)){
        printf("Listen fd: %d, queue length: %d failed!\n%s\n", listenfd, LISTENQUEUE, strerror(errno));
        close(listenfd);
        close(epfd);
        return -1;
    }
    for(; !g_destory_flag ;) {
        nfds = epoll_wait(epfd, events, EVENT_BUF_SIZE, -1);
        request_handle(listenfd, events, nfds, epfd);
    }

    {
        // close client socket
        std::map<int, CLIENT_STATE>::iterator it = g_clientState.begin();
        for ( ; it != g_clientState.end(); ++it) {
            close(it->first);
        }
    }
    close(listenfd);
    close(epfd);
}


// {
//     // ssize_t readlen = 0;
//     // ssize_t totalLen = 0;
//     // while (readlen = read(fd, (void *)buf, buf_size)) {
//     //     if (0 == totalLen && readlen < buf_size - 1) {
//     //         printf("Received %ld bytes\n%s", readlen, buf);
//     //         break;
//     //     } else {
//     //         printf("%s", buf);
//     //         memset(buf, 0, RX_BUF_SIZE);
//     //         totalLen += readlen;
//     //         if (readlen < RX_BUF_SIZE -1)
//     //             break;
//     //     }
//     // }
//     // if (0 != totalLen && totalLen != readlen) {
//     //     printf("\nTotal received %ld bytes\n", totalLen);
//     // }
// }