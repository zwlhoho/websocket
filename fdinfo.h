#ifndef FD_INFO_H
#define FD_INFO_H

#include <stdlib.h>
#include <stdio.h>

#define DEFAULT_BUF_SIZE 4096

class FDInfo
{
private:
    int m_fd;
    void *m_readBuf;
    size_t m_readbufSize;
    size_t m_readbufLen;
    void *m_writeBuf;
    size_t m_writebufSize;
    size_t m_writebufLen;
public:
    FDInfo(int fd);
    ~FDInfo();

    bool AdjustReadBufSize(size_t newSize);
    bool AdjustWriteBufSize(size_t newSize);
    int GetFD() {return this->m_fd;};
    size_t GetReadBufSize() {return this->m_readbufSize;};
    size_t GetReadBufLen() {return this->m_readbufLen;};
    size_t GetWriteBufSize() {return this->m_writebufSize;};
    size_t GetWriteBufLen() {return this->m_writebufLen;};
    void SetReadBufLen(ssize_t readBufLen) {this->m_readbufLen = readBufLen};
    void *GetReadBufStartAddr() {return (void *)(&(((u_char *)m_readBuf)[m_readbufLen]));};
};

#endif