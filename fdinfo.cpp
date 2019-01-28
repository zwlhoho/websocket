#include "fdinfo.h"
#include "string.h"

FDInfo::FDInfo(int fd) {
    this->m_fd = fd;
    this->m_readBuf = (void *)malloc(sizeof(u_char) * DEFAULT_BUF_SIZE);
    if (NULL == this->m_readBuf) {
        printf("Error! Alloc %d bytes memory for fd: %d reading buffer failed!\n", DEFAULT_BUF_SIZE, this->m_fd);
        abort();
    }
    memset(this->m_readBuf, 0, DEFAULT_BUF_SIZE);
    this->m_readbufSize = DEFAULT_BUF_SIZE;
    this->m_readbufLen = 0;

    this->m_writeBuf = (void *)malloc(sizeof(u_char) * DEFAULT_BUF_SIZE);
    if (NULL == this->m_writeBuf) {
        printf("Error! Alloc %d bytes memory for fd: %d writting buffer failed!\n", DEFAULT_BUF_SIZE, this->m_fd);
        free(this->m_readBuf);
        this->m_readBuf = NULL;
    }
    memset(this->m_writeBuf, 0, DEFAULT_BUF_SIZE);
    this->m_writebufSize = DEFAULT_BUF_SIZE;
    this->m_writebufLen = 0;
}

FDInfo::~FDInfo() {
    if (NULL != this->m_readBuf) {
        free(this->m_readBuf);
        this->m_readBuf = NULL;
        this->m_readbufLen = 0;
        this->m_readbufSize = 0;
    }

    if (NULL != this->m_writeBuf) {
        free(this->m_writeBuf);
        this->m_writeBuf = NULL;
        this->m_writebufLen = 0;
        this->m_writebufSize = 0;
    }

}

bool FDInfo::AdjustReadBufSize(size_t newSize) {
    void *tmp = NULL;
    if (newSize <= this->m_readbufSize) {
        return true;
    }

    tmp = realloc(this->m_readBuf, newSize);
    if (NULL == tmp) {
        printf("Error! realloc memory for fd: %d reading buf from size: %ld to %ld failed!\n", this->m_fd, this->m_readbufSize, newSize);
        printf("Trying alloc new memory...");
        tmp = (void *)malloc(sizeof(u_char) * newSize);
        if (NULL == tmp) {
            printf("Error! Allocate memory for fd: %d reading buf failed!\n", this->m_fd);
            return false;
        }
        memcpy(tmp, this->m_readBuf, this->m_readbufLen);
        free(this->m_readBuf);
        this->m_readBuf = tmp;
        this->m_readbufSize = newSize;
    } else {
        this->m_readBuf = tmp;
        this->m_readbufSize = newSize;
    }
    memset((u_char *)tmp + this->m_readbufLen, 0, newSize - this->m_readbufLen);
    return true;    
}

bool FDInfo::AdjustWriteBufSize(size_t newSize) {
    void *tmp = NULL;
    if (newSize <= this->m_writebufSize) {
        return true;
    }

    tmp = realloc(this->m_writeBuf, newSize);
    if (NULL == tmp) {
        printf("Error! realloc memory for fd: %d writting buf from size: %ld to %ld failed!\n", this->m_fd, this->m_writebufSize, newSize);
        printf("Trying alloc new memory...");
        tmp = (void *)malloc(sizeof(u_char) * newSize);
        if (NULL == tmp) {
            printf("Error! Allocate memory for fd: %d writting buf failed!\n", this->m_fd);
            return false;
        }
        memcpy(tmp, this->m_writeBuf, this->m_writebufLen);
        free(this->m_writeBuf);
        this->m_writeBuf = tmp;
        this->m_writebufSize = newSize;
    } else {
        this->m_writebufSize = newSize;
    }
    memset((u_char *)tmp+ this->m_writebufLen, 0, newSize - this->m_writebufLen);
    return true; 
}