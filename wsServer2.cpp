#include "recorder-signal.h"
#include "wsServer2.h"
#include <iostream>
#include <signal.h>
#include <map>

static volatile int exit_sig = 0;
#define MAX_PAYLOAD_SIZE  10 * 1024

static std::map<std::string, struct lws*> g_fromuserLWS;

void userRegister(std::string userid, struct lws* wsi) {
    g_fromuserLWS.insert(std::pair<std::string, struct lws*>(userid, wsi));
}

void sendToUser(std::string userid, std::string data) {
    unsigned char* tmpBuf = nullptr;
    std::map<std::string, struct lws*>::iterator userIterator = g_fromuserLWS.find(userid);
    if (userIterator != g_fromuserLWS.end()) {
        tmpBuf = new unsigned char [LWS_PRE + data.length()];
        memcpy(tmpBuf + LWS_PRE, data.data(), data.length());
        lws_write(userIterator->second, tmpBuf + LWS_PRE, data.length(), LWS_WRITE_TEXT);
        delete []tmpBuf;
    } else {
        lwsl_err("Not found wsi for user: %s\n", userid.data());
    }
}

void sighdl( int sig ) {
    lwsl_notice( "%d traped", sig );
    exit_sig = 1;
}

/**
 * 会话上下文对象，结构根据需要自定义
 */
struct session_data {
    int msg_count;
    unsigned char buf[LWS_PRE + MAX_PAYLOAD_SIZE];
    int writeIndex;
    int len;
    bool bin;
    bool fin;
};

static int protocol_my_callback( struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len ) {
    struct session_data *data = (struct session_data *) user;
    switch ( reason ) {
        case LWS_CALLBACK_ESTABLISHED:       // 当服务器和客户端完成握手后
            printf("Client connect!\n");
            break;
        case LWS_CALLBACK_RECEIVE:           // 当接收到客户端发来的帧以后
            // 判断是否二进制消息
            data->bin = lws_frame_is_binary( wsi );
            if (data->bin) {
                printf("Now not handle binary data\n");
                return 0;
            }

            // 判断是否最后一帧
            data->fin = lws_is_final_fragment( wsi );
            // 业务处理部分，为了实现Echo服务器，把客户端数据保存起来
            memcpy( &data->buf[ LWS_PRE + data->writeIndex], in, len );
            data->writeIndex += len;
            data->len += len;
            // printf("recvied message:%s\n",in);
            if (data->fin) {
                if (0 == strncasecmp((const  char *)data->buf + LWS_PRE, "ping", strlen("ping"))) {
                    data->len = 0;
                    data->writeIndex = 0;
                    memset(data->buf + LWS_PRE, 0, sizeof(data->buf));
                    lws_write( wsi, &data->buf[ LWS_PRE ], data->len, LWS_WRITE_PONG );
                    return 0; 
                } else {
                    std::string response("");
                    recorder_signal_handle((char *)(data->buf + LWS_PRE), data->len, response, wsi);
                    data->len = 0;
                    data->writeIndex = 0;
                    memset(data->buf + LWS_PRE, 0, sizeof(data->buf));

                    memcpy(data->buf + LWS_PRE, response.data(), response.length());
                    data->len = response.length();
                    lws_callback_on_writable(wsi);
                }
            } 
            break;
        case LWS_CALLBACK_SERVER_WRITEABLE:   // 当此连接可写时
            lws_write( wsi, &data->buf[ LWS_PRE ], data->len, LWS_WRITE_TEXT );
            data->len = 0;
            data->writeIndex = 0;
            memset(data->buf + LWS_PRE, 0, sizeof(data->buf));

            // lws_rx_flow_control( wsi, 1 );
            break;
    }
    // 回调函数最终要返回0，否则无法创建服务器
    return 0;
}

/**
 * 支持的WebSocket子协议数组
 * 子协议即JavaScript客户端WebSocket(url, protocols)第2参数数组的元素
 * 你需要为每种协议提供回调函数
 */
struct lws_protocols protocols[] = {
    {
        "ws", protocol_my_callback, sizeof( struct session_data ), MAX_PAYLOAD_SIZE,
    },
    {
        NULL, NULL,   0 // 最后一个元素固定为此格式
    }
};
 
int main(int argc,char **argv)
{

    if (!initMediaServer()) {
        std::cout << "init media server failed!" << std::endl;
        return -1;
    }


    // 信号处理函数
    signal( SIGTERM, sighdl );
    
    struct lws_context_creation_info ctx_info = { 0 };
    ctx_info.port = 8000;
    ctx_info.iface = NULL; // 在所有网络接口上监听
    ctx_info.protocols = protocols;
    ctx_info.gid = -1;
    ctx_info.uid = -1;
    ctx_info.options = LWS_SERVER_OPTION_VALIDATE_UTF8;

    struct lws_context *context = lws_create_context(&ctx_info);
    while ( !exit_sig ) {
        lws_service(context, 1000);
    }
    lws_context_destroy(context);

    return 0;
}