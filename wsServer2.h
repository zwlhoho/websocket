#include <libwebsockets.h>
#include <string>

void userRegister(std::string userid, struct lws* wsi);
void sendToUser(std::string userid, std::string data);