#ifndef RECORDER_SIGNAL_H
#define RECORDER_SIGNAL_H
#include "fdinfo.h"
#include <string>
#include "sdptransform/json.hpp"

using json = nlohmann::json;

bool initMediaServer();
void recorder_signal_handle(FDInfo *fdInfo);
std::string doHandleRequest(std::string msgtype, json requestParam, FDInfo *fdInfo);
std::string inviteHandle(json offerSDP, std::string fromuser);

#endif