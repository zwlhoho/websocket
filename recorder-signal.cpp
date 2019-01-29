#include "recorder-signal.h"
#include <iostream>
#include "sdptransform/sdptransform.hpp"
#include "mediaserver/RTPBundleTransport.h"

#include "mediaserver/RTPBundleTransport.h"
#include "mediaserver/RTPTransport.h"
#include "mediaserver/config.h"

using json = nlohmann::json;
Properties g_properties;
const static std::string g_localip("192.168.8.178");

typedef enum {
	WSOC_CONTINUATION = 0x0,
	WSOC_TEXT = 0x1,
	WSOC_BINARY = 0x2,
	WSOC_CLOSE = 0x8,
	WSOC_PING = 0x9,
	WSOC_PONG = 0xA
} WS_OPCODE;
ssize_t ws_write_frame(int fd, WS_OPCODE oc, void *data, size_t bytes);

void recorder_signal_handle(FDInfo *fdInfo) {
    const char *signal_data = (char *)fdInfo->GetReadBuf();
    try {
        json requestParam = json::parse(signal_data);
        std::cout << requestParam["msgtype"] << std::endl;
        std::string response = doHandleRequest(requestParam["msgtype"], requestParam, fdInfo);        
    } catch (std::exception e) {
        std::cout << "Parse msg failed! " << e.what() << std::endl;
    }
}

std::string doHandleRequest(std::string msgtype, json requestParam, FDInfo *fdInfo) {
    std::string result("");
    std::cout << "msgtype: " << msgtype << " request params: " << requestParam << std::endl;
    if (0 == msgtype.compare("login")) {
        std::cout << "login " << std::endl;
    } else if (0 == msgtype.compare("EventRinging")) {
        std::string sdpStr = requestParam["content"];
        std::cout << "EventRinging" << std::endl;
        std::cout << "SDP: " << sdpStr;

        json offerSDP = sdptransform::parse(sdpStr);
        try {
            std::string sdp_str = inviteHandle(offerSDP);
            json response;
            response["msgtype"] = "RequestAnswerCall";
            response["content"] = sdp_str;
            response["touser"] = "1010";
            std::string res_str = response.dump();
            std::cout << "response str: " << res_str <<std::endl;

            ws_write_frame(fdInfo->GetFD(), WSOC_TEXT, (void *)res_str.c_str(), res_str.length());
        } catch (std::exception e) {
            std::cout << "Invite Handle Failed!\n" << e.what() << std::endl;
        }
    }
    return result;
}

std::string inviteHandle(json offerSDP) {
    int localPort = -1;
    RTPBundleTransport *bundle = new RTPBundleTransport();
    DTLSICETransport *transport = NULL;
    std::string fingerprint = DTLSConnection::GetCertificateFingerPrint(DTLSConnection::Hash::SHA256);
    json candidate;
    bundle->Init();
    localPort = bundle->GetLocalPort();
    candidate["foundation"] = std::string("1");
    candidate["component"] = 1;
    candidate["transport"] = std::string("UDP");
    candidate["priority"] = 33554431;
    candidate["ip"] = g_localip;
    candidate["port"] = localPort;
    candidate["type"] = std::string("host");
    
    std::cout << "candaidate: " << candidate << std::endl;

    std::cout << "------------------------------------------- " << __LINE__ << std::endl;
    json g_ice;
    g_ice["ufrag"] = "abcd";
    g_ice["pwd"] = "1234567890abcdefghijklmnopqrstuvwxy";

    std::cout << "------------------------------------------- " << __LINE__ << std::endl;

    json g_dtls;
    g_dtls["setup"] = "passive";
    g_dtls["fingerprint"] = fingerprint;
    g_dtls["hash"] = "sha-256";

    std::cout << "------------------------------------------- " << __LINE__ << std::endl;
    try {
        //Put ice properties
        g_properties.SetProperty("ice.localUsername"	, "abcd");
        g_properties.SetProperty("ice.localPassword"	, "1234567890abcdefghijklmnopqrstuvwxy");
        g_properties.SetProperty("ice.remoteUsername"	, offerSDP["media"][0]["iceUfrag"].get<std::string>());
        g_properties.SetProperty("ice.remotePassword"	, offerSDP["media"][0]["icePwd"].get<std::string>());

        //Put remote dtls properties
        g_properties.SetProperty("dtls.setup"		, "passive");
        g_properties.SetProperty("dtls.hash"		, "sha-256");
        g_properties.SetProperty("dtls.fingerprint"	, fingerprint);
        
        //Put other options
        g_properties.SetProperty("disableSTUNKeepAlive"	, "false");
        g_properties.SetProperty("srtpProtectionProfiles"	, "");
    } catch(std::exception ee) {
        std::cout << ee.what() << std::endl;
    }
    std::cout << "------------------------------------------- " << __LINE__ << std::endl;
    
    std::string username = g_ice["ufrag"];
    username += ":" ;
    username += offerSDP["media"][0]["iceUfrag"];

    std::cout << "------------------------------------------- " << __LINE__ << std::endl;

    transport =  bundle->AddICETransport(username, g_properties);
    
    std::cout << "------------------------------------------- " << __LINE__ << std::endl;

    for(int index = 0; index < offerSDP["media"].size(); index++) {
        std::cout << "----------------------------------------------------------------" << std::endl;
        std::cout << "media[ " << index << " ]\n" << offerSDP["media"][index] << std::endl;
        
        for(int  jindex = 0; jindex < offerSDP["media"][index]["candidates"].size(); jindex++) {
            json &tmpCandidate = offerSDP["media"][index]["candidates"][jindex];
            bundle->AddRemoteCandidate(username, tmpCandidate["ip"].get<std::string>().c_str(), tmpCandidate["port"].get<int>());   
        }
    }
    
    // set remote properties
    Properties remoteProperties;
    {
        for(int mediaTypeIndex = 0; mediaTypeIndex < offerSDP["media"].size(); ++mediaTypeIndex) {
            json &indexMedia = offerSDP["media"][mediaTypeIndex];
            std::string mediaType(indexMedia["type"].get<std::string>());
            json &codecs = indexMedia["rtp"];
            json &ext = indexMedia["ext"];
            int num = 0;
            std::string codecPrefix = mediaType + "." +"codecs";
            std::string extPrefix  = mediaType + "." + "ext";
            for (int codecIndex = 0; codecIndex < codecs.size(); ++codecIndex) {
                remoteProperties.SetProperty(codecPrefix + "." + std::to_string(codecIndex) + ".codec", codecs[codecIndex]["codec"].get<std::string>());
                remoteProperties.SetProperty(codecPrefix + "." + std::to_string(codecIndex) + ".pt", std::to_string(codecs[codecIndex]["payload"].get<int>()));
            }
            remoteProperties.SetProperty(codecPrefix + ".length", std::to_string(codecs.size()));

            for (int extIndex = 0; extIndex < ext.size(); ++extIndex) {
                remoteProperties.SetProperty(extPrefix + "." + std::to_string(extIndex) + ".id", std::to_string(ext[extIndex]["value"].get<int>()));
                remoteProperties.SetProperty(extPrefix + "." + std::to_string(extIndex) + ".uri", ext[extIndex]["uri"].get<std::string>());
            }
            remoteProperties.SetProperty(extPrefix + ".length", std::to_string(ext.size()));
        }
    }

    transport->SetRemoteProperties(remoteProperties);

    std::string sdp_str(""); 
    {
        json sdp;
        json audio_media;
        json pcma_payload;
        json pcmu_payload;
        json opus_payload;

        json video_media;
        json vp8_payload;
        
        audio_media["candidates"].push_back(candidate);
        audio_media["direction"] = "recvonly";
        audio_media["setup"] = "active";
        audio_media["mid"] = "audio";
        audio_media["payloads"] = "0 8 111";
        audio_media["port"] = candidate["port"];
        audio_media["protocol"] = "UDP/TLS/RTP/SAVPF";
        audio_media["type"] = "audio";
        audio_media["rtcpMux"] = "rtcp-mux";
        audio_media["rtcpRsize"] = "rtcp-rsize";
        audio_media["iceUfrag"] = g_ice["ufrag"];
        audio_media["icePwd"] = g_ice["pwd"];
        audio_media["fingerprint"]["type"] = "sha-256";
        audio_media["fingerprint"]["hash"] = fingerprint;

        pcma_payload["codec"] = "pcma";
        pcma_payload["payload"] = 8;
        pcma_payload["rate"] = 8000;
        pcmu_payload["codec"] = "pcmu";
        pcmu_payload["payload"] = 0;
        pcmu_payload["rate"] = 8000;
        opus_payload["codec"] = "opus";
        opus_payload["payload"] = 111;
        opus_payload["rate"] = 48000;

        audio_media["rtp"].push_back(pcmu_payload);
        audio_media["rtp"].push_back(pcma_payload);
        

        video_media["candidates"].push_back(candidate);
        video_media["direction"] = "recvonly";
        video_media["setup"] = "active";
        video_media["mid"] = "video";
        video_media["payloads"] = "96";
        video_media["port"] = candidate["port"];
        video_media["protocol"] = "UDP/TLS/RTP/SAVPF";
        video_media["type"] = "video";
        video_media["rtcpMux"] = "rtcp-mux";
        video_media["rtcpRsize"] = "rtcp-rsize";
        video_media["iceUfrag"] = g_ice["ufrag"];
        video_media["icePwd"] = g_ice["pwd"];
        video_media["fingerprint"]["type"] = "sha-256";
        video_media["fingerprint"]["hash"] = fingerprint;

        vp8_payload["codec"] = "VP8";
        vp8_payload["payload"] = 96;
        vp8_payload["rate"] = 90000;
        video_media["rtp"].push_back(vp8_payload);


        sdp["media"].push_back(audio_media);
        sdp["media"].push_back(video_media);

        sdp["connection"]["ip"] = "192.168.3.236";
        sdp["connection"]["version"] = 4;
        sdp["origin"]["address"] = "192.168.3.236";
        sdp["origin"]["ipVer"] = 4;
        sdp["origin"]["netType"] = "IN";
        sdp["origin"]["sessionId"] = 1548754406600;
        sdp["origin"]["sessionVersion"] = 1;
        sdp["origin"]["username"] = "-";
        sdp["timing"]["start"] = 0;
        sdp["timing"]["stop"] = 0;

        sdp_str = sdptransform::write(sdp);
        std::cout << "sdp_str: " << sdp_str << std::endl;
    }

    return sdp_str;

}

bool initMediaServer() {
    static int minRTPPort = 65000;
    static int maxRTPPort = 65100;
    if (RTPTransport::SetPortRange(minRTPPort, maxRTPPort)) {
        std::cout << "RTP Port Range [ " << RTPTransport::GetMinPort() << ", " << RTPTransport::GetMaxPort() << " ]" << std::endl;
    } else {
        std::cerr << "Error! Set RTP Port Range" << std::endl;
        return false;
    }
    if (DTLSConnection::Initialize()) {
        //Print hashes
        Log("-DTLS SHA1   local fingerprint \"%s\"\n",DTLSConnection::GetCertificateFingerPrint(DTLSConnection::SHA1).c_str());
        Log("-DTLS SHA224 local fingerprint \"%s\"\n",DTLSConnection::GetCertificateFingerPrint(DTLSConnection::SHA224).c_str());
        Log("-DTLS SHA256 local fingerprint \"%s\"\n",DTLSConnection::GetCertificateFingerPrint(DTLSConnection::SHA256).c_str());
        Log("-DTLS SHA384 local fingerprint \"%s\"\n",DTLSConnection::GetCertificateFingerPrint(DTLSConnection::SHA384).c_str());
        Log("-DTLS SHA512 local fingerprint \"%s\"\n",DTLSConnection::GetCertificateFingerPrint(DTLSConnection::SHA512).c_str());
        } else {
        // DTLS not available.
        Error("DTLS initialization failed, no DTLS available\n");
        return false;
    }
    Logger::EnableDebug(true);
    Logger::EnableLog(true);
    return true;
}
