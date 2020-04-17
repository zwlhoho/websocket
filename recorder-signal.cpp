#include "recorder-signal.h"
#include <iostream>
#include <map>
#include "sdptransform/sdptransform.hpp"
#include "mediaserver/RTPBundleTransport.h"
#include "mediaserver/RTPTransport.h"
#include "mediaserver/rtp/RTPStreamTransponder.h"
#include "mediaserver/rtp/RTPIncomingSourceGroup.h"
#include "mediaserver/mp4recorder.h"
#include "uuid/uuid.h"

using json = nlohmann::json;
const static std::string g_localip("192.168.36.21");
 MP4Recorder *recorder;
typedef enum {
	WSOC_CONTINUATION = 0x0,
	WSOC_TEXT = 0x1,
	WSOC_BINARY = 0x2,
	WSOC_CLOSE = 0x8,
	WSOC_PING = 0x9,
	WSOC_PONG = 0xA
} WS_OPCODE;
ssize_t ws_write_frame(int fd, WS_OPCODE oc, void *data, size_t bytes);

typedef struct _RTPBundleInfo {
    RTPBundleTransport *bundle;
    DTLSICETransport *transport;
    RTPIncomingSourceGroup *audioIncomingSource;
    RTPIncomingSourceGroup *videoIncomingSource;
} RTPBundleInfo;

std::map<std::string, RTPBundleInfo> g_fromuserRTPBundleInfo;

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
    std::string fromuser = requestParam["fromuser"].get<std::string>();
    std::cout << "msgtype: " << msgtype << " request params: " << requestParam << std::endl;
    if (0 == msgtype.compare("login")) {
        std::cout << "login " << std::endl;
    } else if (0 == msgtype.compare("EventRinging")) {
        std::string sdpStr = requestParam["content"];
        std::cout << "EventRinging" << std::endl;
        std::cout << "SDP: " << sdpStr;

        json offerSDP = sdptransform::parse(sdpStr);
        try {
            std::string sdp_str = inviteHandle(offerSDP, fromuser);
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
    } else if (0 == msgtype.compare("EventReleased")) {
        std::map<std::string, RTPBundleInfo>::iterator it;
        it = g_fromuserRTPBundleInfo.find(fromuser);
        if (it != g_fromuserRTPBundleInfo.end()) {
            RTPBundleInfo bundleInfo = it->second;
            if (NULL != bundleInfo.bundle) {
                bundleInfo.bundle->End();
                delete bundleInfo.bundle;
                bundleInfo.bundle = NULL;
            }
            if (NULL != bundleInfo.transport) {
                if (NULL != bundleInfo.audioIncomingSource) {
                    bundleInfo.transport->RemoveIncomingSourceGroup(bundleInfo.audioIncomingSource);
                    delete bundleInfo.audioIncomingSource;
                    bundleInfo.audioIncomingSource = NULL;
                }
                if (NULL != bundleInfo.videoIncomingSource) {
                    bundleInfo.transport->RemoveIncomingSourceGroup(bundleInfo.videoIncomingSource);
                    delete bundleInfo.videoIncomingSource;
                    bundleInfo.videoIncomingSource = NULL;
                }
                bundleInfo.transport->Stop();
                delete bundleInfo.transport;
                bundleInfo.transport = NULL;
            }

            if (NULL != bundleInfo.videoIncomingSource) {
                bundleInfo.videoIncomingSource->Stop();
                delete bundleInfo.videoIncomingSource;
                bundleInfo.videoIncomingSource = NULL;
            }

            if (NULL != bundleInfo.audioIncomingSource) {
                bundleInfo.audioIncomingSource->Stop();
                delete bundleInfo.audioIncomingSource;
                bundleInfo.audioIncomingSource = NULL;
            }

            g_fromuserRTPBundleInfo.erase(it);
        }
        if (NULL != recorder) {
            recorder->Stop();
            recorder->Close(false);
        }
    }
    return result;
}
#include "mediaserver/rtp/RTPDepacketizer.h"
class TestRTPListener : public RTPIncomingSourceGroup::Listener {
private:
    RTPDepacketizer* depacketizer;
    MediaFrame::Listener *m_listener;
public:

    TestRTPListener(MediaFrame::Listener *listener) {
        this->m_listener = listener;
        depacketizer = NULL;
    }

    virtual void onRTP(RTPIncomingSourceGroup* group,const RTPPacket::shared& packet) { 
		if (depacketizer && depacketizer->GetCodec()!=packet->GetCodec())
		{
			delete(depacketizer);
			depacketizer = NULL;
		}
		if (!depacketizer)
			depacketizer = RTPDepacketizer::Create(packet->GetMedia(),packet->GetCodec());
		if (!depacketizer)
			return;
		 MediaFrame* frame = depacketizer->AddPacket(packet);
		 
		 if (frame) {
             std::cout << "received [ " << frame->TypeToString(frame->GetType()) << " ] frame" << std::endl;
			 this->m_listener->onMediaFrame(packet->GetSSRC(),*frame);
			 depacketizer->ResetFrame();
		 }

    }
    virtual void onEnded(RTPIncomingSourceGroup* group) {
        std::cout << "ohaha. Catch RTP Packet!!!!!! End" << std::endl;
	}
};

#include "mediaserver/remoterateestimator.h"
class SenderSideEstimatorListener : 
	public RemoteRateEstimator::Listener
{
public:
	SenderSideEstimatorListener() {
		
	}
	
	virtual void onTargetBitrateRequested(DWORD bitrate) override {
		//Check we have not send an update too recently (1s)
		if (getTimeDiff(last)/1000 < period)
			//Do nothing
			return;
		
		//Update it
		last = getTime();
		// std::cout << "bit rate: " << bitrate << "last: " << last << std::endl;
	}
	
	void SetMinPeriod(DWORD period) { this->period = period; }
	
private:
	DWORD period	= 1000;
	QWORD last	= 0;
};


class StreamTrackDepacketizer :
	public RTPIncomingSourceGroup::Listener
{
public:
	StreamTrackDepacketizer(RTPIncomingSourceGroup* incomingSource)
	{
		//Store
		this->incomingSource = incomingSource;
		//Add us as RTP listeners
		this->incomingSource->AddListener(this);
		//No depkacketixer yet
		depacketizer = NULL;
	}

	virtual ~StreamTrackDepacketizer()
	{
		//JIC
		Stop();
		//Check 
		if (depacketizer)
			//Delete depacketier
			delete(depacketizer);
	}

	virtual void onRTP(RTPIncomingSourceGroup* group,const RTPPacket::shared& packet)
	{
		//Do not do extra work if there are no listeners
		if (listeners.empty()) 
			return;
		
		//If depacketizer is not the same codec 
		if (depacketizer && depacketizer->GetCodec()!=packet->GetCodec())
		{
			//Delete it
			delete(depacketizer);
			//Create it next
			depacketizer = NULL;
		}
		//If we don't have a depacketized
		if (!depacketizer)
			//Create one
			depacketizer = RTPDepacketizer::Create(packet->GetMedia(),packet->GetCodec());
		//Ensure we have it
		if (!depacketizer)
			//Do nothing
			return;
		//Pass the pakcet to the depacketizer
		 MediaFrame* frame = depacketizer->AddPacket(packet);
		 
		 //If we have a new frame
		 if (frame)
		 {
             if (MediaFrame::Video == frame->GetType()) {
                 VideoFrame *videoFrame = (VideoFrame *)frame;
                 std::cout << "received [ Video ] frame, SSRC: " << frame->GetSSRC()  << " Payload Type: " << packet->GetPayloadType() << " Frame Codec: " << videoFrame->GetCodec() \
                            << " Width: " <<  videoFrame->GetWidth() << " Height: " << videoFrame->GetHeight() << " IsIntra: " << videoFrame->IsIntra() << std::endl;
             } else if (MediaFrame::Audio == frame->GetType()) {
                 AudioFrame *audioFrame = (AudioFrame *)frame;
                 std::cout << "received [ Audio ] frame, SSRC: " << frame->GetSSRC()  << " Payload Type: " << packet->GetPayloadType() << " Frame Codec: " << audioFrame->GetCodec() \
                            << " Rate: " <<  audioFrame->GetRate() << std::endl;
             }
			 //Call all listeners
			 for (Listeners::const_iterator it = listeners.begin();it!=listeners.end();++it)
				 //Call listener
				 (*it)->onMediaFrame(packet->GetSSRC(),*frame);
			 //Next
			 depacketizer->ResetFrame();
		 }
		
			
	}
	
	virtual void onEnded(RTPIncomingSourceGroup* group) 
	{
		if (incomingSource==group)
			incomingSource = nullptr;
	}
	
	void AddMediaListener(MediaFrame::Listener *listener)
	{
		//Add to set
		listeners.insert(listener);
	}
	
	void RemoveMediaListener(MediaFrame::Listener *listener)
	{
		//Remove from set
		listeners.erase(listener);
	}
	
	void Stop()
	{
		//If already stopped
		if (!incomingSource)
			//Done
			return;
		
		//Stop listeneing
		incomingSource->RemoveListener(this);
		//Clean it
		incomingSource = NULL;
	}
	
private:
	typedef std::set<MediaFrame::Listener*> Listeners;
private:
	Listeners listeners;
	RTPDepacketizer* depacketizer;
	RTPIncomingSourceGroup* incomingSource;
};

std::string inviteHandle(json offerSDP, std::string fromuser) {
    int localPort = -1;
    RTPBundleTransport *bundle = new RTPBundleTransport();
    DTLSICETransport *transport = NULL;
    std::string fingerprint = DTLSConnection::GetCertificateFingerPrint(DTLSConnection::Hash::SHA256);
    json candidate;
    Properties properties;
    bundle->Init();
    localPort = bundle->GetLocalPort();
    candidate["foundation"] = std::string("1");
    candidate["component"] = 1;
    candidate["transport"] = std::string("UDP");
    candidate["priority"] = 33554431;
    candidate["ip"] = g_localip;
    candidate["port"] = localPort;
    candidate["type"] = std::string("host");
    
    // std::cout << "candaidate: " << candidate << std::endl;

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
    std::cout << "offer sdp: " << offerSDP << std::endl;
    try {
        //Put ice properties
        properties.SetProperty("ice.localUsername"	, "abcd");
        properties.SetProperty("ice.localPassword"	, "1234567890abcdefghijklmnopqrstuvwxy");
        properties.SetProperty("ice.remoteUsername"	, offerSDP["media"][0]["iceUfrag"].get<std::string>());
        properties.SetProperty("ice.remotePassword"	, offerSDP["media"][0]["icePwd"].get<std::string>());

        //Put remote dtls properties
        properties.SetProperty("dtls.setup"		, "passive");
        properties.SetProperty("dtls.hash"		, offerSDP["media"][0]["fingerprint"]["type"].get<std::string>());
        properties.SetProperty("dtls.fingerprint"	, offerSDP["media"][0]["fingerprint"]["hash"].get<std::string>());
        
        //Put other options
        properties.SetProperty("disableSTUNKeepAlive"	, "false");
        properties.SetProperty("srtpProtectionProfiles"	, "");
    } catch(std::exception ee) {
        std::cout << ee.what() << std::endl;
    }
    std::cout << "------------------------------------------- " << __LINE__ << std::endl;
    
    std::string username = g_ice["ufrag"];
    username += ":" ;
    username += offerSDP["media"][0]["iceUfrag"];

    std::cout << "------------------------------------------- " << __LINE__ << std::endl;

    transport =  bundle->AddICETransport(username, properties);
    // transport->SetSenderSideEstimatorListener(new SenderSideEstimatorListener());
    std::cout << "------------------------------------------- " << __LINE__ << std::endl;

    for(int index = 0; index < offerSDP["media"].size(); index++) {
        // std::cout << "----------------------------------------------------------------" << std::endl;
        // std::cout << "media[ " << index << " ]\n" << offerSDP["media"][index] << std::endl;
        
        for(int  jindex = 0; jindex < offerSDP["media"][index]["candidates"].size(); jindex++) {
            json &tmpCandidate = offerSDP["media"][index]["candidates"][jindex];
            bundle->AddRemoteCandidate(username, tmpCandidate["ip"].get<std::string>().c_str(), tmpCandidate["port"].get<int>());   
        }
    }
    
    // set remote properties
    Properties remoteProperties;
    json trackInfo;
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

            json &ssrcs = indexMedia["ssrcs"];
            json &ssrc_group = indexMedia["ssrcGroups"];
            trackInfo[mediaType]["media"] = indexMedia["type"];
            for (int ssrcIndex = 0; ssrcIndex < ssrcs.size(); ++ssrcIndex) {
                uint32_t id = ssrcs[ssrcIndex]["id"].get<uint32_t>();
                
                std::string attribute = ssrcs[ssrcIndex]["attribute"].get<std::string>();
                std::string value = ssrcs[ssrcIndex]["value"].get<std::string>();
                if (0 == attribute.compare("label")) {
                    trackInfo[mediaType]["id"] = ssrcs[ssrcIndex]["value"].get<std::string>();
                    trackInfo[mediaType]["ssrcs"].push_back(id);
                }
            }

            for (int groupIndex = 0; groupIndex < ssrc_group.size(); ++groupIndex) {
                json &group = ssrc_group[groupIndex];
                // std::cout << "ssrc_group:\n"  << group.dump() << std::endl;
                std::string ssrcs_str = group["ssrcs"].get<std::string>();
                uint32_t tmpSSRC = 0;
                trackInfo[mediaType]["groups"]["semantics"] = group["semantics"];

                for (int tmpIndex = 0; tmpIndex < ssrcs_str.length(); ++tmpIndex) {
                    if (ssrcs_str[tmpIndex] >= '0' && ssrcs_str[tmpIndex] <= '9') {
                        tmpSSRC *= 10;
                        tmpSSRC += (ssrcs_str[tmpIndex] - '0');
                        continue;
                    } else if (0 != tmpSSRC) {
                        trackInfo[mediaType]["groups"]["ssrcs"].push_back(tmpSSRC);
                    }
                    tmpSSRC = 0;
                }

                if (0 != tmpSSRC) {
                    trackInfo[mediaType]["groups"]["ssrcs"].push_back(tmpSSRC);
                }
            }
        }
    }

    transport->SetRemoteProperties(remoteProperties); 
    
    {
        // [audio.codecs.0.codec:opus]
        // [audio.codecs.0.pt:111]
        // [audio.codecs.length:1]
        // [audio.ext.length:0]
        // [video.codecs.0.codec:vp8]

        // [video.codecs.0.pt:96]
        // [video.codecs.length:1]
        // [video.ext.length:0]
        Properties localProperties;
        localProperties.SetProperty("audio.codecs.0.codec", "pcmu");
        localProperties.SetProperty("audio.codecs.0.pt", 0);
        localProperties.SetProperty("audio.codecs.1.codec", "pcma");
        localProperties.SetProperty("audio.codecs.1.pt", 8);
        localProperties.SetProperty("audio.codecs.length", 2);
        localProperties.SetProperty("audio.ext.length", 0);

        localProperties.SetProperty("video.codecs.0.codec", "vp8");
        localProperties.SetProperty("video.codecs.0.pt", 96);
        localProperties.SetProperty("video.codecs.length", 1);
        localProperties.SetProperty("video.ext.length", 0);
        
        transport->SetLocalProperties(localProperties);
    }

    std::string sdp_str(""); 
    {
        

    // }    

    // {
        // create track
        json &audioTrack = trackInfo["audio"];
        json &videoTrack = trackInfo["video"];
        //MP4Recorder
        recorder = new MP4Recorder();
        if (recorder->Create("/tmp/myrecorder.mp4")) {
            std::cout << "recorder Create succeed!" << std::endl;
        } else {
            std::cout << "recorder Create failed!" << std::endl;
        }

        recorder->Record(true);

        // TestRTPListener *testRTPListener = new TestRTPListener(recorder);

        // std::cout << "audio track: " << audioTrack << std::endl;
        // std::cout << "video track: " << videoTrack << std::endl;

        RTPIncomingSourceGroup *audioSource = new RTPIncomingSourceGroup(MediaFrame::Audio);
        audioSource->media.ssrc = audioTrack["ssrcs"].at(0).get<uint32_t>();
        audioSource->rtx.ssrc = 0;
        audioSource->fec.ssrc = 0;
        if (transport->AddIncomingSourceGroup(audioSource)) {
            std::cout << "------Add Audio Incoming Source Group succeed!" << std::endl;
        } else {
            std::cout << "------Add Audio Incoming Source Group failed!" << std::endl;
        }

        RTPIncomingSourceGroup *videoSource = new RTPIncomingSourceGroup(MediaFrame::Video);
        videoSource->media.ssrc = videoTrack["ssrcs"].at(0).get<uint32_t>();
        videoSource->rtx.ssrc = videoTrack["groups"]["ssrcs"].at(1).get<uint32_t>();
        videoSource->fec.ssrc = 0;
        if (transport->AddIncomingSourceGroup(videoSource)) {
            std::cout << "------Add Video Incoming Source Group succeed!" << std::endl;
        } else {
            std::cout << "------Add Video Incoming Source Group failed!" << std::endl;
        }

        // audioSource->AddListener(testRTPListener);
        // videoSource->AddListener(testRTPListener);

        StreamTrackDepacketizer *audioTrackDepacket = new StreamTrackDepacketizer(audioSource);
        audioTrackDepacket->AddMediaListener(recorder);

        StreamTrackDepacketizer *videoTrackDepacket = new StreamTrackDepacketizer(videoSource);
        videoTrackDepacket->AddMediaListener(recorder);

        RTPOutgoingSourceGroup *audioOutgoingSource = new RTPOutgoingSourceGroup(MediaFrame::Audio);
        audioOutgoingSource->rtx.ssrc = 0;
        audioOutgoingSource->fec.ssrc = 0;
        if (transport->AddOutgoingSourceGroup(audioOutgoingSource)) {
            std::cout << "------Add Audio Outgoing Source Group succeed!" << std::endl;
        } else {
            std::cout << "------Add Audio Outgoing Source Group failed!" << std::endl;
        }

        RTPStreamTransponder *audioTransponder = new RTPStreamTransponder(audioOutgoingSource, transport);
        audioTransponder->SetIncoming(audioSource, transport);

        RTPOutgoingSourceGroup *videoOutgoingSource = new RTPOutgoingSourceGroup(MediaFrame::Video);
        if (transport->AddOutgoingSourceGroup(videoOutgoingSource)) {
            std::cout << "------Add Video Outgoing Source Group succeed!" << std::endl;
        } else {
            std::cout << "------Add Video Outgoing Source Group failed!" << std::endl;
        }

        RTPStreamTransponder *videoTransponder = new RTPStreamTransponder(videoOutgoingSource, transport);
        videoTransponder->SetIncoming(videoSource, transport);

        RTPBundleInfo rtpBundleInfo;
        rtpBundleInfo.bundle = bundle;
        rtpBundleInfo.transport = transport;
        rtpBundleInfo.audioIncomingSource = audioSource;
        rtpBundleInfo.videoIncomingSource = videoSource;

        g_fromuserRTPBundleInfo.insert(std::pair<std::string, RTPBundleInfo>(fromuser, rtpBundleInfo));


        json sdp;
        json group_bundle;
        json audio_media;
        json pcma_payload;
        json pcmu_payload;
        json opus_payload;

        json video_media;
        json vp8_payload;
        json h264_payload;
        json video_ext3;
        json video_ext5;
        
        audio_media["candidates"].push_back(candidate);
        audio_media["direction"] = "sendrecv";
        audio_media["setup"] = "active";
        audio_media["mid"] = "0";
        audio_media["payloads"] = "0 8";
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

        // a=extmap:3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
        // a=extmap:5 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
        video_ext3["uri"] = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";
        video_ext3["value"] = 3;
        video_ext5["uri"] = "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
        video_ext5["value"] = 5;

        video_media["candidates"].push_back(candidate);
        video_media["direction"] = "sendrecv";
        video_media["setup"] = "active";
        video_media["mid"] = "1";
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
        video_media["ext"].push_back(video_ext3);
        video_media["ext"].push_back(video_ext5);

        vp8_payload["codec"] = "VP8";
        vp8_payload["payload"] = 96;
        vp8_payload["rate"] = 90000;

        h264_payload["codec"] = "H264";
        h264_payload["payload"] = 100;
        h264_payload["rate"] = 90000;

        video_media["rtp"].push_back(vp8_payload);


        json audioSSRC;
        std::string mediastreamid = uuid_gen_test();
        audioSSRC["attribute"] = "cname";
        audioSSRC["value"] = mediastreamid;
        audioSSRC["id"] = audioOutgoingSource->media.ssrc;
        audio_media["ssrcs"].push_back(audioSSRC);

        audioSSRC["attribute"] = "msid";
        audioSSRC["value"] = mediastreamid + " " + "audio0";
        audioSSRC["id"] = audioOutgoingSource->media.ssrc;   
        audio_media["ssrcs"].push_back(audioSSRC);

        json ssrc;
        ssrc["attribute"] = "cname";
        ssrc["value"] = mediastreamid;
        ssrc["id"] = videoOutgoingSource->media.ssrc;
        video_media["ssrcs"].push_back(ssrc);

        ssrc["attribute"] = "msid";
        ssrc["value"] = mediastreamid + " " + "video0";
        ssrc["id"] = videoOutgoingSource->media.ssrc;   
        video_media["ssrcs"].push_back(ssrc);

        ssrc["attribute"] = "cname";
        ssrc["value"] = mediastreamid;
        ssrc["id"] = videoOutgoingSource->rtx.ssrc;
        video_media["ssrcs"].push_back(ssrc);

        ssrc["attribute"] = "msid";
        ssrc["value"] = mediastreamid + " " + "video0";
        ssrc["id"] = videoOutgoingSource->rtx.ssrc;   
        video_media["ssrcs"].push_back(ssrc);

        ssrc["attribute"] = "cname";
        ssrc["value"] = mediastreamid;
        ssrc["id"] = videoOutgoingSource->fec.ssrc;
        video_media["ssrcs"].push_back(ssrc);

        ssrc["attribute"] = "msid";
        ssrc["value"] = mediastreamid + " " + "video0";
        ssrc["id"] = videoOutgoingSource->fec.ssrc;   
        video_media["ssrcs"].push_back(ssrc);

        json ssrc_group;
        std::stringstream ss;

        ss << videoOutgoingSource->media.ssrc << " " << videoOutgoingSource->rtx.ssrc;
        ssrc_group["semantics"] = "FID";
        ssrc_group["ssrcs"] = ss.str();
        video_media["ssrcGroups"].push_back(ssrc_group);

        ss.str("");
        ss << videoOutgoingSource->media.ssrc << " " << videoOutgoingSource->fec.ssrc;
        ssrc_group["semantics"] = "FEC-FR";
        ssrc_group["ssrcs"] = ss.str();
        video_media["ssrcGroups"].push_back(ssrc_group);

        // "groups":[{"mids":"audio video","type":"BUNDLE"}]
        group_bundle["mids"] = "0 1";
        group_bundle["type"] = "BUNDLE";
        sdp["groups"].push_back(group_bundle);
        sdp["media"].push_back(audio_media);
        sdp["media"].push_back(video_media);

        sdp["connection"]["ip"] = "192.168.32.80";
        sdp["connection"]["version"] = 4;
        sdp["origin"]["address"] = "192.168.32.80";
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

    {
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

std::string uuid_gen_test() {
    uuid_t uuid;
    char buf[64] = {0};
    uuid_generate(uuid);
    uuid_unparse(uuid, buf);
    return std::string(buf);
}