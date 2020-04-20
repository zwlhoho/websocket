 g++ -g recorder-signal.cpp fdinfo.cpp base64.cpp wsServer.cpp -L/usr/lib/x86_64-linux-gnu/ -lm  -lstdc++ -lpthread -L./lib -lsdptransform ./lib/libmediaserver.a -lssl -lcrypto -lsrtp2 -I./include -I./include/mediaserver -I /home/zwl/bin/mp4v2/include/ /home/zwl/bin/mp4v2/lib/libmp4v2.a -o wsServer

















 g++ -g recorder-signal.cpp fdinfo.cpp base64.cpp wsServer.cpp -L/usr/lib/x86_64-linux-gnu/ -lm  -lstdc++ -lpthread -L./lib -lsdptransform ./lib/libmediaserver.a ./lib/libuuid.a -lssl -lcrypto -lsrtp2 -I./include -I./include/mediaserver -I/home/zwl/Code/test/medooze/mp4v2/lib/include/ -I /home/zwl/Code/test/medooze/mp4v2/config/include/ /home/zwl/Code/test/medooze/mp4v2/libmp4v2.a  -o wsServer


基于libwebsockets的ws wsServer
 g++ -g recorder-signal.cpp wsServer2.cpp -lstdc++ -lpthread -L./lib -lsdptransform ./lib/libmediaserver.a ./lib/libuuid.a -lssl -lcrypto -lsrtp2 -lwebsockets -I./include -I./include/mediaserver -I/home/zwl/Code/test/medooze/mp4v2/lib/include/ -I /home/zwl/Code/test/medooze/mp4v2/config/include/ /home/zwl/Code/test/medooze/mp4v2/libmp4v2.a  -o wsServer2

