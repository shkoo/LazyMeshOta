#ifndef LAZYMESHOTA_H
#define LAZYMESHOTA_H

#include <ESP8266WiFi.h>
#include <StreamString.h>
#include <flash_hal.h>
#include <lwip/prot/ethernet.h>
#include <wifi_raw.h> // https://github.com/shkoo/esp8266_wifi_raw

// LazyMeshOta propagates a new version of firmware automatically when
// any node comes into wifi range of a node with a higher version.
//
// This can be very useful where nodes are mobile and don't always
// come in contact with a master controller of any sort.
//
// The protocol logic works as follows:
//
// Periodically, each node advertises its current version of firmware
// via a brodcast packet with the ADVERTISE type.
//
// If a node receives an ADVERTISE packet advertising a newer version,
// it remembers where it came from.  Next time it would advertise, it
// instead will start the upgrade process.

class LazyMeshOta {
 public:
  // 'version' is the version number of the current software.  Any
  // peer nodes with lower version numbers will be upgraded.
  //
  // bssid should be unique for this sketch, otherwise we could try to
  // upgrade to a different sketch.
  LazyMeshOta(int version, eth_addr bssid);
  ~LazyMeshOta();

  void register_wifi_cb() { wifi_raw_set_recv_cb(on_receive_raw_frame); }
  static void on_receive_raw_frame(RxPacket*);

  // Call this in loop()
  void loop();

  // Convert ethernet address to string.
  static String ethToString(const eth_addr& addr);
  // Convert string to ethernet address.  Return true on success.
  static bool ethFromString(eth_addr* out, String src);

 private:
  enum class PKT_TYPE : uint8_t {
    // Advertise current version as "<version>\n<sketchsize>\n<md5dum>\n<src bssid>\n".
    // Replies are expected to be sent with the given soure bssid.
    ADVERTISE,

    // Request sketch data, starting at the the given integer, passed as a string "<src
    // bssid>\n<start>\n".
    // Replies are expected to be sent with the given source bssid.
    REQ,

    // Provide sketch data from a request.  Provides "<start>\n<binary data>"
    REPLY
  };

  struct hdr_t;

  struct update_t {
    // Information on a new version available
    int version = 0;
    eth_addr src;    // MAC address of node to retrieve new version from.
    eth_addr bssid;  // BSSID to use when communicating with the source.

    uint32_t offset = 0;
    uint32_t size = 0;

    uint32_t retryCount = 0;
  };

  //  static constexpr uint32_t advertiseInterval = 60000; // Advertise our version every 60
  //  seconds.
  static constexpr uint32_t advertiseInterval = 5000;
  static constexpr uint32_t receiveTimeoutInterval = 1000;  // Time out receive after 1000ms.

  static constexpr uint16_t bufferSize = 1024;  // Number of bytes to transfer per packet.

  static constexpr uint16_t maxRetries = 10;  // Number of times to try a block before giving up.

  void _transmit(PKT_TYPE pkt_type, eth_addr dest, eth_addr bssid, String msg);
  void _receive(uint8_t* frm, uint16_t len);

  void _tracePacket(uint8_t* pkt, uint32_t len, uint32_t hdr_start);

  void _advertise();
  void _receiveAdvertise(const eth_addr& src, Stream& body);
  void _startUpdate(const eth_addr& src, const eth_addr& bssid, int version, uint32_t sketchsize,
                    String md5sum);
  void _requestNextBlock();
  void _receiveTimeout();
  void _receiveReq(const eth_addr& src, Stream& body);
  void _receiveReply(const eth_addr& src, Stream& body);

  // timestamp in millis of next version advertisement
  uint32_t _nextAdvertise = 0;

  // timestamp in millis of next receive timeout, if update is in progress.
  uint32_t _nextReceiveTimeout = 0;
  uint16_t _retryCount = 0;

  // Received packet we're waiting to process when wifi isn't waiting for us.
  volatile bool _receivedPacket = false;
  PKT_TYPE _receivedPacketType;
  eth_addr _receivedSrc;
  StreamString _receivedBody;

  // Version of our current sketch.
  int _localVersion;
  String _localSketchMd5;
  uint32_t _localSketchSize;
  eth_addr _localEthAddr;

  // New version download in progress.
  update_t* _update = nullptr;

  // Static for performance in on_receive_raw_frame.
  static eth_addr _bssid;

  static LazyMeshOta* _instance;
};

#endif
