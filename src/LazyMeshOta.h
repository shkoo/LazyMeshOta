#ifndef LAZYMESHOTA_H
#define LAZYMESHOTA_H

#include <Arduino.h>
#include <WString.h>
#include <assert.h>

#include <algorithm>
#include <atomic>
#if defined(EPOXY_DUINO)
#include "fake_update.h"
#include "fake_wifi.h"
#else
#include <Schedule.h>
#include <lwip/prot/ethernet.h>
#include <user_interface.h>
#include <wifi_raw.h>  // https://github.com/shkoo/esp8266_wifi_raw
#endif

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
  class Listener {
   public:
    virtual void onNeighborSeen(eth_addr src, String sketchName, int version, String md5);
    virtual void onStartUpgrade(eth_addr src, int version, String md5);
    virtual void onDoneUpgrade();

    virtual void onSendProgress(eth_addr src, size_t start, size_t len, size_t tot_size);
    virtual void onRequestChunk(size_t start, size_t tot_size);
    virtual void onReceiveTimeout();
    virtual void onError(String err);
  };

  LazyMeshOta() = default;
  ~LazyMeshOta() { end(); }

  // 'version' is the version number of the current software.  Any
  // peer nodes with lower version numbers and the same sketchName
  // will be upgraded.
  void begin(String sketchName, int version);

  void setListener(Listener* l) { _listener = l; }

  void end();
  void register_wifi_cb() {
    assert(!_instance);
    _instance = this;
    wifi_raw_set_recv_cb(onReceiveRawFrameCallback);
  }
  // Receives a raw frame directly from the network stack, likely in an interrupt context.
  static void onReceiveRawFrameCallback(RxPacket*) IRAM_ATTR;

  // Receives a raw frame.  Must free frame when done.
  bool onReceiveRawFrame(RxPacket* pkt);

  // Convert ethernet address to string.
  static String ethToString(const eth_addr& addr);
  // Convert string to ethernet address.  Return true on success.
  static bool ethFromString(eth_addr* out, String src);

#if defined(EPOXY_DUINO)
  void loop() { _loop(); }
#endif

 private:
  enum class PKT_TYPE : uint8_t {
    // Advertise current version as "<sketchName>\n<version>\n<sketchsize>\n<md5dum>\n<src
    // bssid>\n".
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
  class BufStream : public Stream {
   public:
    BufStream(char* buf, size_t len) : _buf(buf), _len(len) {}
    int available() override {
      assert(_len >= _pos);
      return _len - _pos;
    }
    int read() override {
      assert(_len >= _pos);
      if (_len == _pos) {
        return -1;
      }
      return _buf[_pos++];
    }
#if STREAM_READ_RETURNS_INT
    int read(uint8_t* buffer, size_t len) {
      assert(_len >= _pos);
      size_t actual = std::min<size_t>(len, _len - _pos);
      memcpy(buffer, _buf + _pos, actual);
      return actual;
    }
#endif
    int peek() override {
      assert(_len >= _pos);
      if (_len == _pos) {
        return -1;
      }
      return _buf[_pos];
    }

#if STREAMSEND_API
#define STREAMSEND_OVERRIDE override
#else
#define STREAMSEND_OVERRIDE
#endif
    bool hasPeekBufferAPI() const STREAMSEND_OVERRIDE { return true; }

    size_t peekAvailable() STREAMSEND_OVERRIDE {
      assert(_len >= _pos);
      return _len - _pos;
    }

    const char* peekBuffer() STREAMSEND_OVERRIDE {
      assert(_len >= _pos);
      return _buf + _pos;
    }

    void peekConsume(size_t consume) STREAMSEND_OVERRIDE {
      assert(_len >= _pos);
      assert(consume + _pos <= _len);
      _pos += consume;
    }

    bool inputCanTimeout() STREAMSEND_OVERRIDE { return false; }
#undef STREAMSEND_OVERRIDE

    virtual size_t write(uint8_t) override { return 0; }

   private:
    char* _buf = nullptr;
    size_t _pos = 0;
    size_t _len = 0;
  };

  //  static constexpr uint32_t advertiseInterval = 60000; // Advertise our version every 60
  //  seconds.

#if defined(EPOXY_DUINO)
  static constexpr uint32_t advertiseInterval = 1000;
  static constexpr uint32_t receiveTimeoutInterval = 456;
  static constexpr uint16_t bufferSize = 4;  // Number of bytes to transfer per packet.
#else
  static constexpr uint32_t advertiseInterval = 30000;
  static constexpr uint32_t receiveTimeoutInterval = 10000;
  static constexpr uint16_t bufferSize = 1024;  // Number of bytes to transfer per packet.
#endif
  static constexpr uint16_t maxRetries = 10;  // Number of times to try a block before giving up.

  eth_addr _getLocalBssid();

  // Runs once per loop.  Checks to see if we need to advertise and/or resend lost packets.
  void _loop();

  void _transmit(PKT_TYPE pkt_type, eth_addr dest, eth_addr bssid, String msg);
  void _tracePacket(uint8_t* pkt, uint32_t len, uint32_t hdr_start);

  void _advertise();
  void _receiveAdvertise(const eth_addr& src, BufStream& body);
  void _startUpdate(const eth_addr& src, const eth_addr& bssid, int version, uint32_t sketchsize,
                    String md5sum);
  void _requestNextBlock();
  void _receiveTimeout();
  void _receiveReq(const eth_addr& src, BufStream& body);
  void _receiveReply(const eth_addr& src, BufStream& body);

  Listener _defaultListener;
  Listener* _listener = &_defaultListener;
  // timestamp in millis of next version advertisement
  uint32_t _nextAdvertise = 0;

  // timestamp in millis of next receive timeout, if update is in progress.
  uint32_t _nextReceiveTimeout = 0;
  uint16_t _retryCount = 0;

  // Version of our current sketch.
  String _localSketchName;
  int _localVersion;
  String _localSketchMd5;
  uint32_t _localSketchSize;
  eth_addr _localEthAddr;

  // New version download in progress.
  update_t* _update = nullptr;

  // True if an update is complete; we then just wait for reboot.
  bool _terminate = false;

  // For the register_wifi_cb convenience method
  static LazyMeshOta* _instance;
};

#endif
