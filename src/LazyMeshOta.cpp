#include <LazyMeshOta.h>
#include <stdio.h>

#include <cerrno>

constexpr uint32_t LazyMeshOta::advertiseInterval;
constexpr uint32_t LazyMeshOta::receiveTimeoutInterval;
constexpr uint16_t LazyMeshOta::bufferSize;
constexpr uint16_t LazyMeshOta::maxRetries;

static constexpr eth_addr ethBroadcast = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
// 0 = no trace, 1 = trace some, 3 = verbose trace
static constexpr int tracePackets = 0;

LazyMeshOta* LazyMeshOta::_instance = nullptr;

#if !defined(EPOXY_DUINO)
// If not testing, run real versions of these functions from the ESP core.
static bool flashRead(uint32_t address, uint8_t* data, size_t size) {
  return ESP.flashRead(address, data, size);
}

static String getSketchMD5() { return ESP.getSketchMD5(); }

static uint32_t getSketchSize() { return ESP.getSketchSize(); }

static uint32_t getChipId() { return ESP.getChipId(); }

static bool concatString(String* str, char* buf, size_t len) { return str->concat(buf, len); }

#else

// Epoxy duino doesn't allow us to concatinate more than one character at once.
static bool concatString(String* str, char* buf, size_t len) {
  while (len) {
    if (!str->concat(*buf++)) {
      return false;
    }
    len--;
  }
  return true;
}

#endif

String LazyMeshOta::ethToString(const eth_addr& src) {
  char buf[sizeof(eth_addr) * 3 + 1];
  for (unsigned i = 0; i != sizeof(eth_addr); ++i) {
    sprintf(buf + i * 3, ":%02x", src.addr[i]);
  }
  return buf + 1 /* skip first : */;
}

static uint8_t fromHexDigit(char digit) {
  if (digit >= 'a' && digit <= 'f') {
    return digit - 'a' + 10;
  }
  if (digit >= 'A' && digit <= 'F') {
    return digit - 'A' + 10;
  }
  assert(digit >= '0' && digit <= '9');
  return digit - '0';
}

bool LazyMeshOta::ethFromString(eth_addr* dest, String src) {
  const char* ptr = src.c_str();
  for (unsigned octet = 0; octet != 6; ++octet) {
    if (!isxdigit(*ptr)) {
      return false;
    }

    dest->addr[octet] = fromHexDigit(*ptr);
    ++ptr;
    if (isxdigit(*ptr)) {
      dest->addr[octet] <<= 4;
      dest->addr[octet] |= fromHexDigit(*ptr);
      ++ptr;
    }

    if (*ptr == ':' && octet != 5) {
      ++ptr;
    }
  }
  if (*ptr) {
    // Junk afterwards
    return false;
  }
  return true;
}

struct LazyMeshOta::hdr_t {
  // 802.11 fields:

  // Bit order is weird here; ISO defines it in terms of bits, but we
  // read bytes big endian.  So what ISO calls bit 0 is our bit 7.
  //
  // Here are our bits in on-the-wire order:
  // 00 - Protocol version
  // 10 - Type = data
  // 0000 - Subtype = plain old data
  // 00 - fromds, tods = station-to-station
  // 0 - more fragments bit, not set
  // 0 - retry, not set
  // 0 - power management, not set
  // 0 - more data, not set
  // 0 - protected frame, not set
  // 0 - HTC/order, not set
  uint8_t frame_control1 = 0b00001000;
  uint8_t frame_control2 = 0b00000000;

  uint16_t duration = 0;
  eth_addr dest;
  eth_addr src;
  eth_addr bssid;
  uint16_t seq = 0;

  // 802.2 LLC PDU fields.  Not needed for us to understand ourself,
  // but useful for tcpdump output.
  uint8_t dsap = 0x31;
  uint8_t ssap = 0x31;
  uint16_t llc_pdu_ctrl = 0;

  // Our protocol data:
  uint16_t len = 0;
  PKT_TYPE packetType;
};

void LazyMeshOta::_tracePacket(uint8_t* pkt, uint32_t len, uint32_t hdr_start) {
  Serial.println("Packet of length " + String(len) + " hdr_start=" + String(hdr_start));
  if (len >= sizeof(hdr_t)) {
    hdr_t* hdr = reinterpret_cast<hdr_t*>(pkt);
    Serial.println("From: " + ethToString(hdr->src) + " To: " + ethToString(hdr->dest) +
                   " BSSID: " + ethToString(hdr->bssid) +
                   " PktType: " + String(int(hdr->packetType)));
  }
  if (tracePackets > 2) {
    for (uint32_t i = 0; i != len; ++i) {
      if ((i & 7) == 0) {
        Serial.printf("\n@%d: ", i);
      }
      if (i == hdr_start || i == (hdr_start + sizeof(hdr_t))) {
        Serial.print("*");
      } else {
        Serial.print(" ");
      }
      Serial.printf("%02x %c", pkt[i], isprint(pkt[i]) ? pkt[i] : ' ');
    }
  }
  Serial.print("\n");
}

/* Should we generate an 802.2 SNAP header inside of the 802.11 data packet?
 According to
https://legal.vvv.enseirb-matmeca.fr/download/amichel/%5BStandard%20LDPC%5D%20802.11-2012.pdf

The frame body consists of either:
— The MSDU (or a fragment thereof), the Mesh Control field (present if the frame is transmitted by a
mesh STA and the Mesh Control Present subfield of the QoS Control field is 1, otherwise absent),
and a security header and trailer (present if the Protected Frame subfield in the Frame Control
field is 1, otherwise absent) — The A-MSDU and a security header and trailer (present if the
Protected Frame subfield in the Frame Control field is 1, otherwise absen


...

all MSDUs are LLC PDUs as
defined in ISO/IEC 8802-2: 1998


*/

void LazyMeshOta::begin(String sketchName, int version) {
  _localSketchName = sketchName;
  _localSketchMd5 = getSketchMD5();
  _localSketchSize = getSketchSize();

  _localVersion = version;
  assert(wifi_get_macaddr(0, _localEthAddr.addr));

  // Don't have everything advertise all at once.
  _nextAdvertise = getChipId() % advertiseInterval;
}

void LazyMeshOta::end() {
  if (_update) {
    Update.end();
    delete _update;
    _update = nullptr;
  }
  if (_instance == this) {
    _instance = nullptr;
    wifi_raw_set_recv_cb(nullptr);
  }
}

void LazyMeshOta::loop() {
  if (_updateSucceeded) {
    return;
  }
  uint32_t cur = millis();

  if (int32_t(cur - _nextAdvertise) > 0) {
    _advertise();
    _nextAdvertise = cur + advertiseInterval;
  }

  if (_receivedPacket) {
    if (tracePackets) {
      Serial.print("Processing received packet\n");
    }
    switch (_receivedPacketType) {
      case PKT_TYPE::ADVERTISE:
        _receiveAdvertise(_receivedSrc, _receivedBody);
        break;
      case PKT_TYPE::REQ:
        _receiveReq(_receivedSrc, _receivedBody);
        break;
      case PKT_TYPE::REPLY:
        _receiveReply(_receivedSrc, _receivedBody);
        break;
      default:
        if (tracePackets) {
          Serial.printf("Unknown packet type %d\n", int(_receivedPacketType));
        }
        break;
    }
    _receivedPacket = false;
  } else if (_update && int32_t(cur - _nextReceiveTimeout) > 0) {
    _receiveTimeout();
  }
}

void LazyMeshOta::_advertise() {
  if (tracePackets) {
    Serial.println("Advertising local version " + String(_localVersion) +
                   " md5=" + _localSketchMd5);
  }
  _transmit(PKT_TYPE::ADVERTISE, ethBroadcast, ethBroadcast /* bssid */,
            _localSketchName + "\n" + String(_localVersion) + "\n" + String(_localSketchSize) +
                "\n" + _localSketchMd5 + "\n" + ethToString(_getLocalBssid()) + "\n");
}

void LazyMeshOta::_transmit(PKT_TYPE pkt_type, eth_addr dest, eth_addr bssid, String msg) {
  uint32_t tot_len = sizeof(hdr_t) + msg.length();
  uint8_t buf[tot_len];
  hdr_t hdr;

  hdr.duration = 0;
  hdr.src = _localEthAddr;
  hdr.dest = dest;
  hdr.bssid = bssid;
  hdr.packetType = pkt_type;
  static uint16_t curSeq = 0;
  hdr.seq = ++curSeq;
  hdr.len = msg.length();

  memcpy(buf, &hdr, sizeof(hdr));
  memcpy(buf + sizeof(hdr), msg.c_str(), msg.length());

  int freedom_result = wifi_send_pkt_freedom(buf, tot_len, true);

  if (tracePackets) {
    Serial.print("SENT packet with result " + String(freedom_result) + " errno " + String(errno) +
                 ":\n");
    _tracePacket(buf, tot_len, 0 /* 802.11 header starts at 0 */);
  }
}

void LazyMeshOta::onReceiveRawFrameCallback(RxPacket* pkt) {
  assert(_instance);
  _instance->onReceiveRawFrame(pkt);
}

void LazyMeshOta::onReceiveRawFrame(RxPacket* pkt) {
  uint8_t* frm = pkt->data;
  uint16_t len = pkt->rx_ctl.legacy_length;
  if (tracePackets) {
    Serial.printf(".%d", len);
  }
  // Quick check to filter out any bssids that don't pertain to LazyMeshOta.
  if (len < sizeof(hdr_t)) {
    // Packet too short.
    return;
  }
  hdr_t* hdr = reinterpret_cast<hdr_t*>(frm);
  if (hdr->dsap != hdr_t().dsap) {
    // Different protocol than ours; skip.
    if (tracePackets) {
      Serial.printf("dsap(%02x)", hdr->dsap);
    }
    return;
  }
  if (memcmp(&hdr->dest, &_localEthAddr, sizeof(_localEthAddr)) != 0 &&
      memcmp(&hdr->dest, &ethBroadcast, sizeof(ethBroadcast))) {
    // Not to us.
    if (tracePackets) {
      Serial.println("Received packet to wrong target " + ethToString(hdr->dest));
    }
    return;
  }

  _receive(frm, len);
}

eth_addr LazyMeshOta::_getLocalBssid() {
  eth_addr bssid;
  station_config sc;
  wifi_station_get_config(&sc);
  memcpy(&bssid, sc.bssid, sizeof(bssid));
  return bssid;
}

void LazyMeshOta::_receive(uint8_t* frm, uint16_t tot_len) {
  hdr_t* hdr = reinterpret_cast<hdr_t*>(frm);
  if (hdr->dsap != hdr_t().dsap) {
    if (tracePackets) {
      Serial.printf("dsap(%02x)", hdr->dsap);
    }
    return;
  }

  if (memcmp(&hdr->src, &_localEthAddr, sizeof(_localEthAddr)) == 0) {
    // We sent this packet
    if (tracePackets) {
      Serial.print("Received a packet we sent\n");
    }
  }

  if (tracePackets) {
    Serial.printf("\nReceived packet:\n");
    _tracePacket(frm, tot_len, 0);
  }

  if (_receivedPacket) {
    if (tracePackets) {
      Serial.printf("Already waiting on packet to process; discarding\n");
    }
    return;
  }

  if (tot_len <= sizeof(hdr_t)) {
    if (tracePackets) {
      Serial.printf("Packet too short; tot_len %d <= %d\n", tot_len, sizeof(hdr_t));
    }
    return;
  }
  if (hdr->ssap != hdr_t().ssap) {
    if (tracePackets) {
      Serial.printf("Wrong ssap %02x\n", hdr->ssap);
    }
    return;
  }
  uint16_t pdu_len = tot_len - sizeof(hdr_t);

  // Don't need the whole header, so just copy out what we care about.
  uint16_t hdr_len;
  memcpy(&hdr_len, frm + offsetof(hdr_t, len), sizeof(hdr_len));

  if (hdr_len > pdu_len) {
    if (tracePackets) {
      Serial.printf("Packet length mismatch; packet has pdu length %d but says it has length %d\n",
                    pdu_len, hdr_len);
    }
    return;
  }

  memcpy(&_receivedPacketType, frm + offsetof(hdr_t, packetType), sizeof(_receivedPacketType));
  memcpy(&_receivedSrc, frm + offsetof(hdr_t, src), sizeof(_receivedSrc));
  _receivedBody.reset(frm + sizeof(hdr_t), hdr_len);
  if (tracePackets) {
    String ethstr = ethToString(_receivedSrc);
    Serial.printf("Got of type %d from %s len %u\n", int(_receivedPacketType), ethstr.c_str(),
                  _receivedBody.peekAvailable());
  }
  _receivedPacket = true;
}

void LazyMeshOta::_receiveAdvertise(const eth_addr& src, BufStream& body) {
  // <version>\n<sketchsize>\n<md5sum>\n
  if (tracePackets) {
    Serial.printf("Advertisement received '%s'\n", body.peekBuffer());
  }

  String sketchName = body.readStringUntil('\n');
  if (sketchName != _localSketchName) {
    if (tracePackets) {
      Serial.printf("Advertisement for sketch '%s', which is not our '%s'.\n", sketchName.c_str(),
                    _localSketchName.c_str());
    }
  }

  int version = body.parseInt();
  if (version <= _localVersion) {
    if (tracePackets) {
      Serial.printf("Advertisement for version %d is not new.\n", version);
    }
    return;
  }

  int nl = body.read();
  if (nl != '\n') {
    if (tracePackets) {
      Serial.printf("Missing newline after version, '%c'\n", nl);
    }
    return;
  }

  int sketchsize = body.parseInt();
  if (sketchsize <= 1) {
    if (tracePackets) {
      Serial.printf("Bad sketchsize %d\n", sketchsize);
    }
    return;
  }

  nl = body.read();
  if (nl != '\n') {
    if (tracePackets) {
      Serial.printf("Missing newline after sketchsize\n");
    }
    return;
  }

  String md5 = body.readStringUntil('\n');
  if (md5.length() != 32) {
    if (tracePackets) {
      Serial.printf("md5sum '%s' should be exactly 32 chars long\n", md5.c_str());
    }
    return;
  }

  String bssidStr = body.readStringUntil('\n');
  eth_addr bssid;
  if (!ethFromString(&bssid, bssidStr)) {
    if (tracePackets) {
      Serial.println("Unable to process bssid '" + bssidStr + "'");
    }
    return;
  }

  _startUpdate(src, bssid, version, sketchsize, md5);
}

void LazyMeshOta::_startUpdate(const eth_addr& src, const eth_addr& bssid, int version,
                               uint32_t sketchsize, String md5sum) {
  if (tracePackets) {
    Serial.println("Starting update? src=" + ethToString(src) + " bssid=" + ethToString(bssid));
  }
  if (_update && _update->version < version) {
    if (tracePackets) {
      Serial.println("Aborting previous update!");
    }
    Update.end();
    delete _update;
    _update = nullptr;
  }

  if (_update) {
    if (tracePackets) {
      Serial.println("Except not, since there's an update already in progress.");
    }
    // Update already in progress.
    return;
  }

  _update = new update_t;
  _update->version = version;
  _update->src = src;
  _update->size = sketchsize;
  _update->bssid = bssid;

  Update.setMD5(md5sum.c_str());
  Update.begin(sketchsize);

  _requestNextBlock();
}

void LazyMeshOta::_requestNextBlock() {
  assert(_update);

  if (tracePackets) {
    Serial.printf("Requesting next block at %u/%u\n", _update->offset, _update->size);
  }

  if (_update->offset == _update->size) {
    // Update complete!
    if (!Update.end()) {
      Serial.println("Update error:");
      Update.printError(Serial);
    }

    _updateSucceeded = true;

    delete _update;
    _update = nullptr;
    return;
  }

  _transmit(PKT_TYPE::REQ, _update->src, _update->bssid,
            ethToString(_getLocalBssid()) + "\n" + String(_update->offset) + "\n");
  _nextReceiveTimeout = millis() + receiveTimeoutInterval;
}

void LazyMeshOta::_receiveTimeout() {
  assert(_update);

  ++_update->retryCount;
  if (_update->retryCount > maxRetries) {
    Update.end();
    delete _update;
    _update = nullptr;

    Serial.println("Update exceeded max retries");
    return;
  }

  if (tracePackets) {
    Serial.println("Resending due to timeout");
  }

  _requestNextBlock();
}

void LazyMeshOta::_receiveReq(const eth_addr& src, BufStream& body) {
  if (tracePackets) {
    Serial.printf("Request received '%s'\n", body.peekBuffer());
  }
  // "<src bssid>\n<start>\n".
  String bssidStr = body.readStringUntil('\n');
  eth_addr bssid;
  if (!ethFromString(&bssid, bssidStr)) {
    if (tracePackets) {
      Serial.println("Could not parse bssid " + bssidStr);
    }
    return;
  }

  uint32_t startOffset = body.parseInt();
  if (startOffset >= _localSketchSize) {
    if (tracePackets) {
      Serial.printf("Start offset %u larger than local sketch size %u\n", startOffset,
                    _localSketchSize);
    }
    return;
  }

  uint32_t len = bufferSize;
  if (startOffset + len > _localSketchSize) {
    len = _localSketchSize - startOffset;
  }

  if (tracePackets) {
    Serial.printf("Replying with %u bytes of flash, %u-%u/%u\n", len, startOffset,
                  startOffset + len, _localSketchSize);
  }

  String reply = String(startOffset) + "\n";
  uint8_t buf[len];
  if (!flashRead(startOffset, buf, len)) {
    if (tracePackets) {
      Serial.print("Reading from flash failed");
    }
    return;
  }

  if (!concatString(&reply, (char*)buf, len)) {
    if (tracePackets) {
      Serial.print("Unable to concat to reply!");
    }
    return;
  }
  _transmit(PKT_TYPE::REPLY, src, bssid, reply);
}

void LazyMeshOta::_receiveReply(const eth_addr& /* src */, BufStream& body) {
  if (tracePackets) {
    Serial.printf("Reply received '%s'\n", body.peekBuffer());
  }
  if (!_update) {
    if (tracePackets) {
      Serial.print("No update in progress!\n");
    }
    return;
  }

  uint32_t startOffset = body.parseInt();
  if (startOffset != _update->offset) {
    if (tracePackets) {
      Serial.printf("Wrong start offset; received %u but we're at %u\n", startOffset,
                    _update->offset);
    }
    return;
  }

  int nl = body.read();
  if (nl != '\n') {
    if (tracePackets) {
      Serial.printf("Missing newline after received replyoffset\n");
    }
    return;
  }

  uint32_t size = body.peekAvailable();
  if (size + startOffset > _update->size) {
    if (tracePackets) {
      Serial.printf("Size %u + startoffset %u too big for sketch size %u\n", size, startOffset,
                    _update->size);
    }
    return;
  }

  uint32_t writelen = Update.write((uint8_t*)body.peekBuffer(), size);
  if (writelen != size) {
    if (tracePackets) {
      Serial.printf("Tried to write %u to updater, but only got %u\n", size, writelen);
    }
    return;
  }

  if (tracePackets) {
    Serial.printf("Sent %u bytes to updater at offset %u\n", writelen, startOffset);
  }
  _update->offset += writelen;
  _requestNextBlock();
}

/*
LazyMeshOta::receiveRawCallback(uint8_t* frm, int16_t len) {

// Size and md5:
ESP.getSketchSize()
ESP.getSketchMd5()

// Flash start in RAM, per https://github.com/esp8266/esp8266-wiki/wiki/Memory-Map:

0x40200000h

// Start of first sketch:
#include <spi_flash_geometry.h>
APP_START_OFFSET

*/
