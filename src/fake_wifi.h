#ifndef FAKE_WIFI_H
#define FAKE_WIFI_H

#include <Arduino.h>
#include <assert.h>

// from lwip
struct eth_addr {
  uint8_t addr[6];
};

#define WL_MAC_ADDR_LENGTH 6

// raw wifi stubs
struct RxControl {
  int8_t rssi;
  unsigned legacy_length : 12;
};

struct RxPacket {
  RxControl rx_ctl;
  uint8_t data[];
};

typedef void (*wifi_raw_recv_cb_fn)(struct RxPacket*);

extern void wifi_raw_set_recv_cb(wifi_raw_recv_cb_fn rx_fn);

// esp8266 core stubs
struct FakeWifiContext {
 public:
  FakeWifiContext(eth_addr macaddrArg, eth_addr bssidArg) : macaddr(macaddrArg), bssid(bssidArg) {
    enable();
  }

  void enable() { curContext = this; }

  static void discardRawWifiPacket() {
    if (rawWifiPacket) {
      free(rawWifiPacket);
      rawWifiPacket = nullptr;
    }
  }

  eth_addr macaddr;
  eth_addr bssid;

  // Current context being processed
  static FakeWifiContext* curContext;
  // packet shared by all contexts.
  static RxPacket* rawWifiPacket;
};

static inline bool wifi_get_macaddr(uint8_t /* if_index */, uint8_t* macaddr) {
  assert(FakeWifiContext::curContext);
  memcpy(macaddr, &FakeWifiContext::curContext->macaddr, 6);
  return true;
}
static inline int wifi_send_pkt_freedom(uint8_t* buf, int len, bool /* sys_seq */) {
  auto& rawWifiPacket = FakeWifiContext::rawWifiPacket;

  FakeWifiContext::discardRawWifiPacket();
  rawWifiPacket = (RxPacket*)malloc(sizeof(RxControl) + len);
  memcpy(rawWifiPacket->data, buf, len);
  rawWifiPacket->rx_ctl.rssi = 1;
  rawWifiPacket->rx_ctl.legacy_length = len;
  return len;
}

struct station_config {
  uint8_t bssid[6];
};

static inline void wifi_station_get_config(station_config* sc) {
  assert(FakeWifiContext::curContext);
  memcpy(sc->bssid, &FakeWifiContext::curContext->bssid, sizeof(sc->bssid));
}

// No need for interrupt stuff to be in the IRAM when testing.
#define IRAM_ATTR

#endif
