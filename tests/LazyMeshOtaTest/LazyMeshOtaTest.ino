#if defined(EPOXY_DUINO)
#include <AUnitVerbose.h>
#else
#include <AUnit.h>
#endif

#include <Arduino.h>
#include <LazyMeshOta.h>

#include <iostream>

using namespace aunit;

eth_addr testBssid = {3, 1, 3, 3, 3, 7};

void wifi_raw_set_recv_cb(wifi_raw_recv_cb_fn /* rx_fn */) {
  assert(0 /* this should not be called */);
}

void runSome(LazyMeshOta& ota, FakeWifiContext& wifiCtx, FakeUpdateContext& updateCtx) {
  wifiCtx.enable();
  updateCtx.enable();
  if (FakeWifiContext::rawWifiPacket) {
    RxPacket* pkt = FakeWifiContext::rawWifiPacket;
    FakeWifiContext::rawWifiPacket = nullptr;
    ota.onReceiveRawFrame(pkt);
  }
  ota.loop();
}

test(simpleTest) {
  FakeUpdateContext update1("sketch1", 12345);
  LazyMeshOta lmo;
  lmo.begin("LazyMeshOtaTest", 1);
  lmo.end();
}

test(noTransferTest) {
  FakeWifiContext wifi1({1, 2, 3, 4, 5, 6}, testBssid);
  FakeUpdateContext update1("sketch1", 12345);
  LazyMeshOta lmo1;
  lmo1.begin("noTransferTest", 1);

  FakeWifiContext wifi2({7, 8, 9, 10, 11, 12}, testBssid);
  FakeUpdateContext update2("sketch1", 789101);
  LazyMeshOta lmo2;
  lmo2.begin("noTransferTest", 1);

  uint32_t start = millis();
  for (;;) {
    uint32_t cur = millis();
    uint32_t elapsed = cur - start;

    if (elapsed > 5000) {
      break;
    }

    runSome(lmo1, wifi1, update1);
    runSome(lmo2, wifi2, update2);

    delay(10);
  }
  assertFalse(update1.didBegin);
  assertFalse(update1.didUpdate);
  assertFalse(update1.didRestart);
  assertFalse(update2.didBegin);
  assertFalse(update2.didUpdate);
  assertFalse(update2.didRestart);
}

test(transferTest) {
  FakeWifiContext wifi1({1, 2, 3, 4, 5, 6}, testBssid);
  FakeUpdateContext update1("sketch1", 12345);
  LazyMeshOta lmo1;
  lmo1.begin("transferTest", 2);

  FakeWifiContext wifi2({7, 8, 9, 10, 11, 12}, testBssid);
  FakeUpdateContext update2("sketch1", 789101);
  LazyMeshOta lmo2;
  lmo2.begin("transferTest", 1);

  uint32_t start = millis();
  for (;;) {
    uint32_t cur = millis();
    uint32_t elapsed = cur - start;

    if (elapsed > 5000 || update2.didUpdate) {
      break;
    }

    runSome(lmo1, wifi1, update1);
    runSome(lmo2, wifi2, update2);

    delay(10);
  }
  assertFalse(update1.didBegin);
  assertFalse(update1.didUpdate);
  assertFalse(update1.didRestart);
  assertTrue(update2.didBegin);
  assertTrue(update2.didUpdate);
  assertTrue(update2.didRestart);
}

test(retryTest) {
  FakeWifiContext wifi1({1, 2, 3, 4, 5, 6}, testBssid);
  FakeUpdateContext update1("sketch1datadatadata", 12345);
  LazyMeshOta lmo1;
  lmo1.begin("transferTest", 2);

  FakeWifiContext wifi2({7, 8, 9, 10, 11, 12}, testBssid);
  FakeUpdateContext update2("sketch2datadatadata", 789101);
  LazyMeshOta lmo2;
  lmo2.begin("transferTest", 1);

  uint32_t start = millis();
  size_t pktCount = 0;
  for (;;) {
    uint32_t cur = millis();
    uint32_t elapsed = cur - start;

    if (elapsed > 5000 || update2.didUpdate) {
      break;
    }

    runSome(lmo1, wifi1, update1);
    if (FakeWifiContext::rawWifiPacket) {
      if ((pktCount % 2) == 1) {
        FakeWifiContext::discardRawWifiPacket();
      }
      ++pktCount;
    }

    runSome(lmo2, wifi2, update2);

    delay(10);
  }
  assertFalse(update1.didBegin);
  assertFalse(update1.didUpdate);
  assertFalse(update1.didRestart);
  assertTrue(update2.didBegin);
  assertTrue(update2.didUpdate);
  assertTrue(update2.didRestart);
}

void setup() {
#if !defined(EPOXY_DUINO)
  delay(1000);  // wait to prevent garbage on SERIAL_PORT_MONITOR
#endif
  SERIAL_PORT_MONITOR.begin(115200);
  while (!SERIAL_PORT_MONITOR)
    ;  // needed for Leonardo/Micro
}

void loop() { TestRunner::run(); }
