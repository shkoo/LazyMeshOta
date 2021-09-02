#if defined(EPOXY_DUINO)

#include "fake_wifi.h"

FakeWifiContext* FakeWifiContext::curContext = nullptr;
RxPacket* FakeWifiContext::rawWifiPacket = nullptr;

#endif
