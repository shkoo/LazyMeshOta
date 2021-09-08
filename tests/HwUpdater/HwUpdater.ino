#include <ESP8266WiFi.h>
#include <LazyMeshOta.h>

String sketchName = "HwUpdaterTest";

LazyMeshOta lmo;
static int version = 0;

void setup() {
  delay(5000);
  Serial.begin(115200);
  for (int trynum = 0; trynum < 20 && !version; ++trynum) {
    Serial.println("Enter version number");
    version = Serial.parseInt();
  }
  version = random(1,3);
  Serial.printf("Version %d starting\n", version);
  WiFi.mode(WIFI_STA);
  lmo.begin(sketchName, version);
  lmo.register_wifi_cb();
  pinMode(LED_BUILTIN, OUTPUT);

  Serial.print("WiFi configured!\n");
}

void loop() {
  static int x= 0;
  if (x == 5) {
    Serial.printf("We are running version %d with %d, %d free memory\n", version,
                  ESP.getFreeHeap(), ESP.getFreeContStack());
  }
  x++;
  delay(100);
  if (x == 100) {
    x = 0;
  }
}
