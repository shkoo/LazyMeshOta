#include <LazyMeshOta.h>
#include <ESP8266WiFi.h>

constexpr int version = 3;

String sketchName = "VersionBlink";

LazyMeshOta lmo;

void setup() {
  delay(300);
  Serial.begin(115200);
  Serial.printf("Version %d starting\n", version);
  WiFi.mode(WIFI_STA);
  lmo.begin(sketchName, version);
  lmo.register_wifi_cb();
  pinMode(LED_BUILTIN, OUTPUT);
  
  Serial.print("WiFi configured\n");
}

void loop() {
  delay(3000);
  for (int i = 0; i < version; ++i) {
    Serial.printf("We are running version %d\n", version);
    delay(300);
    digitalWrite(LED_BUILTIN, HIGH);
    delay(300);
    digitalWrite(LED_BUILTIN, LOW);
  }  
}
