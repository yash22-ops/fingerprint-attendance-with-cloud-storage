// Enforce: only 2 scans/day per user (in_time, out_time)
// ESP32 + AS608/ZA620_M5 (Adafruit_Fingerprint) + SPI SSD1306 + Firebase REST (DB Secret)
// Admin commands via Serial: e (enroll), d (delete), l (list users), wipe (erase all templates)

#include <WiFi.h>
#include <HTTPClient.h>
#include <SPI.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <Adafruit_Fingerprint.h>
#include <WiFiUdp.h>
#include <NTPClient.h>
#include "esp_log.h"

// ---------------- CONFIG ----------------
const char* WIFI_SSID = "samsung";
const char* WIFI_PASS = "12345678";

const char* FIREBASE_DB_URL = "https://fingerprint-759af-default-rtdb.asia-southeast1.firebasedatabase.app/";
const char* FIREBASE_DB_SECRET = "Ibd8xrbcXN5058UbCKCs6Z7WwZx7OVunTiknkatg";

// ---------------- HARDWARE PINS ----------------
#define FINGER_RX_PIN 16  // sensor TX -> ESP32 RX2
#define FINGER_TX_PIN 17  // sensor RX -> ESP32 TX2

#define OLED_SCK  18 // D0
#define OLED_MOSI 23 // D1
#define OLED_DC   2
#define OLED_CS   5
#define OLED_RST  4

// ---------------- OBJECTS ----------------
HardwareSerial FingerSerial(2);
Adafruit_Fingerprint finger(&FingerSerial);

#define SCREEN_W 128
#define SCREEN_H 64
Adafruit_SSD1306 display(SCREEN_W, SCREEN_H, &SPI, OLED_DC, OLED_RST, OLED_CS);

// NTP (IST offset)
WiFiUDP ntpUDP;
NTPClient timeClient(ntpUDP, "pool.ntp.org", 19800, 60000);

// debounce
unsigned long lastLogTime = 0;
int lastLoggedID = -1;
const unsigned long DUP_BLOCK_MS = 7000UL;

// ---------------- helper: silence noisy logs ----------------
void silenceEspLogs() {
  esp_log_level_set("*", ESP_LOG_ERROR);
}

// ---------------- OLED helper ----------------
void oledShow(const String &l1, const String &l2 = "", uint8_t s1 = 2, uint8_t s2 = 1) {
  display.clearDisplay();
  display.setTextSize(s1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.println(l1);
  if (l2.length()) {
    display.setTextSize(s2);
    display.setCursor(0, 28);
    display.println(l2);
  }
  display.display();
}

// ---------------- time helpers ----------------
String getDateStr() {
  timeClient.update();
  time_t raw = timeClient.getEpochTime();
  struct tm *t = localtime(&raw);
  char buf[12];
  sprintf(buf, "%04d-%02d-%02d", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);
  return String(buf);
}
String getTimeStr() {
  timeClient.update();
  time_t raw = timeClient.getEpochTime();
  struct tm *t = localtime(&raw);
  char buf[12];
  sprintf(buf, "%02d:%02d:%02d", t->tm_hour, t->tm_min, t->tm_sec);
  return String(buf);
}

// ---------------- firebase REST helpers ----------------
String buildUrl(const String &path) {
  String base = FIREBASE_DB_URL;
  if (!base.endsWith("/")) base += "/";
  String p = path;
  if (p.startsWith("/")) p = p.substring(1);
  return base + p + ".json?auth=" + FIREBASE_DB_SECRET;
}

String firebaseGet(const String &path) {
  HTTPClient http;
  String url = buildUrl(path);
  http.begin(url);
  int code = http.GET();
  String r = "";
  if (code > 0) r = http.getString();
  http.end();
  return r;
}

bool firebasePatch(const String &path, const String &json, String &resp) {
  HTTPClient http;
  String url = buildUrl(path);
  http.begin(url);
  http.addHeader("Content-Type", "application/json");
  int code = http.sendRequest("PATCH", (uint8_t*)json.c_str(), json.length());
  if (code > 0) resp = http.getString();
  http.end();
  return (code == 200 || code == 201 || code == 204);
}

bool firebasePut(const String &path, const String &json, String &resp) {
  HTTPClient http;
  String url = buildUrl(path);
  http.begin(url);
  http.addHeader("Content-Type", "application/json");
  int code = http.PUT(json);
  if (code > 0) resp = http.getString();
  http.end();
  return (code == 200 || code == 201 || code == 204);
}

bool firebaseDelete(const String &path) {
  HTTPClient http;
  String url = buildUrl(path);
  http.begin(url);
  int code = http.sendRequest("DELETE");
  http.end();
  return (code == 200 || code == 204);
}

String stripQuotes(const String &s) {
  if (s.length() >= 2 && s[0] == '"' && s[s.length()-1] == '"') return s.substring(1, s.length()-1);
  return s;
}

// ---------------- fingerprint helpers ----------------
String fpStatusToText(int code) {
  switch (code) {
    case FINGERPRINT_OK: return "OK";
    case FINGERPRINT_NOFINGER: return "NOFINGER";
    case FINGERPRINT_PACKETRECIEVEERR: return "PACKETRECIEVEERR";
    case FINGERPRINT_IMAGEFAIL: return "IMAGEFAIL";
    case FINGERPRINT_IMAGEMESS: return "IMAGEMESS";
    case FINGERPRINT_FEATUREFAIL: return "FEATUREFAIL";
    case FINGERPRINT_NOMATCH: return "NOMATCH";
    case FINGERPRINT_NOTFOUND: return "NOTFOUND";
    case FINGERPRINT_ENROLLMISMATCH: return "ENROLLMISMATCH";
    case FINGERPRINT_BADLOCATION: return "BADLOCATION";
    case FINGERPRINT_DBRANGEFAIL: return "DBRANGEFAIL";
    case FINGERPRINT_UPLOADFAIL: return "UPLOADFAIL";
    case FINGERPRINT_DELETEFAIL: return "DELETEFAIL";
    default: return "UNKNOWN";
  }
}

bool initFingerprint() {
  FingerSerial.begin(57600, SERIAL_8N1, FINGER_RX_PIN, FINGER_TX_PIN);
  delay(50);
  finger.begin(57600);
  for (int i = 0; i < 3; ++i) {
    if (finger.verifyPassword()) return true;
    delay(200);
  }
  return false;
}

// safe image2Tz: suppress error prints to stop spam
bool safeImageToTz(uint8_t slot) {
  int r = finger.image2Tz(slot);
  return (r == FINGERPRINT_OK);
}

// scanFinger returns:
//  -1 = no finger detected in window
//   0 = finger detected but not matched (not enrolled)
//  >0 = matched template id
int scanFinger(unsigned long timeoutMs) {
  unsigned long start = millis();
  while (millis() - start < timeoutMs) {
    int p = finger.getImage();
    if (p == FINGERPRINT_OK) {
      // We have an image. Convert silently.
      if (!safeImageToTz(1)) {
        // conversion failed (poor image) => treat as "not matched" (0)
        return 0;
      }
      int r = finger.fingerFastSearch();
      if (r == FINGERPRINT_OK) {
        return finger.fingerID; // matched
      } else {
        // image OK but no match
        return 0;
      }
    }
    // no finger or transient errors -> continue quietly
    delay(25);
  }
  // timeout w/o finger
  return -1;
}

// Enroll and store in flash permanently
bool enrollFingerprint(uint16_t id) {
  oledShow("Enroll", "Place (1)", 1, 1);
  unsigned long start = millis();
  while (millis() - start < 20000UL) {
    int p = finger.getImage();
    if (p == FINGERPRINT_OK) {
      if (!safeImageToTz(1)) { return false; }
      oledShow("Remove", "Then place (2)", 1, 1);
      delay(900);
      unsigned long start2 = millis();
      oledShow("Place (2)", "", 1, 1);
      while (millis() - start2 < 20000UL) {
        if (finger.getImage() == FINGERPRINT_OK) {
          if (!safeImageToTz(2)) return false;
          int r = finger.createModel();
          if (r != FINGERPRINT_OK) return false;
          r = finger.storeModel(id);
          if (r != FINGERPRINT_OK) return false;
          return true;
        }
        delay(100);
      }
      return false;
    }
    delay(120);
  }
  return false;
}

bool deleteTemplate(uint16_t id) {
  int r = finger.deleteModel(id);
  return (r == FINGERPRINT_OK);
}

// ---------------- admin serial handler ----------------
String readSerialLine(unsigned long timeoutMs=10000) {
  unsigned long start = millis();
  String s="";
  while (millis() - start < timeoutMs) {
    while (Serial.available()) {
      char c = Serial.read();
      if (c == '\r') continue;
      if (c == '\n') { s.trim(); return s; }
      s += c;
    }
    delay(5);
  }
  s.trim();
  return s;
}

void handleAdmin() {
  if (!Serial) return;
  if (!Serial.available()) return;
  String cmd = Serial.readStringUntil('\n');
  cmd.trim();
  if (cmd.length() == 0) return;

  if (cmd == "e") {
    Serial.println("Enroll - enter numeric ID:");
    String sid = readSerialLine(15000);
    if (sid == "") { Serial.println("Canceled"); return; }
    int id = sid.toInt();
    if (id <= 0) { Serial.println("Invalid ID"); return; }
    Serial.println("Enter name:");
    String name = readSerialLine(15000);
    if (name == "") name = "User" + String(id);
    oledShow("Enroll", "Place finger", 1, 1);
    if (enrollFingerprint(id)) {
      Serial.println("Enroll OK");
      oledShow("Enroll OK", "ID:" + String(id), 1, 1);
      // Save name to /users/<id>/name
      String payload = "\"" + name + "\"";
      String resp;
      firebasePut("users/" + String(id) + "/name", payload, resp);
    } else {
      Serial.println("Enroll failed");
      oledShow("Enroll Failed", "", 1, 1);
    }
  }
  else if (cmd == "d") {
    Serial.println("Delete - Enter numeric ID:");
    String sid = readSerialLine(10000);
    if (sid == "") { Serial.println("Canceled"); return; }
    int id = sid.toInt();
    if (id <= 0) { Serial.println("Invalid ID"); return; }
    if (deleteTemplate(id)) {
      Serial.println("Deleted template");
      oledShow("Delete OK", "ID:" + String(id), 1, 1);
      firebaseDelete("users/" + String(id));
    } else {
      Serial.println("Delete failed");
      oledShow("Delete Failed", "", 1, 1);
    }
  }
  else if (cmd == "l") {
    Serial.println("Listing /users ...");
    String r = firebaseGet("users");
    if (r.length()) Serial.println(r);
    else Serial.println("Failed to list users");
  }
  else if (cmd == "wipe") {
    Serial.println("Wiping ALL fingerprint templates (1..200) ...");
    oledShow("Wiping Sensor", "Please wait...", 1, 1);
    for (int i = 1; i <= 200; i++) {
      finger.deleteModel(i);
      delay(10);
    }
    Serial.println("Wipe Complete.");
    oledShow("Sensor Wiped", "", 1, 1);
  }
  else {
    Serial.println("Unknown command. Allowed: e d l wipe");
  }
}

// ---------------- attendance log (username-based, 2-scans/day) ----------------
void logAttendanceByUsername(int id) {
  // Get username from /users/<id>/name
  String raw = firebaseGet("users/" + String(id) + "/name");
  String uname = stripQuotes(raw);

  if (uname.length() == 0 || uname == "null") {
    // Show Place Finger To Scan (instead of unauthorized)
    oledShow("Place Finger", "To Scan", 1, 1);
    delay(1000);
    return;
  }

  String date = getDateStr();
  String timeS = getTimeStr();

  // attendance / YYYY-MM-DD / username
  String path = "attendance/" + date + "/" + uname;

  // read existing (will be "null" if not present)
  String current = firebaseGet(path);

  bool hasIn = (current.indexOf("\"in_time\"") >= 0);
  bool hasOut = (current.indexOf("\"out_time\"") >= 0);

  if (!hasIn) {
    // first scan -> IN
    String payload = "{\"in_time\":\"" + timeS + "\"}";
    String resp;
    if (firebasePatch(path, payload, resp)) {
      Serial.printf("Logged IN %s at %s\n", uname.c_str(), timeS.c_str());
      oledShow(uname, "Checked IN", 1, 1);
    } else {
      Serial.println("Firebase IN failed");
      oledShow("Firebase Err", "", 1, 1);
    }
  } else if (hasIn && !hasOut) {
    // second scan -> OUT
    String payload = "{\"out_time\":\"" + timeS + "\"}";
    String resp;
    if (firebasePatch(path, payload, resp)) {
      Serial.printf("Logged OUT %s at %s\n", uname.c_str(), timeS.c_str());
      oledShow(uname, "Checked OUT", 1, 1);
    } else {
      Serial.println("Firebase OUT failed");
      oledShow("Firebase Err", "", 1, 1);
    }
  } else {
    // already has in and out
    Serial.printf("%s already marked IN & OUT today\n", uname.c_str());
    oledShow("Attendance", "Already Marked", 1, 1);
    delay(1200);
  }
}

// ---------------- idle UI ----------------
void showIdle() {
  static unsigned long last = 0;
  static int phase = 0;
  if (millis() - last < 800) return;
  last = millis();
  phase = (phase + 1) % 3;
  display.clearDisplay();
  display.setTextSize(1);
  display.setCursor(0, 0);
  display.println("Place Finger");
  display.setCursor(0, 14);
  display.println("To Scan");
  display.drawCircle(110, 30, 6 + phase*2, SSD1306_WHITE);
  display.display();
}

// ---------------- wifi ----------------
void wifiConnect() {
  oledShow("WiFi", "Connecting...", 1, 1);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  unsigned long start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 15000UL) delay(200);
  if (WiFi.status() == WL_CONNECTED) oledShow("WiFi Connected", WiFi.localIP().toString(), 1, 1);
  else oledShow("WiFi Failed", "", 1, 1);
}

void wifiAutoReconnect() {
  static unsigned long lastTry = 0;
  if (WiFi.status() == WL_CONNECTED) return;
  if (millis() - lastTry < 5000UL) return;
  lastTry = millis();
  WiFi.disconnect();
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  unsigned long start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 8000UL) delay(200);
  if (WiFi.status() == WL_CONNECTED) oledShow("WiFi Reconnected", WiFi.localIP().toString(), 1, 1);
  else oledShow("WiFi Reconnect", "Failed", 1, 1);
}

// ---------------- setup & loop ----------------
void setup() {
  Serial.begin(115200);
  delay(50);

  silenceEspLogs();

  // OLED SPI init
  SPI.begin(OLED_SCK, -1, OLED_MOSI, OLED_CS);
  if (!display.begin(SSD1306_SWITCHCAPVCC)) {
    Serial.println("SSD1306 init failed");
    while (1);
  }
  display.clearDisplay();
  display.display();
  oledShow("System Booting", "", 2, 1);

  // fingerprint
  bool fpok = initFingerprint();
  if (fpok) {
    Serial.println("Fingerprint sensor OK");
    oledShow("Fingerprint OK", "", 1, 1);
  } else {
    Serial.println("Fingerprint sensor NOT found");
    oledShow("FP Not found", "", 1, 1);
  }

  // WiFi & NTP
  wifiConnect();
  timeClient.begin();
  timeClient.update();

  oledShow("Attendance Mode", "Ready", 1, 1);
  delay(800);
}

void loop() {
  wifiAutoReconnect();

  handleAdmin();

  int scan = scanFinger(800);

  if (scan == -1) {
    // no finger
    showIdle();
    delay(10);
    return;
  } else if (scan == 0) {
    // finger captured but not enrolled -> show Place Finger To Scan (per request)
    oledShow("Place Finger", "To Scan", 1, 1);
    delay(1200);
    return;
  }

  uint16_t id = (uint16_t)scan;

  if (lastLoggedID == id && millis() - lastLogTime < DUP_BLOCK_MS) {
    // duplicate; ignore quietly
    return;
  }

  lastLoggedID = id;
  lastLogTime = millis();

  logAttendanceByUsername(id);
}
