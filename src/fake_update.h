#ifndef FAKE_UPDATE_H
#define FAKE_UPDATE_H

#include <Arduino.h>
#include <assert.h>
#include <openssl/md5.h>
#include <stdio.h>

#include <string>

class FakeUpdateContext {
 public:
  FakeUpdateContext(const std::string &localSketchData, uint32_t chipId)
      : _localSketchData(localSketchData), _chipId(chipId) {
    enable();
  }

  void enable() { curContext = this; }

  // Set to true if an update was successful.
  bool didUpdate = false;
  bool didBegin = false;
  bool didRestart = false;

  bool begin(size_t size) {
    assert(!_inProgress);
    _expected_size = size;
    _size = 0;
    _curError = String();
    _inProgress = true;
    MD5_Init(&_md5);
    didBegin = true;
    return true;
  }
  bool setMD5(const char *expected_md5) {
    _expected_md5 = expected_md5;
    return true;
  }
  void printError(Print &out) { out.print(_curError); }
  size_t write(uint8_t *data, size_t len) {
    MD5_Update(&_md5, data, len);
    _size += len;
    return len;
  }
  bool end() {
    if (!_inProgress) {
      _curError = "Not in progress";
      return false;
    }
    _inProgress = false;
    if (_size != _expected_size) {
      _curError =
          "Wrong expected size; got " + String(_size) + " but expected " + String(_expected_size);
      return false;
    }
    uint8_t md5Result[MD5_DIGEST_LENGTH];
    MD5_Final(md5Result, &_md5);
    String md5Str = md5ToString(md5Result);
    if (md5Str != _expected_md5) {
      _curError = "Expected md5 " + _expected_md5 + " but got " + md5Str;
      return false;
    }
    didUpdate = true;
    return true;
  }

  String md5ToString(uint8_t *md5Result) {
    char md5Str[2 * MD5_DIGEST_LENGTH + 1];
    for (size_t i = 0; i != MD5_DIGEST_LENGTH; ++i) {
      sprintf(&md5Str[i * 2], "%02x", md5Result[i]);
    }
    return md5Str;
  }

  // Fakes for reading existing local flash
  inline uint32_t getLocalSketchSize() {
    assert(FakeUpdateContext::curContext);
    return _localSketchData.size();
  }
  String getLocalSketchMD5() {
    assert(FakeUpdateContext::curContext);
    uint8_t result[MD5_DIGEST_LENGTH];
    MD5((const uint8_t *)_localSketchData.data(), _localSketchData.size(), result);
    return md5ToString(result);
  }
  bool localFlashRead(uint32_t address, uint8_t *data, size_t size) {
    assert(FakeUpdateContext::curContext);
    if (address + size > _localSketchData.size()) {
      return false;
    }

    memcpy(data, _localSketchData.data() + address, size);
    return true;
  }
  uint32_t getLocalChipId() { return _chipId; }

  void espRestart() { didRestart = true; }

  static FakeUpdateContext *curContext;

 private:
  MD5_CTX _md5;
  bool _inProgress = false;
  size_t _expected_size = 0;
  size_t _size = 0;
  String _expected_md5;
  String _curError;

  std::string _localSketchData;
  uint32_t _chipId;
};

class FakeUpdateForwarder {
 public:
  static FakeUpdateContext *instance() { return FakeUpdateContext::curContext; }
  bool begin(size_t size) { return instance()->begin(size); }
  bool setMD5(const char *expected_md5) { return instance()->setMD5(expected_md5); }
  void printError(Print &out) { instance()->printError(out); }
  size_t write(uint8_t *data, size_t len) { return instance()->write(data, len); }
  bool end() { return instance()->end(); }
  void runAsync(bool) {}
};

extern FakeUpdateForwarder Update;

// stand-ins for ESP
static inline uint32_t getSketchSize() {
  assert(FakeUpdateContext::curContext);
  return FakeUpdateContext::curContext->getLocalSketchSize();
}
static inline String getSketchMD5() {
  assert(FakeUpdateContext::curContext);
  return FakeUpdateContext::curContext->getLocalSketchMD5();
}
static inline bool flashRead(uint32_t address, uint8_t *data, size_t size) {
  assert(FakeUpdateContext::curContext);
  return FakeUpdateContext::curContext->localFlashRead(address, data, size);
}
static inline uint32_t getChipId() {
  assert(FakeUpdateContext::curContext);
  return FakeUpdateContext::curContext->getLocalChipId();
}
static inline void espRestart() {
  assert(FakeUpdateContext::curContext);
  return FakeUpdateContext::curContext->espRestart();
}

#endif
