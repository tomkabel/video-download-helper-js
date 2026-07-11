/**
 * === VDH-SoTA Multi-Layer Media Interception Payload ===
 * Compatible with Chromium 120+, ECMAScript 2024
 * Inject via DevTools Console, Content Script (MAIN world), or puppeteer evaluateOnNewDocument
 *
 * Layers:
 *   A - HTTP Stream Sniffing (fetch/XHR + MediaSource)
 *   B - WebRTC SDP Interception
 *   C - WebSocket Binary Stream Monitoring
 *   D - EME/DRM Cryptographic Sniffer (Widevine L3 / ClearKey)
 *   E - Unified Data Logger
 *
 * All hooks are non-destructive: original behavior is strictly preserved.
 */

(function () {
  "use strict";

  if (window.__VDH_SOTA_INTERCEPTOR_ACTIVE__) {
    return;
  }
  window.__VDH_SOTA_INTERCEPTOR_ACTIVE__ = true;

  /* ------------------------------------------------------------------ */
  /*  UTILITY HELPERS                                                     */
  /* ------------------------------------------------------------------ */

  function bytesToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
      .map(function (b) {
        return b.toString(16).padStart(2, "0");
      })
      .join("");
  }

  function bytesToBase64(buffer) {
    var binary = "";
    var bytes = new Uint8Array(buffer);
    for (var i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function parsePsshBox(psshBytes) {
    if (psshBytes.byteLength < 32) {
      return { error: "PSSH too short: " + psshBytes.byteLength + " bytes" };
    }
    var view = new DataView(psshBytes.buffer || psshBytes);
    var boxSize = view.getUint32(0);
    var boxType = view.getUint32(4);
    if (boxType !== 0x70737368) {
      return { error: "Not a PSSH box: 0x" + boxType.toString(16) };
    }
    var version = view.getUint8(8);
    var flags = (view.getUint8(9) << 16) | (view.getUint8(10) << 8) | view.getUint8(11);
    var sysIdBytes = new Uint8Array(psshBytes.slice(12, 28));
    var sysIdParts = [];
    for (var si = 0; si < 16; si++) {
      sysIdParts.push(sysIdBytes[si].toString(16).padStart(2, "0"));
    }
    var sysId = sysIdParts.slice(0, 4).join("") + "-" + sysIdParts.slice(4, 6).join("") + "-" + sysIdParts.slice(6, 8).join("") + "-" + sysIdParts.slice(8, 10).join("") + "-" + sysIdParts.slice(10, 16).join("");

    var kids = [];
    var dataSize = 0;
    var dataOffset = 28;
    if (version === 1) {
      var kidCount = view.getUint32(28);
      dataOffset = 32;
      var kidLen = 16;
      for (var ki = 0; ki < kidCount && dataOffset + kidLen <= boxSize; ki++) {
        var kidHex = "";
        for (var kj = 0; kj < kidLen; kj++) {
          kidHex += view
            .getUint8(dataOffset + kj)
            .toString(16)
            .padStart(2, "0");
        }
        kids.push(kidHex);
        dataOffset += kidLen;
      }
      if (dataOffset + 4 <= boxSize) {
        dataSize = view.getUint32(dataOffset);
        dataOffset += 4;
      }
    } else {
      dataSize = boxSize - dataOffset;
    }
    var dataPayload = new Uint8Array(psshBytes.slice(dataOffset, dataOffset + dataSize));

    return {
      boxSize: boxSize,
      version: version,
      flags: flags,
      systemId: sysId,
      kids: kids,
      dataSize: dataSize,
      dataPayloadB64: bytesToBase64(dataPayload.buffer || dataPayload),
      dataPayloadHex: bytesToHex(dataPayload.buffer || dataPayload),
    };
  }

  function safeCall(fn, fallback) {
    try {
      return fn();
    } catch (e) {
      return typeof fallback !== "undefined" ? fallback : null;
    }
  }

  function makeTimestamp() {
    return new Date().toISOString();
  }

  /* ------------------------------------------------------------------ */
  /*  LAYER A: HTTP STREAM SNIFFING (fetch / XHR / MediaSource)          */
  /* ------------------------------------------------------------------ */

  var MEDIA_PATTERNS = [
    /\.m3u8($|\?)/i,
    /\.mpd($|\?)/i,
    /\.ts($|\?)/i,
    /\.m4s($|\?)/i,
    /\.m2ts($|\?)/i,
    /\.m4a($|\?)/i,
    /\.m4v($|\?)/i,
    /mpegurl/i,
    /dash\+xml/i,
    /\/api\/playlist\/master\//i,
    /\/dash\//i,
    /\/hls\//i,
    /\/video\/playlist\//i,
  ];

  function isMediaUrl(url) {
    if (typeof url !== "string" || url.length === 0) {
      return false;
    }
    for (var i = 0; i < MEDIA_PATTERNS.length; i++) {
      if (MEDIA_PATTERNS[i].test(url)) {
        return true;
      }
    }
    return false;
  }

  function logMediaUrl(protocol, url, method, requestHeaders) {
    var entry = {
      protocol: protocol,
      url: typeof url === "string" ? url : url.toString(),
      method: method || "GET",
      headers: requestHeaders || {},
      timestamp: makeTimestamp(),
    };
    window.__VDH_MEDIA_LOG__.push(entry);
    console.groupCollapsed(
      "%c[VDH-SoTA] %c" + protocol.toUpperCase() + "%c → " + (typeof url === "string" ? url.substring(0, 120) : url.toString().substring(0, 120)),
      "color: #fff; background: #1a73e8; padding: 1px 6px; border-radius: 3px; font-weight: bold;",
      "color: #1a73e8; font-weight: bold;",
      "color: inherit;",
    );
    console.log("URL:", entry.url);
    console.log("Method:", entry.method);
    console.log("Headers:", entry.headers);
    console.log("Timestamp:", entry.timestamp);
    console.groupEnd();
  }

  window.__VDH_MEDIA_LOG__ = [];

  /* --- A1: fetch interception --- */
  {
    var _nativeFetch = window.fetch;
    if (typeof _nativeFetch === "function") {
      window.fetch = function (input, init) {
        var url = typeof input === "string" ? input : input instanceof Request ? input.url : input && input.url ? input.url : "";
        var method = (init && init.method) || (input instanceof Request ? input.method : "GET");
        var headers = {};
        if (init && init.headers) {
          if (init.headers instanceof Headers) {
            init.headers.forEach(function (v, k) {
              headers[k] = v;
            });
          } else if (typeof init.headers === "object") {
            Object.assign(headers, init.headers);
          }
        }
        if (input instanceof Request) {
          input.headers.forEach(function (v, k) {
            if (!(k in headers)) {
              headers[k] = v;
            }
          });
        }
        if (isMediaUrl(url)) {
          var proto = url.match(/\.mpd/i) ? "mpd" : url.match(/\.m3u8/i) ? "m3u8" : "segment";
          logMediaUrl(proto, url, method, headers);
        }
        return _nativeFetch.call(this, input, init);
      };
    }
  }

  /* --- A2: XMLHttpRequest interception --- */
  {
    var _nativeOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (method, url, async, user, password) {
      if (isMediaUrl(url)) {
        var proto = url.match(/\.mpd/i) ? "mpd" : url.match(/\.m3u8/i) ? "m3u8" : "segment";
        var self = this;
        var reqUrl = url;
        logMediaUrl(proto, url, method);
        this.addEventListener("readystatechange", function () {
          if (self.readyState === 4 && self.status >= 200 && self.status < 300) {
            var ct = self.getResponseHeader("Content-Type") || "";
            if (ct.match(/mpegurl|dash\+xml|video\/|audio\//i)) {
              console.log("[VDH-SoTA] XHR Response:", {
                url: reqUrl,
                status: self.status,
                contentType: ct,
                responseSize: self.responseText ? self.responseText.length : self.response ? self.response.byteLength : 0,
              });
            }
          }
        });
      }
      return _nativeOpen.call(this, method, url, async, user, password);
    };
  }

  /* --- A3: MediaSource SourceBuffer hook for init segment detection --- */
  if (typeof MediaSource !== "undefined") {
    var _nativeAddSourceBuffer = MediaSource.prototype.addSourceBuffer;
    MediaSource.prototype.addSourceBuffer = function (mimeType) {
      var sb = _nativeAddSourceBuffer.call(this, mimeType);
      console.log("[VDH-SoTA] MediaSource.addSourceBuffer:", {
        mimeType: mimeType,
        sourceBuffers: this.sourceBuffers ? this.sourceBuffers.length + 1 : 1,
      });
      if (typeof SourceBuffer !== "undefined") {
        var _nativeAppendBuffer = sb.appendBuffer;
        sb.appendBuffer = function (data) {
          if (
            data instanceof ArrayBuffer &&
            data.byteLength < 8192 &&
            new Uint8Array(data, 4, 4).reduce(function (a, b) {
              return a + String.fromCharCode(b);
            }, "") === "ftyp"
          ) {
            console.log("[VDH-SoTA] SourceBuffer init segment detected:", {
              byteLength: data.byteLength,
              hexPreview: bytesToHex(data).substring(0, 64),
            });
          }
          return _nativeAppendBuffer.call(this, data);
        };
      }
      return sb;
    };
  }

  /* ------------------------------------------------------------------ */
  /*  LAYER B: WebRTC SDP INTERCEPTION                                  */
  /* ------------------------------------------------------------------ */

  if (typeof RTCPeerConnection !== "undefined") {
    var _nativeSetRemoteDescription = RTCPeerConnection.prototype.setRemoteDescription;
    RTCPeerConnection.prototype.setRemoteDescription = function (desc) {
      if (desc && desc.sdp) {
        var lines = desc.sdp.split("\r\n");
        var mediaLines = lines.filter(function (l) {
          return l.startsWith("m=");
        });
        var candidateLines = lines.filter(function (l) {
          return l.startsWith("a=candidate:");
        });
        var codecLines = lines.filter(function (l) {
          return l.startsWith("a=rtpmap:");
        });
        console.groupCollapsed("%c[VDH-SoTA] %cWebRTC %csetRemoteDescription", "color: #fff; background: #34a853; padding: 1px 6px; border-radius: 3px; font-weight: bold;", "color: #34a853;", "color: inherit;");
        console.log("Type:", desc.type);
        console.log("Media Lines:", mediaLines);
        console.log("Codecs:", codecLines);
        console.log("ICE Candidates:", candidateLines.length);
        console.groupEnd();
      }
      return _nativeSetRemoteDescription.call(this, desc);
    };

    var _nativeSetLocalDescription = RTCPeerConnection.prototype.setLocalDescription;
    RTCPeerConnection.prototype.setLocalDescription = function (desc) {
      if (desc && desc.sdp) {
        console.log("[VDH-SoTA] WebRTC setLocalDescription:", {
          type: desc.type,
          fingerprint: safeCall(function () {
            var fpMatch = desc.sdp.match(/a=fingerprint:(\S+)\s+(\S+)/);
            return fpMatch ? fpMatch[2] : "unknown";
          }, "unknown"),
          iceUfrag: safeCall(function () {
            var ufMatch = desc.sdp.match(/a=ice-ufrag:(\S+)/);
            return ufMatch ? ufMatch[1] : "unknown";
          }, "unknown"),
        });
      }
      return _nativeSetLocalDescription.call(this, desc);
    };
  }

  /* ------------------------------------------------------------------ */
  /*  LAYER C: WebSocket BINARY STREAM MONITORING                        */
  /* ------------------------------------------------------------------ */

  if (typeof WebSocket !== "undefined") {
    var _nativeWebSocket = WebSocket;
    var _wsRegistry = new WeakMap();
    var _wsIdCounter = 0;

    window.WebSocket = function (url, protocols) {
      var ws;
      if (protocols !== undefined) {
        ws = new _nativeWebSocket(url, protocols);
      } else {
        ws = new _nativeWebSocket(url);
      }
      var wsId = ++_wsIdCounter;
      _wsRegistry.set(ws, { id: wsId, url: url, bytesReceived: 0, messagesSinceStart: 0 });

      var _nativeAddEventListener = ws.addEventListener;
      ws.addEventListener = function (type, listener, options) {
        if (type === "message") {
          var wrappedListener = function (event) {
            var meta = _wsRegistry.get(ws);
            if (meta) {
              meta.messagesSinceStart++;
            }
            if (event.data instanceof ArrayBuffer) {
              meta.bytesReceived += event.data.byteLength;
              if (meta.messagesSinceStart <= 5 || meta.messagesSinceStart % 100 === 0) {
                console.log("[VDH-SoTA] WebSocket binary frame:", {
                  wsId: wsId,
                  url: meta.url,
                  msgNum: meta.messagesSinceStart,
                  frameSize: event.data.byteLength,
                  hexPreview: bytesToHex(event.data).substring(0, 64),
                  totalBytes: meta.bytesReceived,
                });
              }
            } else if (event.data instanceof Blob) {
              console.log("[VDH-SoTA] WebSocket blob frame:", {
                wsId: wsId,
                url: meta.url,
                msgNum: meta.messagesSinceStart,
                blobSize: event.data.size,
                blobType: event.data.type,
              });
            }
            return listener.call(this, event);
          };
          return _nativeAddEventListener.call(this, type, wrappedListener, options);
        }
        return _nativeAddEventListener.call(this, type, listener, options);
      };
      return ws;
    };
    Object.assign(window.WebSocket, _nativeWebSocket);
    window.WebSocket.prototype = _nativeWebSocket.prototype;
  }

  /* ------------------------------------------------------------------ */
  /*  LAYER D: EME / DRM CRYPTOGRAPHIC SNIFFER                           */
  /* ------------------------------------------------------------------ */

  function logEmeEvent(category, data) {
    console.groupCollapsed(
      "%c[VDH-SoTA] %cEME " + category.toUpperCase() + "%c — " + (data.keySystem || data.systemId || ""),
      "color: #fff; background: #ea4335; padding: 1px 6px; border-radius: 3px; font-weight: bold;",
      "color: #ea4335; font-weight: bold;",
      "color: inherit;",
    );
    Object.keys(data).forEach(function (k) {
      if (k === "rawInitData" || k === "rawLicenseResponse" || k === "rawLicenseRequest") {
        if (data[k] instanceof ArrayBuffer || data[k] instanceof Uint8Array) {
          console.log(k + " (hex):", bytesToHex(data[k]));
          console.log(k + " (b64):", bytesToBase64(data[k]));
        } else if (typeof data[k] === "string") {
          console.log(k + ":", data[k].substring(0, 200));
        } else {
          console.log(k + ":", data[k]);
        }
      } else {
        console.log(k + ":", data[k]);
      }
    });
    console.groupEnd();
    window.__VDH_EME_LOG__.push(Object.assign({ timestamp: makeTimestamp() }, data));
  }

  window.__VDH_EME_LOG__ = [];

  /* --- D1: navigator.requestMediaKeySystemAccess interception --- */
  if (typeof navigator !== "undefined" && typeof navigator.requestMediaKeySystemAccess === "function") {
    var _nativeReqMKSA = navigator.requestMediaKeySystemAccess;
    navigator.requestMediaKeySystemAccess = function (keySystem, supportedConfigurations) {
      logEmeEvent("key_system_access", {
        event: "requestMediaKeySystemAccess",
        keySystem: keySystem,
        configCount: supportedConfigurations ? supportedConfigurations.length : 0,
        configurations: supportedConfigurations,
      });
      return _nativeReqMKSA.call(this, keySystem, supportedConfigurations);
    };
  }

  /* --- D2: MediaKeys.createSession interception --- */
  if (typeof MediaKeys !== "undefined" && MediaKeys.prototype.createSession) {
    var _nativeCreateSession = MediaKeys.prototype.createSession;
    MediaKeys.prototype.createSession = function (sessionType) {
      var session = _nativeCreateSession.call(this, sessionType);
      var sessionIdLog = "session_" + Math.random().toString(36).substring(2, 10);
      session.__VDH_SESSION_ID__ = sessionIdLog;

      logEmeEvent("session_created", {
        event: "createSession",
        sessionType: sessionType || "temporary",
        sessionId: sessionIdLog,
        keySystem: safeCall(function () {
          return session._keySystem || "unknown";
        }, "unknown"),
      });

      /* --- D3: MediaKeySession.generateRequest interception --- */
      if (session.generateRequest) {
        var _nativeGenerateRequest = session.generateRequest;
        session.generateRequest = function (initDataType, initData) {
          var logData = {
            event: "generateRequest",
            sessionId: sessionIdLog,
            initDataType: initDataType,
            initDataByteLength: initData ? initData.byteLength : 0,
            rawInitData: initData,
          };
          if (initData && initData.byteLength > 0) {
            var psshResult = parsePsshBox(initData);
            if (!psshResult.error) {
              logData.psshParsed = psshResult;
            } else {
              logData.psshError = psshResult.error;
            }
            logData.initDataB64 = bytesToBase64(initData);
            logData.initDataHex = bytesToHex(initData);
          }
          logEmeEvent("license_request", logData);
          return _nativeGenerateRequest.call(this, initDataType, initData);
        };
      }

      /* --- D4: MediaKeySession.update interception (license response) --- */
      if (session.update) {
        var _nativeUpdate = session.update;
        session.update = function (response) {
          var logData = {
            event: "license_response",
            sessionId: sessionIdLog,
            responseByteLength: response ? response.byteLength : 0,
            rawLicenseResponse: response,
          };
          if (response && response.byteLength > 0) {
            logData.responseB64 = bytesToBase64(response);
            logData.responseHex = bytesToHex(response);

            var responseView = new Uint8Array(response);
            var readableStart = "";
            for (var ri = 0; ri < Math.min(64, responseView.length); ri++) {
              var ch = responseView[ri];
              if (ch >= 32 && ch <= 126) {
                readableStart += String.fromCharCode(ch);
              } else if (readableStart[readableStart.length - 1] !== ".") {
                readableStart += ".";
              }
            }
            if (logData.responseB64.match(/^eyJ/)) {
              try {
                var decoded = JSON.parse(atob(logData.responseB64));
                if (decoded.keys && Array.isArray(decoded.keys)) {
                  logData.clearkeyKeys = decoded.keys.map(function (k) {
                    return {
                      kid: k.kid || k.k || "",
                      k: k.k || k.kid || "",
                      kty: k.kty || "oct",
                      type: k.type || "temporary",
                    };
                  });
                }
                logData.decodedJson = decoded;
              } catch (jsonErr) {
                logData.jsonParseError = jsonErr.message;
              }
            }
          }
          logEmeEvent("license_response", logData);
          return _nativeUpdate.call(this, response);
        };
      }
      return session;
    };
  }

  /* --- D5: HTMLVideoElement mediaKeys property monitoring --- */
  if (typeof HTMLMediaElement !== "undefined") {
    var _mediaElements = new WeakSet();
    var _checkInterval = setInterval(function () {
      var videos = document.querySelectorAll("video, audio");
      for (var i = 0; i < videos.length; i++) {
        var el = videos[i];
        if (_mediaElements.has(el)) {
          continue;
        }
        _mediaElements.add(el);
        if (el.mediaKeys) {
          console.log("[VDH-SoTA] DRM MediaElement detected:", {
            tagName: el.tagName,
            src: el.src || el.currentSrc || "MSE",
            hasMediaKeys: true,
            readyState: el.readyState,
            networkState: el.networkState,
            errorCode: el.error ? el.error.code : null,
          });
        }
      }
    }, 2000);
  }

  /* ------------------------------------------------------------------ */
  /*  LAYER E: UNIFIED DATA LOGGER / TELEMETRY DASHBOARD                 */
  /* ------------------------------------------------------------------ */

  function generateDashboard() {
    var mediaCount = window.__VDH_MEDIA_LOG__.length;
    var emeCount = window.__VDH_EME_LOG__.length;

    var mediaUrls = window.__VDH_MEDIA_LOG__.map(function (e) {
      return e.url;
    });
    var uniqueUrls = [];
    mediaUrls.forEach(function (u) {
      if (uniqueUrls.indexOf(u) === -1) {
        uniqueUrls.push(u);
      }
    });

    var protocols = {};
    window.__VDH_MEDIA_LOG__.forEach(function (e) {
      protocols[e.protocol] = (protocols[e.protocol] || 0) + 1;
    });

    var emeEvents = {};
    window.__VDH_EME_LOG__.forEach(function (e) {
      emeEvents[e.event] = (emeEvents[e.event] || 0) + 1;
    });

    var clearkeyMatrices = window.__VDH_EME_LOG__.filter(function (e) {
      return e.clearkeyKeys && e.clearkeyKeys.length > 0;
    });

    console.groupCollapsed(
      "%c[VDH-SoTA] %cUNIFIED DASHBOARD %c(" + makeTimestamp() + ")",
      "color: #fff; background: #000; padding: 2px 8px; border-radius: 3px; font-weight: bold; font-size: 14px;",
      "color: #1a73e8; font-weight: bold; font-size: 14px;",
      "color: #999; font-size: 11px;",
    );
    console.log("%cMedia Intercepts:%c " + mediaCount + " (%c" + uniqueUrls.length + " unique%c)", "font-weight:bold;", "", "color:#1a73e8;", "");
    console.log("  Protocol distribution:", protocols);
    console.log("%cEME Events:%c " + emeCount, "font-weight:bold;", "");
    console.log("  Event types:", emeEvents);
    if (clearkeyMatrices.length > 0) {
      console.log("%cClearKey Matrices Captured:%c " + clearkeyMatrices.length, "font-weight:bold; color:#34a853;", "");
      clearkeyMatrices.forEach(function (m, idx) {
        console.log("  [" + idx + "] Session:", m.sessionId, "Keys:", JSON.stringify(m.clearkeyKeys));
      });
    }
    console.log("%cFull Logs:%c", "font-weight:bold;", "");
    console.log("  window.__VDH_MEDIA_LOG__ (" + mediaCount + " entries)");
    console.log("  window.__VDH_EME_LOG__   (" + emeCount + " entries)");
    console.groupEnd();

    return {
      timestamp: makeTimestamp(),
      mediaIntercepts: mediaCount,
      uniqueUrls: uniqueUrls.length,
      protocolDistribution: protocols,
      emeEvents: emeCount,
      emeEventTypes: emeEvents,
      clearkeyMatrices: clearkeyMatrices.length,
    };
  }

  window.__VDH_GET_DASHBOARD__ = generateDashboard;

  /* ------------------------------------------------------------------ */
  /*  FINAL: LOG INITIALIZATION                                          */
  /* ------------------------------------------------------------------ */

  console.log(
    "%c[VDH-SoTA] %cMulti-Layer Interception Grid %cACTIVE %c| " + makeTimestamp() + " |",
    "color: #fff; background: #000; padding: 2px 8px; border-radius: 3px;",
    "color: #1a73e8; font-weight: bold;",
    "color: #0f0; font-weight: bold;",
    "color: #999;",
  );
  console.log(
    "  Layers: " + "%cHTTP Sniff%c | " + "%cWebRTC SDP%c | " + "%cWebSocket%c | " + "%cEME/DRM%c | " + "%cLogger%c",
    "color:#1a73e8;",
    "",
    "color:#34a853;",
    "",
    "color:#fbbc04;",
    "",
    "color:#ea4335;",
    "",
    "color:#000;",
    "",
  );
  console.log("  Dashboard: %cwindow.__VDH_GET_DASHBOARD__()%c to view summary", "font-weight:bold;", "");
  console.log("  Logs: %cwindow.__VDH_MEDIA_LOG__%c, %cwindow.__VDH_EME_LOG__%c", "font-family:monospace;", "", "font-family:monospace;", "");
})();
