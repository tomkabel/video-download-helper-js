/**
 * ============================================================================
 * VIDEO DOWNLOAD HELPER — DIAGNOSTIC TELEMETRY & PROTOCOL INTERCEPTION SUITE
 * ============================================================================
 *
 * Execution Model:
 *   Module A (Event Bus) → Module B (Fetch/XHR)  ┐
 *   Module A (Event Bus) → Module C (MSE Source)  ├─ Parallel Hooks
 *   Module A (Event Bus) → Module D (WebRTC/WS)   │
 *   Module A (Event Bus) → Module E (EME/ClearKey)┘
 *     → Module F (Report Logger) subscribes to bus events
 *
 * IMPORTANT: Module A MUST produce a resolved bus handle before B—E execute.
 * This is enforced by sequential await in the Top-Level IIFE.
 *
 * License: MIT — Non-destructive diagnostic instrumentation only.
 * ============================================================================
 */

"use strict";

// ===========================================================================
// MODULE A: CORE EVENT BUS & ORCHESTRATION LAYER
// ===========================================================================

(function initializeTelemetryBus() {
  if (window.__telemetryBus !== void 0) {
    console.warn("[Telemetry:A] __telemetryBus already initialized — skipping duplicate bootstrap");
    return;
  }

  const SUBSCRIBERS = new Map();
  let NEXT_ID = 1;

  const bus = {
    publish(eventType, payload) {
      if (typeof eventType !== "string" || eventType.length === 0) {
        return;
      }
      if (payload === void 0) {
        payload = null;
      }
      const timestamp = Date.now();
      const envelope = Object.freeze({
        eventType,
        payload,
        timestamp,
        sessionId: bus.sessionId,
      });
      const listeners = SUBSCRIBERS.get(eventType);
      if (listeners !== void 0 && listeners.size > 0) {
        for (const [_, handler] of listeners) {
          try {
            handler(envelope);
          } catch (err) {
            console.error(`[Telemetry:A] Subscriber error for event "${eventType}":`, err);
          }
        }
      }
      const wildcardListeners = SUBSCRIBERS.get("*");
      if (wildcardListeners !== void 0 && wildcardListeners.size > 0) {
        for (const [_, handler] of wildcardListeners) {
          try {
            handler(envelope);
          } catch (err) {
            console.error(`[Telemetry:A] Wildcard subscriber error for event "${eventType}":`, err);
          }
        }
      }
    },

    subscribe(eventType, handler) {
      if (typeof eventType !== "string" || eventType.length === 0) {
        throw new TypeError("[Telemetry:A] subscribe() requires a non-empty string eventType");
      }
      if (typeof handler !== "function") {
        throw new TypeError("[Telemetry:A] subscribe() requires a function handler");
      }
      const id = NEXT_ID++;
      if (!SUBSCRIBERS.has(eventType)) {
        SUBSCRIBERS.set(eventType, new Map());
      }
      SUBSCRIBERS.get(eventType).set(id, handler);
      return function unsubscribe() {
        const map = SUBSCRIBERS.get(eventType);
        if (map !== void 0) {
          map.delete(id);
          if (map.size === 0) {
            SUBSCRIBERS.delete(eventType);
          }
        }
      };
    },

    once(eventType, handler) {
      const unsub = bus.subscribe(eventType, (envelope) => {
        unsub();
        handler(envelope);
      });
      return unsub;
    },

    sessionId: `telemetry_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`,

    subscriberCount(eventType) {
      const map = SUBSCRIBERS.get(eventType);
      return map !== void 0 ? map.size : 0;
    },
  };

  Object.defineProperty(window, "__telemetryBus", {
    value: Object.freeze(bus),
    writable: false,
    configurable: false,
    enumerable: false,
  });

  console.info("[Telemetry:A] Diagnostic event bus initialized. Session ID:", bus.sessionId);
})();

// ===========================================================================
// MODULE B: API HOOKING — MANIFESTS & HTTP STREAM INTERCEPTION
// ===========================================================================

(function installManifestHooks() {
  const bus = window.__telemetryBus;
  if (!bus) {
    console.error("[Telemetry:B] __telemetryBus not found — aborting hook installation");
    return;
  }

  const MANIFEST_EXTENSIONS = new Set(["m3u8", "mpd", "m3u"]);
  const MANIFEST_MIME_PATTERNS = [/^application\/(x-)?mpegurl/i, /^application\/dash\+xml/i, /^application\/vnd\.apple\.mpegurl/i, /^audio\/(x-)?mpegurl/i, /^video\/(x-)?mpegurl/i];

  function isLikelyManifest(url, contentType) {
    if (!url || typeof url !== "string") {
      return false;
    }
    try {
      const pathname = new URL(url, location.origin).pathname;
      const ext = pathname.split(".").pop()?.toLowerCase();
      if (ext && MANIFEST_EXTENSIONS.has(ext)) {
        return true;
      }
    } catch (_) {
      /* malformed URL — skip extension check */
    }
    if (contentType && typeof contentType === "string") {
      for (const pattern of MANIFEST_MIME_PATTERNS) {
        if (pattern.test(contentType)) {
          return true;
        }
      }
    }
    const lower = url.toLowerCase();
    if (lower.includes(".m3u8") || lower.includes(".mpd")) {
      return true;
    }
    return false;
  }

  // --- fetch() hook ---
  const nativeFetch = window.fetch;
  window.fetch = function hookedFetch(input, init) {
    const requestUrl = input instanceof Request ? input.url : String(input || "");
    const requestHeaders = new Headers(input instanceof Request ? input.headers : init && init.headers ? init.headers : void 0);

    const startTime = performance.now();
    const resultPromise = nativeFetch.call(this, input, init);

    resultPromise
      .then((response) => {
        const duration = Math.round(performance.now() - startTime);
        const contentType = response.headers.get("content-type") || "";
        const contentLength = response.headers.get("content-length") || "";
        const cloned = response.clone();
        if (isLikelyManifest(requestUrl, contentType)) {
          cloned
            .text()
            .then((body) => {
              const trimmed = body.length > 8192 ? body.slice(0, 8192) + "..." : body;
              bus.publish("fetch:manifest", {
                url: requestUrl,
                method: init?.method || "GET",
                status: response.status,
                contentType,
                contentLength: contentLength ? parseInt(contentLength, 10) : null,
                headers: Object.fromEntries(response.headers.entries()),
                requestHeaders: Object.fromEntries(requestHeaders.entries()),
                bodyPreview: trimmed,
                bodyLength: body.length,
                durationMs: duration,
                type: contentType.includes("dash") ? "dash" : "hls",
              });
            })
            .catch((readErr) => {
              bus.publish("fetch:manifest:error", {
                url: requestUrl,
                error: readErr.message || String(readErr),
                contentType,
                status: response.status,
                durationMs: duration,
              });
            });
        } else if (/video\//i.test(contentType) || /audio\//i.test(contentType)) {
          bus.publish("fetch:media_stream", {
            url: requestUrl,
            type: contentType.startsWith("video") ? "video" : "audio",
            contentType,
            contentLength: contentLength ? parseInt(contentLength, 10) : null,
            status: response.status,
            requestHeaders: Object.fromEntries(requestHeaders.entries()),
            durationMs: duration,
          });
        }
      })
      .catch((fetchErr) => {
        const duration = Math.round(performance.now() - startTime);
        if (isLikelyManifest(requestUrl, "")) {
          bus.publish("fetch:manifest:error", {
            url: requestUrl,
            error: fetchErr.message || String(fetchErr),
            durationMs: duration,
          });
        }
      });

    return resultPromise;
  };
  console.info("[Telemetry:B] window.fetch hooked for manifest interception");

  // --- XMLHttpRequest hook ---
  const NativeXHR = window.XMLHttpRequest;
  const originalOpen = NativeXHR.prototype.open;
  const originalSetRequestHeader = NativeXHR.prototype.setRequestHeader;

  NativeXHR.prototype.open = function hookedXHROpen(method, url, async = true, user, password) {
    this.__telemetry_url = String(url || "");
    this.__telemetry_method = String(method || "GET");
    this.__telemetry_requestHeaders = {};
    return originalOpen.call(this, method, url, async, user, password);
  };

  NativeXHR.prototype.setRequestHeader = function hookedSetRequestHeader(name, value) {
    if (this.__telemetry_requestHeaders) {
      this.__telemetry_requestHeaders[name] = String(value);
    }
    return originalSetRequestHeader.call(this, name, value);
  };

  const originalSend = NativeXHR.prototype.send;
  NativeXHR.prototype.send = function hookedXHRSend(body) {
    const xhr = this;
    const url = xhr.__telemetry_url || "";
    const method = xhr.__telemetry_method || "GET";
    const requestHeaders = xhr.__telemetry_requestHeaders || {};
    const startTime = performance.now();

    const onReadyState = function () {
      if (xhr.readyState !== 4) {
        return;
      }
      const duration = Math.round(performance.now() - startTime);
      const contentType = xhr.getResponseHeader("content-type") || "";
      const contentLength = xhr.getResponseHeader("content-length") || "";

      if (isLikelyManifest(url, contentType)) {
        const body = xhr.responseText.length > 8192 ? xhr.responseText.slice(0, 8192) + "..." : xhr.responseText;
        bus.publish("xhr:manifest", {
          url,
          method,
          status: xhr.status,
          contentType,
          contentLength: contentLength ? parseInt(contentLength, 10) : null,
          requestHeaders,
          responseHeaders: xhr
            .getAllResponseHeaders()
            .split("\r\n")
            .filter((line) => line.includes(":"))
            .reduce((acc, line) => {
              const [k, ...v] = line.split(":");
              acc[k.trim().toLowerCase()] = v.join(":").trim();
              return acc;
            }, {}),
          bodyPreview: body,
          bodyLength: xhr.responseText.length,
          durationMs: duration,
          type: contentType.includes("dash") ? "dash" : "hls",
        });
      } else if (/video\//i.test(contentType) || /audio\//i.test(contentType)) {
        bus.publish("xhr:media_stream", {
          url,
          method,
          type: contentType.startsWith("video") ? "video" : "audio",
          contentType,
          contentLength: contentLength ? parseInt(contentLength, 10) : null,
          status: xhr.status,
          requestHeaders,
          durationMs: duration,
        });
      }
    };

    xhr.addEventListener("readystatechange", onReadyState, { once: false });
    return originalSend.call(this, body);
  };
  console.info("[Telemetry:B] XMLHttpRequest.prototype hooked");
})();

// ===========================================================================
// MODULE C: MSE SOURCE BUFFER INTERCEPTION — INIT SEGMENT CAPTURE
// ===========================================================================

(function installMSEHooks() {
  const bus = window.__telemetryBus;
  if (!bus) {
    console.error("[Telemetry:C] __telemetryBus not found — aborting MSE hook");
    return;
  }

  if (typeof MediaSource === "undefined" || !MediaSource.prototype || !MediaSource.prototype.addSourceBuffer) {
    console.info("[Telemetry:C] MediaSource API not available in this context");
    return;
  }

  const nativeAddSourceBuffer = MediaSource.prototype.addSourceBuffer;
  MediaSource.prototype.addSourceBuffer = function hookedAddSourceBuffer(mimeType) {
    const sourceBuffer = nativeAddSourceBuffer.call(this, mimeType);
    bus.publish("ms:sourcebuffer_added", {
      mimeType,
      mode: sourceBuffer.mode,
    });

    if (typeof SourceBuffer !== "undefined" && !SourceBuffer.prototype.__telemetry_appendBuffer_hooked) {
      const nativeAppendBuffer = SourceBuffer.prototype.appendBuffer;
      SourceBuffer.prototype.appendBuffer = function hookedAppendBuffer(data) {
        if (data instanceof ArrayBuffer || ArrayBuffer.isView(data)) {
          const buffer = data instanceof ArrayBuffer ? new Uint8Array(data) : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
          const hex = Array.from(buffer.slice(0, 256))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
          const isInitSegment = detectInitSegment(buffer);
          if (isInitSegment) {
            bus.publish("ms:init_segment", {
              byteLength: buffer.byteLength,
              hexPreview: hex,
              hexPreviewTruncated: buffer.byteLength > 256,
              isoBoxes: parseISOBoxHeaders(buffer),
            });
          }
          bus.publish("ms:segment", {
            byteLength: buffer.byteLength,
            hexPreview: hex,
            hexPreviewTruncated: buffer.byteLength > 256,
            isInitSegment,
          });
        }
        return nativeAppendBuffer.call(this, data);
      };
      SourceBuffer.prototype.__telemetry_appendBuffer_hooked = true;
      console.info("[Telemetry:C] SourceBuffer.prototype.appendBuffer hooked");
    }

    return sourceBuffer;
  };
  console.info("[Telemetry:C] MediaSource.prototype.addSourceBuffer hooked");

  function detectInitSegment(buffer) {
    if (buffer.byteLength < 8) {
      return false;
    }
    const ftypOffset = indexOfBox(buffer, 0x66747970); // 'ftyp'
    const moovOffset = indexOfBox(buffer, 0x6d6f6f76); // 'moov'
    const pdinOffset = indexOfBox(buffer, 0x7064696e); // 'pdin'
    return ftypOffset !== -1 || moovOffset !== -1 || pdinOffset !== -1;
  }

  function indexOfBox(buffer, boxType) {
    const dv = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    let offset = 0;
    while (offset + 8 <= buffer.byteLength) {
      const size = dv.getUint32(offset);
      const type = dv.getUint32(offset + 4);
      if (type === boxType) {
        return offset;
      }
      if (size === 0 || size < 8) {
        break;
      }
      offset += size;
    }
    return -1;
  }

  function parseISOBoxHeaders(buffer) {
    const boxes = [];
    const dv = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    let offset = 0;
    while (offset + 8 <= buffer.byteLength) {
      let size = dv.getUint32(offset);
      const type = dv.getUint32(offset + 4);
      if (size === 0) {
        break;
      }
      if (size === 1 && offset + 16 <= buffer.byteLength) {
        const high = dv.getUint32(offset + 8);
        const low = dv.getUint32(offset + 12);
        size = Number((BigInt(high) << 32n) | BigInt(low));
      }
      if (size < 8) {
        break;
      }
      const typeStr = String.fromCharCode((type >> 24) & 0xff, (type >> 16) & 0xff, (type >> 8) & 0xff, type & 0xff);
      boxes.push({
        type: typeStr,
        size,
        offset,
      });
      offset += size;
      if (offset >= buffer.byteLength) {
        break;
      }
    }
    return boxes;
  }
})();

// ===========================================================================
// MODULE D: WEBRTC & WEBSOCKET TELEMETRY
// ===========================================================================

(function installWebRTCAndWebSocketHooks() {
  const bus = window.__telemetryBus;
  if (!bus) {
    console.error("[Telemetry:D] __telemetryBus not found — aborting WebRTC/WS hooks");
    return;
  }

  // --- RTCPeerConnection hooks ---
  if (typeof RTCPeerConnection !== "undefined" && RTCPeerConnection.prototype) {
    const proto = RTCPeerConnection.prototype;

    if (proto.setLocalDescription && !proto.__telemetry_sld_hooked) {
      const nativeSLD = proto.setLocalDescription;
      proto.setLocalDescription = function hookedSLD(desc) {
        if (desc && desc.sdp) {
          bus.publish("webrtc:local_description", {
            type: desc.type || "unknown",
            sdp: desc.sdp,
          });
        }
        return nativeSLD.call(this, desc);
      };
      proto.__telemetry_sld_hooked = true;
    }

    if (proto.setRemoteDescription && !proto.__telemetry_srd_hooked) {
      const nativeSRD = proto.setRemoteDescription;
      proto.setRemoteDescription = function hookedSRD(desc) {
        if (desc && desc.sdp) {
          bus.publish("webrtc:remote_description", {
            type: desc.type || "unknown",
            sdp: desc.sdp,
          });
        }
        return nativeSRD.call(this, desc);
      };
      proto.__telemetry_srd_hooked = true;
    }

    console.info("[Telemetry:D] RTCPeerConnection.prototype hooks installed");
  }

  // --- WebSocket hooks ---
  if (typeof WebSocket !== "undefined") {
    const NativeWebSocket = WebSocket;
    const hookedMap = new WeakMap();

    const HookedWebSocket = function hookedWSConstructor(url, protocols) {
      const ws = new NativeWebSocket(url, protocols);
      hookedMap.set(ws, { url, startTime: performance.now() });
      bus.publish("ws:connect", { url, protocols: protocols || null });

      wrapWebSocketEvent(ws, "message", (event) => {
        const meta = hookedMap.get(ws);
        if (!meta) {
          return;
        }
        let dataType = "text";
        let byteLength = 0;
        let hexPreview = "";
        if (event.data instanceof ArrayBuffer) {
          dataType = "arraybuffer";
          byteLength = event.data.byteLength;
          const arr = new Uint8Array(event.data);
          hexPreview = Array.from(arr.slice(0, 128))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
        } else if (event.data instanceof Blob) {
          dataType = "blob";
          byteLength = event.data.size;
        } else if (ArrayBuffer.isView(event.data)) {
          dataType = "bufferview";
          byteLength = event.data.byteLength;
          const arr = new Uint8Array(event.data.buffer, event.data.byteOffset, event.data.byteLength);
          hexPreview = Array.from(arr.slice(0, 128))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
        }
        bus.publish("ws:message", {
          url: meta.url,
          dataType,
          byteLength,
          hexPreview,
          hexPreviewTruncated: byteLength > 128,
          elapsedMs: Math.round(performance.now() - meta.startTime),
        });
      });

      wrapWebSocketEvent(ws, "error", (event) => {
        const meta = hookedMap.get(ws);
        bus.publish("ws:error", {
          url: meta ? meta.url : "unknown",
          elapsedMs: meta ? Math.round(performance.now() - meta.startTime) : 0,
        });
      });

      wrapWebSocketEvent(ws, "close", (event) => {
        const meta = hookedMap.get(ws);
        bus.publish("ws:close", {
          url: meta ? meta.url : "unknown",
          code: event.code,
          reason: event.reason,
          wasClean: event.wasClean,
          elapsedMs: meta ? Math.round(performance.now() - meta.startTime) : 0,
        });
      });

      return ws;
    };

    HookedWebSocket.prototype = NativeWebSocket.prototype;
    HookedWebSocket.CONNECTING = NativeWebSocket.CONNECTING;
    HookedWebSocket.OPEN = NativeWebSocket.OPEN;
    HookedWebSocket.CLOSING = NativeWebSocket.CLOSING;
    HookedWebSocket.CLOSED = NativeWebSocket.CLOSED;

    Object.defineProperty(window, "WebSocket", {
      value: HookedWebSocket,
      writable: true,
      configurable: true,
      enumerable: true,
    });

    function wrapWebSocketEvent(ws, eventName, listener) {
      ws.addEventListener(eventName, function handler(e) {
        try {
          listener(e);
        } catch (err) {
          console.error(`[Telemetry:D] WebSocket ${eventName} handler error:`, err);
        }
      });
    }

    console.info("[Telemetry:D] WebSocket constructor wrapped");
  }
})();

// ===========================================================================
// MODULE E: EME & CLEARKEY MONITORING
// ===========================================================================

(function installEMEHooks() {
  const bus = window.__telemetryBus;
  if (!bus) {
    console.error("[Telemetry:E] __telemetryBus not found — aborting EME hooks");
    return;
  }

  if (typeof navigator === "undefined" || typeof navigator.requestMediaKeySystemAccess !== "function") {
    console.info("[Telemetry:E] EME API not available in this context");
    return;
  }

  const nativeRMKSA = navigator.requestMediaKeySystemAccess.bind(navigator);
  navigator.requestMediaKeySystemAccess = function hookedRMKSA(keySystem, supportedConfigurations) {
    bus.publish("eme:request_key_system", {
      keySystem,
      configCount: supportedConfigurations.length,
      configs: supportedConfigurations.map((cfg) => ({
        initDataTypes: cfg.initDataTypes || [],
        audioCapabilities: (cfg.audioCapabilities || []).map((c) => c.contentType),
        videoCapabilities: (cfg.videoCapabilities || []).map((c) => c.contentType),
        distinctiveIdentifier: cfg.distinctiveIdentifier || "not specified",
        persistentState: cfg.persistentState || "not specified",
      })),
    });

    return nativeRMKSA(keySystem, supportedConfigurations).then((mediaKeySystemAccess) => {
      const nativeCreateMediaKeys = mediaKeySystemAccess.createMediaKeys.bind(mediaKeySystemAccess);
      mediaKeySystemAccess.createMediaKeys = function hookedCreateMediaKeys() {
        return nativeCreateMediaKeys().then((mediaKeys) => {
          if (mediaKeys.createSession && !mediaKeys.__telemetry_createSession_hooked) {
            const nativeCreateSession = mediaKeys.createSession.bind(mediaKeys);
            mediaKeys.createSession = function hookedCreateSession(sessionType) {
              const session = nativeCreateSession(sessionType);
              bus.publish("eme:session_created", {
                keySystem,
                sessionType: sessionType || "temporary",
              });

              if (session.generateRequest && !session.__telemetry_genRequest_hooked) {
                const nativeGenerateRequest = session.generateRequest.bind(session);
                session.generateRequest = function hookedGenerateRequest(initDataType, initData) {
                  let initDataHex = "";
                  let initDataB64 = "";
                  let psshBoxes = [];

                  try {
                    if (initData instanceof ArrayBuffer) {
                      initDataB64 = arrayBufferToBase64(initData);
                      initDataHex = arrayBufferToHex(initData);
                      psshBoxes = parsePSSHBoxes(new Uint8Array(initData));
                    } else if (ArrayBuffer.isView(initData)) {
                      const sliced = new Uint8Array(initData.buffer, initData.byteOffset, initData.byteLength);
                      initDataB64 = uint8ArrayToBase64(sliced);
                      initDataHex = uint8ArrayToHex(sliced);
                      psshBoxes = parsePSSHBoxes(sliced);
                    }
                  } catch (parseErr) {
                    console.warn("[Telemetry:E] initData parsing error:", parseErr);
                  }

                  bus.publish("eme:license_request", {
                    keySystem,
                    sessionType: sessionType || "temporary",
                    initDataType,
                    initDataLength: initData instanceof ArrayBuffer ? initData.byteLength : ArrayBuffer.isView(initData) ? initData.byteLength : 0,
                    initDataHex,
                    initDataB64,
                    psshBoxes,
                  });

                  return nativeGenerateRequest(initDataType, initData);
                };
                session.__telemetry_genRequest_hooked = true;
              }

              if (session.update && !session.__telemetry_update_hooked) {
                const nativeUpdate = session.update.bind(session);
                session.update = function hookedUpdate(response) {
                  let responseHex = "";
                  let responseB64 = "";
                  let clearkeyMatrix = [];

                  try {
                    if (response instanceof ArrayBuffer) {
                      responseB64 = arrayBufferToBase64(response);
                      responseHex = arrayBufferToHex(response);
                      clearkeyMatrix = extractClearKeyMatrixFromLicense(new Uint8Array(response));
                    } else if (ArrayBuffer.isView(response)) {
                      const sliced = new Uint8Array(response.buffer, response.byteOffset, response.byteLength);
                      responseB64 = uint8ArrayToBase64(sliced);
                      responseHex = uint8ArrayToHex(sliced);
                      clearkeyMatrix = extractClearKeyMatrixFromLicense(sliced);
                    }
                  } catch (parseErr) {
                    console.warn("[Telemetry:E] License response parsing error:", parseErr);
                  }

                  bus.publish("eme:license_response", {
                    keySystem,
                    responseLength: response instanceof ArrayBuffer ? response.byteLength : ArrayBuffer.isView(response) ? response.byteLength : 0,
                    responseHex,
                    responseB64,
                    clearkeyMatrix,
                  });

                  return nativeUpdate(response);
                };
                session.__telemetry_update_hooked = true;
              }

              return session;
            };
            mediaKeys.__telemetry_createSession_hooked = true;
          }
          return mediaKeys;
        });
      };
      return mediaKeySystemAccess;
    });
  };
  console.info("[Telemetry:E] EME pipeline hooked");

  // --- Binary utility functions ---
  function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function uint8ArrayToBase64(arr) {
    let binary = "";
    for (let i = 0; i < arr.byteLength; i++) {
      binary += String.fromCharCode(arr[i]);
    }
    return btoa(binary);
  }

  function arrayBufferToHex(buffer) {
    const arr = new Uint8Array(buffer);
    return uint8ArrayToHex(arr);
  }

  function uint8ArrayToHex(arr) {
    const hexParts = new Array(arr.byteLength);
    for (let i = 0; i < arr.byteLength; i++) {
      hexParts[i] = arr[i].toString(16).padStart(2, "0");
    }
    return hexParts.join("");
  }

  function parsePSSHBoxes(data) {
    const boxes = [];
    let offset = 0;
    const len = data.byteLength;
    while (offset + 8 <= len) {
      const view = new DataView(data.buffer, data.byteOffset + offset, Math.min(len - offset, len));
      let size = view.getUint32(0);
      const boxType = view.getUint32(4);
      if (size === 0) {
        break;
      }
      if (size === 1 && offset + 16 <= len) {
        const high = view.getUint32(8);
        const low = view.getUint32(12);
        size = Number((BigInt(high) << 32n) | BigInt(low));
      }
      if (size < 8 || offset + size > len) {
        break;
      }
      const typeStr = String.fromCharCode((boxType >> 24) & 0xff, (boxType >> 16) & 0xff, (boxType >> 8) & 0xff, boxType & 0xff);
      if (typeStr === "pssh") {
        const systemIdBytes = data.slice(offset + 12, offset + 28);
        const systemIdHex = uint8ArrayToHex(systemIdBytes);
        const systemIdUUID = `${systemIdHex.slice(0, 8)}-${systemIdHex.slice(8, 12)}-${systemIdHex.slice(12, 16)}-${systemIdHex.slice(16, 20)}-${systemIdHex.slice(20)}`;
        const dataSize = view.getUint32(28);
        const psshData = data.slice(offset + 32, offset + 32 + Math.min(dataSize, size - 32));
        boxes.push({
          systemId: systemIdUUID,
          systemIdHex: "0x" + systemIdHex,
          dataSize,
          dataHex: uint8ArrayToHex(psshData),
          dataB64: uint8ArrayToBase64(psshData),
        });
      }
      offset += size;
    }
    return boxes;
  }

  function extractClearKeyMatrixFromLicense(data) {
    const matrix = [];
    try {
      const jsonStr = new TextDecoder("utf-8", { fatal: false }).decode(data);
      let parsed;
      try {
        parsed = JSON.parse(jsonStr);
      } catch (_) {
        return matrix;
      }
      if (!parsed || !Array.isArray(parsed.keys)) {
        return matrix;
      }
      for (const entry of parsed.keys) {
        if (entry && entry.kid && entry.k) {
          let kidB64 = "";
          let keyB64 = "";
          try {
            kidB64 = typeof entry.kid === "string" ? entry.kid : uint8ArrayToBase64(new Uint8Array(entry.kid));
          } catch (_) {
            kidB64 = String(entry.kid);
          }
          try {
            keyB64 = typeof entry.k === "string" ? entry.k : uint8ArrayToBase64(new Uint8Array(entry.k));
          } catch (_) {
            keyB64 = String(entry.k);
          }
          matrix.push({
            kid: kidB64,
            key: keyB64,
            type: entry.type || "temporary",
          });
        }
      }
    } catch (err) {
      console.warn("[Telemetry:E] ClearKey matrix extraction error:", err);
    }
    return matrix;
  }
})();

// ===========================================================================
// MODULE F: UNIFIED DATA LOGGER & REPORT MODULE
// ===========================================================================

(function installTelemetryLogger() {
  const bus = window.__telemetryBus;
  if (!bus) {
    console.error("[Telemetry:F] __telemetryBus not found — cannot install logger");
    return;
  }

  if (bus.__telemetry_logger_installed) {
    console.info("[Telemetry:F] Logger already installed — skipping");
    return;
  }

  const collectedEvents = [];
  const MAX_COLLECTED = 2000;

  function pushCollected(envelope) {
    collectedEvents.push(envelope);
    if (collectedEvents.length > MAX_COLLECTED) {
      collectedEvents.shift();
    }
  }

  // --- Fetch manifest log ---
  bus.subscribe("fetch:manifest", (env) => {
    pushCollected(env);
    console.groupCollapsed(
      `%c[FETCH:MANIFEST] %c${env.payload.type.toUpperCase()} %c${env.payload.status} %c${truncate(env.payload.url, 80)}`,
      "color: #4fc3f7; font-weight: bold",
      "color: #ffb74d",
      env.payload.status < 400 ? "color: #66bb6a" : "color: #ef5350",
      "color: #90a4ae",
    );
    console.log("URL:", env.payload.url);
    console.log("Method:", env.payload.method);
    console.log("Content-Type:", env.payload.contentType || "(none)");
    console.log("Content-Length:", env.payload.contentLength);
    console.log("Body Length:", env.payload.bodyLength);
    console.log("Body Preview:", env.payload.bodyPreview);
    console.log("Duration:", env.payload.durationMs + "ms");
    console.log("Request Headers:", env.payload.requestHeaders);
    console.log("Response Headers:", env.payload.headers);
    console.groupEnd();
  });

  // --- XHR manifest log ---
  bus.subscribe("xhr:manifest", (env) => {
    pushCollected(env);
    console.groupCollapsed(
      `%c[XHR:MANIFEST] %c${env.payload.type.toUpperCase()} %c${env.payload.status} %c${truncate(env.payload.url, 80)}`,
      "color: #4fc3f7; font-weight: bold",
      "color: #ffb74d",
      env.payload.status < 400 ? "color: #66bb6a" : "color: #ef5350",
      "color: #90a4ae",
    );
    console.log("URL:", env.payload.url);
    console.log("Method:", env.payload.method);
    console.log("Content-Type:", env.payload.contentType);
    console.log("Content-Length:", env.payload.contentLength);
    console.log("Body Length:", env.payload.bodyLength);
    console.log("Body Preview:", env.payload.bodyPreview);
    console.log("Duration:", env.payload.durationMs + "ms");
    console.log("Request Headers:", env.payload.requestHeaders);
    console.log("Response Headers:", env.payload.responseHeaders);
    console.groupEnd();
  });

  // --- Direct media stream log ---
  bus.subscribe("fetch:media_stream", (env) => {
    pushCollected(env);
    console.groupCollapsed(
      `%c[FETCH:STREAM] %c${env.payload.type.toUpperCase()} %c${env.payload.contentType} %c${truncate(env.payload.url, 80)}`,
      "color: #4fc3f7; font-weight: bold",
      "color: #ffb74d",
      "color: #66bb6a",
      "color: #90a4ae",
    );
    console.log("URL:", env.payload.url);
    console.log("Type:", env.payload.type);
    console.log("Content-Type:", env.payload.contentType);
    console.log("Content-Length:", env.payload.contentLength);
    console.log("Status:", env.payload.status);
    console.log("Duration:", env.payload.durationMs + "ms");
    console.log("Request Headers:", env.payload.requestHeaders);
    console.groupEnd();
  });

  // --- MSE init segment log ---
  bus.subscribe("ms:init_segment", (env) => {
    pushCollected(env);
    console.groupCollapsed(
      `%c[MSE:INIT] %c${formatBytes(env.payload.byteLength)} %c${env.payload.isoBoxes.map((b) => b.type).join(" → ") || "unknown"}`,
      "color: #ce93d8; font-weight: bold",
      "color: #ffb74d",
      "color: #90a4ae",
    );
    console.log("Byte Length:", env.payload.byteLength);
    console.log("Hex Preview:", env.payload.hexPreview);
    console.log("Truncated:", env.payload.hexPreviewTruncated);
    console.log("ISO Boxes:", env.payload.isoBoxes);
    console.groupEnd();
  });

  // --- WebRTC SDP log ---
  bus.subscribe("webrtc:local_description", (env) => {
    pushCollected(env);
    console.groupCollapsed(`%c[WebRTC:LOCAL] %c${env.payload.type}`, "color: #ef5350; font-weight: bold", "color: #ffb74d");
    console.log("SDP:\n", env.payload.sdp);
    console.groupEnd();
  });

  bus.subscribe("webrtc:remote_description", (env) => {
    pushCollected(env);
    console.groupCollapsed(`%c[WebRTC:REMOTE] %c${env.payload.type}`, "color: #ef5350; font-weight: bold", "color: #ffb74d");
    console.log("SDP:\n", env.payload.sdp);
    console.groupEnd();
  });

  // --- WebSocket log ---
  bus.subscribe("ws:connect", (env) => {
    pushCollected(env);
    console.groupCollapsed(`%c[WS:CONNECT] %c${truncate(env.payload.url, 80)}`, "color: #26c6da; font-weight: bold", "color: #90a4ae");
    console.log("URL:", env.payload.url);
    console.log("Protocols:", env.payload.protocols);
    console.groupEnd();
  });

  bus.subscribe("ws:message", (env) => {
    pushCollected(env);
    console.groupCollapsed(`%c[WS:MSG] %c${env.payload.dataType} %c${formatBytes(env.payload.byteLength)}`, "color: #26c6da; font-weight: bold", "color: #ffb74d", "color: #66bb6a");
    console.log("URL:", env.payload.url);
    console.log("Data Type:", env.payload.dataType);
    console.log("Byte Length:", env.payload.byteLength);
    console.log("Elapsed:", env.payload.elapsedMs + "ms");
    if (env.payload.hexPreview) {
      console.log("Hex Preview:", env.payload.hexPreview);
    }
    console.groupEnd();
  });

  // --- EME log ---
  bus.subscribe("eme:request_key_system", (env) => {
    pushCollected(env);
    console.groupCollapsed(`%c[EME:INIT] %c${env.payload.keySystem}`, "color: #ff7043; font-weight: bold", "color: #ffb74d");
    console.log("Key System:", env.payload.keySystem);
    console.log("Config Count:", env.payload.configCount);
    console.log("Configurations:", env.payload.configs);
    console.groupEnd();
  });

  bus.subscribe("eme:license_request", (env) => {
    pushCollected(env);
    console.groupCollapsed(`%c[EME:LICENSE_REQ] %c${env.payload.keySystem} %c${env.payload.initDataType}`, "color: #ff7043; font-weight: bold", "color: #ffb74d", "color: #90a4ae");
    console.log("Key System:", env.payload.keySystem);
    console.log("Init Data Type:", env.payload.initDataType);
    console.log("Init Data Length:", env.payload.initDataLength);
    console.log("Init Data (Base64):", env.payload.initDataB64);
    console.log("Init Data (Hex):", env.payload.initDataHex);
    if (env.payload.psshBoxes.length > 0) {
      console.table(
        env.payload.psshBoxes.map((b) => ({
          SystemID: b.systemId,
          DataSize: b.dataSize,
        })),
      );
      console.log(
        "PSSH Data (B64):",
        env.payload.psshBoxes.map((b) => b.dataB64),
      );
    }
    console.groupEnd();
  });

  bus.subscribe("eme:license_response", (env) => {
    pushCollected(env);
    const hasClearKey = env.payload.clearkeyMatrix && env.payload.clearkeyMatrix.length > 0;
    console.groupCollapsed(
      `%c[EME:LICENSE_RES] %c${env.payload.keySystem} %c${hasClearKey ? "ClearKey:" + env.payload.clearkeyMatrix.length + " keys" : "No ClearKey"} %c${formatBytes(env.payload.responseLength)}`,
      "color: #ff7043; font-weight: bold",
      "color: #ffb74d",
      hasClearKey ? "color: #66bb6a" : "color: #90a4ae",
      "color: #90a4ae",
    );
    console.log("Response Length:", env.payload.responseLength);
    console.log("Response (Base64):", env.payload.responseB64);
    console.log("Response (Hex):", env.payload.responseHex);
    if (hasClearKey) {
      console.group("ClearKey Matrix (kid:key pairs)");
      for (let i = 0; i < env.payload.clearkeyMatrix.length; i++) {
        const entry = env.payload.clearkeyMatrix[i];
        console.log(`  [${i}] kid: ${entry.kid}`, `\n      key: ${entry.key}`, `\n      type: ${entry.type}`);
      }
      console.groupEnd();
    }
    console.groupEnd();
  });

  // --- Utility functions ---
  function truncate(str, maxLen) {
    if (!str) {
      return "(empty)";
    }
    return str.length > maxLen ? str.slice(0, maxLen) + "..." : str;
  }

  function formatBytes(bytes) {
    if (bytes == null || isNaN(bytes)) {
      return "? B";
    }
    if (bytes === 0) {
      return "0 B";
    }
    const units = ["B", "KB", "MB", "GB"];
    const idx = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    return (bytes / Math.pow(1024, idx)).toFixed(idx > 0 ? 2 : 0) + " " + units[idx];
  }

  // --- Global report accessor ---
  Object.defineProperty(window, "__telemetryReport", {
    get() {
      const categories = {
        manifests: [],
        mediaStreams: [],
        mseInitSegments: [],
        webrtcSDP: [],
        websocketMessages: [],
        emeEvents: [],
      };
      for (const env of collectedEvents) {
        switch (env.eventType) {
          case "fetch:manifest":
          case "xhr:manifest":
            categories.manifests.push({
              url: env.payload.url,
              type: env.payload.type,
              status: env.payload.status,
              contentType: env.payload.contentType,
              timestamp: env.timestamp,
            });
            break;
          case "fetch:media_stream":
          case "xhr:media_stream":
            categories.mediaStreams.push({
              url: env.payload.url,
              mimeType: env.payload.contentType,
              timestamp: env.timestamp,
            });
            break;
          case "ms:init_segment":
            categories.mseInitSegments.push({
              byteLength: env.payload.byteLength,
              boxes: env.payload.isoBoxes,
              timestamp: env.timestamp,
            });
            break;
          case "webrtc:local_description":
          case "webrtc:remote_description":
            categories.webrtcSDP.push({
              type: env.payload.type,
              timestamp: env.timestamp,
            });
            break;
          case "ws:message":
            categories.websocketMessages.push({
              url: env.payload.url,
              dataType: env.payload.dataType,
              byteLength: env.payload.byteLength,
              timestamp: env.timestamp,
            });
            break;
          case "eme:request_key_system":
          case "eme:license_request":
          case "eme:license_response":
            categories.emeEvents.push({
              eventType: env.eventType,
              keySystem: env.payload.keySystem,
              timestamp: env.timestamp,
            });
            break;
        }
      }
      return {
        sessionId: bus.sessionId,
        totalEvents: collectedEvents.length,
        byCategory: categories,
        rawEvents: collectedEvents,
      };
    },
    configurable: false,
    enumerable: true,
  });

  // --- Console command ---
  console.info(
    "%c[Telemetry] Diagnostic suite active. Commands:\n" + "  %c__telemetryReport %c— print aggregated diagnostic summary\n" + "  %c__telemetryBus.subscriberCount(eventType) %c— query listener count",
    "font-weight: bold",
    "color: #4fc3f7; font-weight: bold",
    "",
    "color: #4fc3f7; font-weight: bold",
    "",
  );

  // Mark logger as installed on the bus object
  Object.defineProperty(bus, "__telemetry_logger_installed", {
    value: true,
    writable: false,
    configurable: false,
    enumerable: false,
  });
})();
