/**
 * Video DownloadHelper — PoC Media Interception Payload
 * ======================================================
 * Dual-detection strategy: API hooking (XHR/Fetch) + DOM observation + MSE monkeypatching.
 *
 * Usage: Paste entire script into DevTools Console.
 * Output: Structured console logging of all detected media streams.
 *
 * Non-destructive — preserves original API behavior via passthrough closures.
 * No external dependencies. Modern ES2022+. Isolated via IIFE.
 */

(() => {
  // ---------------------------------------------------------------------------
  // INTERNAL CAPTURE STORE — in-memory FIFO buffer for detected streams
  // ---------------------------------------------------------------------------

  const CAPTURE_STORE = [];
  const MAX_STORE_SIZE = 50;
  const SEEN_URLS = new Set();

  /** Deduplicated push with FIFO eviction */
  const pushCapture = (entry) => {
    const key = `${entry.url}|${entry.type}`;
    if (SEEN_URLS.has(key)) return;
    SEEN_URLS.add(key);
    if (CAPTURE_STORE.length >= MAX_STORE_SIZE) {
      const evicted = CAPTURE_STORE.shift();
      SEEN_URLS.delete(`${evicted.url}|${evicted.type}`);
    }
    CAPTURE_STORE.push(entry);
  };

  // ---------------------------------------------------------------------------
  // MEDIA URL CLASSIFICATION — MIME/signature matching engine
  // ---------------------------------------------------------------------------

  const MEDIA_PATTERNS = Object.freeze({
    HLS: {
      contentType: /^application\/(x-mpegURL|vnd\.apple\.mpegurl)/i,
      url:          /\.m3u8(\?|$)/i,
      label:        'HLS (m3u8)',
    },
    DASH: {
      contentType: /^application\/(dash\+xml|mpd)/i,
      url:          /\.mpd(\?|$)/i,
      label:        'DASH (mpd)',
    },
    PROGRESSIVE_MP4: {
      contentType: /^video\/mp4/i,
      url:          /\.mp4(\?|$)/i,
      label:        'MP4 (progressive)',
    },
    PROGRESSIVE_WEBM: {
      contentType: /^video\/webm/i,
      url:          /\.webm(\?|$)/i,
      label:        'WebM (progressive)',
    },
    AUDIO_MP4: {
      contentType: /^audio\/mp4/i,
      url:          /\.m4a(\?|$)/i,
      label:        'MP4 Audio',
    },
    AUDIO_WEBM: {
      contentType: /^audio\/webm/i,
      url:          /\.weba(\?|$)/i,
      label:        'WebM Audio',
    },
    GENERIC_VIDEO: {
      contentType: /^video\//i,
      url:          null,
      label:        'Generic Video',
    },
    GENERIC_AUDIO: {
      contentType: /^audio\//i,
      url:          null,
      label:        'Generic Audio',
    },
  });

  /**
   * Classify a URL and optional Content-Type into a media type descriptor.
   * @returns {{ type: string, label: string } | null}
   */
  const classifyMedia = (url, contentType) => {
    for (const [typeKey, { contentType: ctRe, url: urlRe, label }] of Object.entries(MEDIA_PATTERNS)) {
      const ctMatch  = ctRe && contentType && ctRe.test(contentType);
      const urlMatch = urlRe && urlRe.test(url);
      if (ctMatch || urlMatch) return { type: typeKey, label };
    }
    return null;
  };

  // ---------------------------------------------------------------------------
  // HEADER EXTRACTION — capture auth tokens, cookies, signing headers
  // ---------------------------------------------------------------------------

  /**
   * Extract security-relevant headers for replay.
   * These are likely needed to re-fetch the stream outside the browser.
   */
  const extractAuthHeaders = (headers) => {
    const authHeaders = {};
    const relevantKeys = [
      'authorization', 'cookie', 'x-csrf-token', 'x-api-key',
      'x-client-id', 'x-session-id', 'x-signature', 'x-token',
      'x-auth-token', 'x-meta-tk', 'x-requested-with', 'origin',
      'referer', 'user-agent',
    ];

    if (headers instanceof Headers) {
      for (const key of relevantKeys) {
        const val = headers.get(key);
        if (val) authHeaders[key] = val;
      }
    } else if (typeof headers === 'object' && headers !== null) {
      for (const key of relevantKeys) {
        if (headers[key]) authHeaders[key] = headers[key];
      }
    }

    return authHeaders;
  };

  // ---------------------------------------------------------------------------
  // CAPTURE PIPELINE — log detected media to private store and console
  // ---------------------------------------------------------------------------

  let captureCounter = 0;

  const captureMedia = (url, contentType, headers, method, timestamp, source) => {
    const mediaType = classifyMedia(url, contentType);
    if (!mediaType) return;

    const entry = {
      id:           ++captureCounter,
      url,
      type:         mediaType.type,
      label:        mediaType.label,
      contentType:  contentType || 'unknown',
      method:       method || 'GET',
      headers:      extractAuthHeaders(headers),
      timestamp:    timestamp || Date.now(),
      source,
      origin:       window.location.origin,
      pageUrl:      window.location.href,
    };

    pushCapture(entry);
    emitConsoleGroup(entry);
  };

  // ---------------------------------------------------------------------------
  // CONSOLE OUTPUT — structured, color-coded display groups
  // ---------------------------------------------------------------------------

  const COLORS = {
    HLS:              '#FF6B35',
    DASH:             '#6C63FF',
    PROGRESSIVE_MP4:  '#00C853',
    PROGRESSIVE_WEBM: '#00E5FF',
    AUDIO_MP4:        '#FFD600',
    AUDIO_WEBM:       '#FF9100',
    GENERIC_VIDEO:    '#9E9E9E',
    GENERIC_AUDIO:    '#795548',
    MSE_INIT:         '#E91E63',
    DOM_DETECT:       '#26C6DA',
  };

  const emitConsoleGroup = (entry) => {
    const color = COLORS[entry.type] || '#FFF';
    const timeStr = new Date(entry.timestamp).toLocaleTimeString();

    console.groupCollapsed(
      `%c▶ [${entry.id}] %c${entry.label}%c @ ${timeStr}`,
      `color: ${color}; font-weight: bold;`,
      `color: ${color}; font-size: 1.1em; font-weight: bold;`,
      `color: #888;`
    );

    console.log('%c URL:%c',          'font-weight: bold; color: #FFF;', entry.url);
    console.log('%c Method:%c',        'font-weight: bold; color: #FFF;', entry.method);
    console.log('%c Content-Type:%c',  'font-weight: bold; color: #FFF;', entry.contentType);
    console.log('%c Source:%c',        'font-weight: bold; color: #FFF;', entry.source);
    console.log('%c Page:%c',          'font-weight: bold; color: #FFF;', entry.pageUrl);

    if (Object.keys(entry.headers).length > 0) {
      console.group('%c Auth Headers (for replay):', 'font-weight: bold; color: #FF6B35;');
      for (const [k, v] of Object.entries(entry.headers)) {
        console.log(`%c ${k}:%c`, 'font-weight: bold;', v);
      }
      console.groupEnd();
    }

    console.log(
      '%c To copy URL:%c',
      'font-weight: bold;',
      `\n   copy(VHSHELPER_CAPTURES[${entry.id - 1}].url)\n`
    );

    console.groupEnd();
  };

  // ---------------------------------------------------------------------------
  // EXPORT API — attach to window for programmatic access
  // ---------------------------------------------------------------------------

  const exportAPI = () => {
    /** @type {{ id: number, url: string, type: string, label: string, contentType: string, headers: Record<string,string>, timestamp: number, source: string, pageUrl: string }[]} */
    Object.defineProperty(window, 'VHSHELPER_CAPTURES', {
      get: () => [...CAPTURE_STORE],
      configurable: false,
    });

    /** Dump all captures as a JSON download */
    window.VHSHELPER_DUMP = () => {
      const blob = new Blob([JSON.stringify(CAPTURE_STORE, null, 2)], { type: 'application/json' });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href     = url;
      a.download = `vdh_captures_${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
      console.log(`%c Exported ${CAPTURE_STORE.length} captures.`, 'color: #00C853; font-weight: bold;');
    };

    /** Clear capture store */
    window.VHSHELPER_CLEAR = () => {
      CAPTURE_STORE.length = 0;
      SEEN_URLS.clear();
      captureCounter = 0;
      console.log('%c Capture store cleared.', 'color: #E91E63;');
    };
  };

  // ===========================================================================
  // A. API HOOKING LAYER — XHR / Fetch Interception
  // ===========================================================================

  /**
   * Monkeypatch window.fetch — transparently intercept all fetch() calls.
   * Scans URL and response Content-Type for media signatures.
   * Original behavior is preserved; errors are caught silently.
   */
  (() => {
    const _fetch = window.fetch;

    window.fetch = async function patchedFetch(input, init = {}) {
      const url = typeof input === 'string' ? input : (input instanceof Request ? input.url : input?.href || '');
      const method = (init.method || (input instanceof Request ? input.method : 'GET') || 'GET').toUpperCase();

      let response;
      try {
        response = await _fetch.call(this, input, init);
      } catch (_err) {
        // Passthrough — do not alter behavior on network errors
        return _fetch.call(this, input, init);
      }

      // Only intercept successful responses
      if (!response || !response.ok) return response;

      const contentType = response.headers.get('content-type') || '';

      // Test URL classification first (pre-response), then Content-Type classification
      if (classifyMedia(url, contentType)) {
        captureMedia(url, contentType, init.headers || (input instanceof Request ? input.headers : {}), method, Date.now(), 'fetch()');
      }

      // Preserve stream consumption — clone response so the page can still read the body
      return response;
    };

    console.log('%c [VDH-PoC] fetch() hook installed.', 'color: #6C63FF;');
  })();

  /**
   * Monkeypatch XMLHttpRequest.prototype.open — transparently intercept all XHR calls.
   * We hook `open` to capture the URL and method, then proxy `send` to capture headers.
   * The `onreadystatechange` / `load` event chain is then wired to check the response.
   */
  (() => {
    const OrigXHR = window.XMLHttpRequest;
    const origOpen = OrigXHR.prototype.open;
    const origSend = OrigXHR.prototype.send;
    const origSetRequestHeader = OrigXHR.prototype.setRequestHeader;

    OrigXHR.prototype.open = function patchedOpen(method, url, async = true, user, password) {
      /** @type {{ url: string, method: string }} */
      this.__vdh_meta = { url: String(url || ''), method: String(method || 'GET').toUpperCase() };
      return origOpen.call(this, method, url, async, user, password);
    };

    OrigXHR.prototype.setRequestHeader = function patchedSetRequestHeader(name, value) {
      if (!this.__vdh_headers) this.__vdh_headers = {};
      this.__vdh_headers[name.toLowerCase()] = value;
      return origSetRequestHeader.call(this, name, value);
    };

    OrigXHR.prototype.send = function patchedSend(body) {
      const meta = this.__vdh_meta;
      if (!meta) return origSend.call(this, body);

      const url     = meta.url;
      const method  = meta.method;
      const headers = this.__vdh_headers || {};

      // Wire up response detection after load
      this.addEventListener('load', function onLoad() {
        try {
          const ct = this.getResponseHeader('content-type') || this.getResponseHeader('Content-Type') || '';

          if (classifyMedia(url, ct)) {
            // Reconstruct full header map from response
            const responseHeaders = {};
            const allHeaders = this.getAllResponseHeaders();
            if (allHeaders) {
              for (const line of allHeaders.trim().split(/[\r\n]+/)) {
                const [k, ...v] = line.split(': ');
                if (k) responseHeaders[k.toLowerCase()] = v.join(': ');
              }
            }

            captureMedia(url, ct, { ...headers, ...responseHeaders }, method, Date.now(), 'XMLHttpRequest');
          }
        } catch (_err) {
          // Silently ignore errors in detection — do not break the page
        }
      });

      return origSend.call(this, body);
    };

    console.log('%c [VDH-PoC] XMLHttpRequest hook installed.', 'color: #6C63FF;');
  })();

  // ===========================================================================
  // B. DOM MUTATION & MEDIA SOURCE EXTENSION (MSE) INTERCEPTION
  // ===========================================================================

  /**
   * MutationObserver — detect dynamically injected <video> and <source> elements.
   * Captures src attributes before playback begins, catching late-loaded players.
   */
  (() => {
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node.nodeType !== Node.ELEMENT_NODE) continue;

          // Direct <video> insertion
          if (node.tagName === 'VIDEO' && node.src) {
            captureMedia(node.src, null, {}, 'GET', Date.now(), 'DOM MutationObserver (video)');
            continue;
          }
          if (node.tagName === 'SOURCE' && node.src) {
            captureMedia(node.src, node.type || null, {}, 'GET', Date.now(), 'DOM MutationObserver (source)');
            continue;
          }

          // Deep scan — <video> + nested <source>
          if (typeof node.querySelectorAll === 'function') {
            for (const video of node.querySelectorAll('video[src]')) {
              captureMedia(video.src, null, {}, 'GET', Date.now(), 'DOM MutationObserver (nested video)');
            }
            for (const source of node.querySelectorAll('source[src]')) {
              captureMedia(source.src, source.type || null, {}, 'GET', Date.now(), 'DOM MutationObserver (nested source)');
            }
          }
        }

        // Handle attribute changes on existing elements
        if (mutation.type === 'attributes' && mutation.attributeName === 'src') {
          const el = mutation.target;
          if (el.tagName === 'VIDEO' || el.tagName === 'SOURCE') {
            const newSrc = el.getAttribute('src');
            if (newSrc) {
              captureMedia(newSrc, el.type || null, {}, 'GET', Date.now(), 'DOM MutationObserver (src attr change)');
            }
          }
        }
      }
    });

    observer.observe(document.documentElement, {
      childList:     true,
      subtree:       true,
      attributes:    true,
      attributeFilter: ['src'],
    });

    // Scan existing elements on page load
    for (const video of document.querySelectorAll('video[src]')) {
      captureMedia(video.src, null, {}, 'GET', Date.now(), 'DOM Scanner (existing video)');
    }
    for (const source of document.querySelectorAll('source[src]')) {
      captureMedia(source.src, source.type || null, {}, 'GET', Date.now(), 'DOM Scanner (existing source)');
    }

    console.log('%c [VDH-PoC] MutationObserver installed.', 'color: #00C853;');
  })();

  /**
   * Monkeypatch MediaSource.prototype.addSourceBuffer — intercept MSE pipeline.
   * Captures init segments, codec strings, and MIME configuration.
   * This reveals media type information BEFORE network requests fire.
   */
  (() => {
    if (typeof MediaSource === 'undefined' || !MediaSource.prototype.addSourceBuffer) {
      console.log('%c [VDH-PoC] MediaSource API not available in this context.', 'color: #FFD600;');
      return;
    }

    const origAddSourceBuffer = MediaSource.prototype.addSourceBuffer;

    MediaSource.prototype.addSourceBuffer = function patchedAddSourceBuffer(mimeType) {
      console.groupCollapsed(`%c▶ MSE addSourceBuffer: %c${mimeType}`, 'color: #E91E63; font-weight: bold;', 'color: #FFF;');

      // Parse codec string if available
      const codecMatch = mimeType.match(/codecs="([^"]+)"/);
      if (codecMatch) {
        const codecs = codecMatch[1].split(',');
        console.log('%c Codecs:%c', 'font-weight: bold;', codecs.join(', '));
      }

      console.log('%c MIME Type:%c', 'font-weight: bold;', mimeType);
      console.log('%c URL (MediaSource):%c', 'font-weight: bold;', this.sourceURL || '(not set)');
      console.log('%c Ready State:%c', 'font-weight: bold;', this.readyState);
      console.log('%c Duration:%c', 'font-weight: bold;', this.duration);
      console.groupEnd();

      /**
       * Register an MSE init segment capture.
       * Init segments contain the codec configuration data critical for
       * reconstructing valid media files from individual appended buffers.
       */
      const entry = {
        id:           ++captureCounter,
        url:          this.sourceURL || window.location.href,
        type:         'MSE_INIT',
        label:        `MSE SourceBuffer (${mimeType})`,
        contentType:  mimeType,
        method:       'MSE',
        headers:      {},
        timestamp:    Date.now(),
        source:       'MediaSource.addSourceBuffer',
        origin:       window.location.origin,
        pageUrl:      window.location.href,
      };

      pushCapture(entry);
      emitConsoleGroup(entry);

      return origAddSourceBuffer.call(this, mimeType);
    };

    console.log('%c [VDH-PoC] MediaSource.addSourceBuffer hook installed.', 'color: #E91E63;');
  })();

  // ===========================================================================
  // C. INITIALIZATION — export API, report status
  // ===========================================================================

  exportAPI();

  console.log(
    `\n%c╔══════════════════════════════════════════════════════════╗
%c║ %cVDH PoC Media Interception Payload — ACTIVE %c            ║
%c║ %cAPI: Fetch(), XHR, MutationObserver, MSE addSourceBuffer ║
%c║ %cExports: VHSHELPER_CAPTURES, VHSHELPER_DUMP(), VHSHELPER_CLEAR() ║
%c╚══════════════════════════════════════════════════════════╝\n`,
    'color: #FF6B35;',
    'color: #FF6B35;',
    'color: #00C853; font-weight: bold;',
    'color: #FFF;',
    'color: #FF6B35;',
    'color: #FFF;',
    'color: #FF6B35;',
    'color: #FF6B35;',
  );
})();
