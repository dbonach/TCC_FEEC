"""
Sondas JavaScript para coleta de atributos de fingerprint.

Separadas do runner para poderem ser evoluídas e também coladas
manualmente no console do Firefox (configuração A, linha de base).
"""

# ---------------------------------------------------------------------------
# Atributos estáticos: navigator, tela, WebGL, canvas, áudio, fontes.
# Síncrono exceto pelo AudioContext, que usa OfflineAudioContext.
# ---------------------------------------------------------------------------
STATIC_PROBE = r"""
async () => {
  const out = {};
  const safe = (label, fn) => {
    try { return fn(); } catch (e) { return { __error: String(e), __at: label }; }
  };

  // ---- navigator -------------------------------------------------------
  out.navigator = safe('navigator', () => ({
    userAgent: navigator.userAgent,
    appVersion: navigator.appVersion,
    platform: navigator.platform,
    oscpu: navigator.oscpu ?? null,
    vendor: navigator.vendor,
    product: navigator.product,
    language: navigator.language,
    languages: [...(navigator.languages || [])],
    hardwareConcurrency: navigator.hardwareConcurrency ?? null,
    deviceMemory: navigator.deviceMemory ?? null,
    maxTouchPoints: navigator.maxTouchPoints ?? null,
    webdriver: navigator.webdriver ?? null,
    pdfViewerEnabled: navigator.pdfViewerEnabled ?? null,
    cookieEnabled: navigator.cookieEnabled,
    doNotTrack: navigator.doNotTrack,
    plugins: Array.from(navigator.plugins || []).map(p => ({
      name: p.name, filename: p.filename, description: p.description
    })),
    mimeTypes: Array.from(navigator.mimeTypes || []).map(m => m.type),
  }));

  // ---- tela e viewport -------------------------------------------------
  out.screen = safe('screen', () => ({
    width: screen.width,
    height: screen.height,
    availWidth: screen.availWidth,
    availHeight: screen.availHeight,
    availLeft: screen.availLeft ?? null,
    availTop: screen.availTop ?? null,
    colorDepth: screen.colorDepth,
    pixelDepth: screen.pixelDepth,
    orientation: screen.orientation ? screen.orientation.type : null,
    innerWidth: window.innerWidth,
    innerHeight: window.innerHeight,
    outerWidth: window.outerWidth,
    outerHeight: window.outerHeight,
    devicePixelRatio: window.devicePixelRatio,
  }));

  // matchMedia precisa concordar com screen.width — par de consistência
  out.matchMedia = safe('matchMedia', () => {
    const probes = {};
    for (const w of [360, 768, 1024, 1280, 1440, 1680, 1920, 2560, 3440]) {
      probes['min-width-' + w] = matchMedia(`(min-width: ${w}px)`).matches;
    }
    for (const r of [1, 1.5, 2, 3]) {
      probes['dpr-' + r] = matchMedia(`(resolution: ${r}dppx)`).matches;
    }
    probes['pointer-fine'] = matchMedia('(pointer: fine)').matches;
    probes['pointer-coarse'] = matchMedia('(pointer: coarse)').matches;
    probes['hover-hover'] = matchMedia('(hover: hover)').matches;
    probes['prefers-color-scheme-dark'] =
      matchMedia('(prefers-color-scheme: dark)').matches;
    return probes;
  });

  // ---- tempo e locale --------------------------------------------------
  out.locale = safe('locale', () => {
    const r = Intl.DateTimeFormat().resolvedOptions();
    return {
      timeZone: r.timeZone,
      locale: r.locale,
      calendar: r.calendar,
      numberingSystem: r.numberingSystem,
      timezoneOffsetMinutes: new Date().getTimezoneOffset(),
      dateString: new Date(0).toString(),
    };
  });

  // ---- WebGL -----------------------------------------------------------
  out.webgl = safe('webgl', () => {
    const c = document.createElement('canvas');
    const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
    if (!gl) return null;
    // Firefox descontinuou WEBGL_debug_renderer_info e expõe o valor real
    // em RENDERER. Coletamos os dois: a divergência entre eles é, ela
    // própria, um par de consistência.
    let dbg = null;
    try { dbg = gl.getExtension('WEBGL_debug_renderer_info'); } catch (e) {}
    const unmaskedVendor = dbg
      ? (() => { try { return gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL); }
                 catch (e) { return null; } })() : null;
    const unmaskedRenderer = dbg
      ? (() => { try { return gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL); }
                 catch (e) { return null; } })() : null;
    return {
      vendor: gl.getParameter(gl.VENDOR),
      renderer: gl.getParameter(gl.RENDERER),
      unmaskedVendor,
      unmaskedRenderer,
      debugExtensionAvailable: !!dbg,
      rendererMismatch: !!(unmaskedRenderer &&
        unmaskedRenderer !== gl.getParameter(gl.RENDERER)),
      version: gl.getParameter(gl.VERSION),
      shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
      maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
      maxViewportDims: Array.from(gl.getParameter(gl.MAX_VIEWPORT_DIMS) || []),
      maxRenderbufferSize: gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
      extensions: (gl.getSupportedExtensions() || []).slice().sort(),
    };
  });

  // ---- canvas ----------------------------------------------------------
  out.canvas = safe('canvas', () => {
    const c = document.createElement('canvas');
    c.width = 280; c.height = 60;
    const ctx = c.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillStyle = '#f60';
    ctx.fillRect(5, 5, 120, 20);
    ctx.fillStyle = '#069';
    ctx.fillText('Camoufox TCC 1234 \u00e7\u00e3\u00f5', 10, 10);
    ctx.fillStyle = 'rgba(102,204,0,0.7)';
    ctx.fillText('Camoufox TCC 1234 \u00e7\u00e3\u00f5', 12, 24);
    ctx.globalCompositeOperation = 'multiply';
    ctx.beginPath(); ctx.arc(60, 40, 18, 0, Math.PI * 2); ctx.fill();
    const data = c.toDataURL();
    let h = 0;
    for (let i = 0; i < data.length; i++) {
      h = ((h << 5) - h + data.charCodeAt(i)) | 0;
    }
    return { hash: (h >>> 0).toString(16), length: data.length };
  });

  // ---- fontes ----------------------------------------------------------
  // Mede a largura de um texto em cada fonte candidata contra as fontes
  // genéricas. Diferença de largura = fonte presente no sistema.
  out.fonts = safe('fonts', () => {
    const CANDIDATES = [
      // Windows
      'Calibri', 'Cambria', 'Candara', 'Consolas', 'Constantia', 'Corbel',
      'Franklin Gothic Medium', 'Gabriola', 'Lucida Console', 'MS Gothic',
      'MV Boli', 'Segoe UI', 'Segoe Print', 'Sylfaen', 'Tahoma',
      // macOS
      'American Typewriter', 'Avenir', 'Chalkboard', 'Cochin', 'Didot',
      'Futura', 'Geneva', 'Helvetica Neue', 'Hoefler Text', 'Menlo',
      'Monaco', 'Optima', 'Papyrus', 'SF Pro Text', 'Skia',
      // Linux
      'Bitstream Vera Sans', 'Cantarell', 'DejaVu Sans', 'DejaVu Serif',
      'DejaVu Sans Mono', 'FreeMono', 'FreeSans', 'Liberation Mono',
      'Liberation Sans', 'Liberation Serif', 'Nimbus Roman', 'Ubuntu',
      // multiplataforma
      'Arial', 'Courier New', 'Georgia', 'Times New Roman', 'Verdana',
      'Trebuchet MS', 'Impact', 'Comic Sans MS',
    ];
    const BASE = ['monospace', 'sans-serif', 'serif'];
    const TEXT = 'mmmmmmmmmmlli WwMm 0123';
    const SIZE = '72px';

    // A medição ocorre dentro de um iframe em branco, não no documento
    // da página. Motivo: páginas que carregam fontes próprias ou aplicam
    // CSS herdado (letter-spacing, font-feature-settings, suavização)
    // deslocam a largura de referência, e TODAS as candidatas passam a
    // diferir da base — o resultado vira 100% de falsos positivos.
    // Observado empiricamente no CreepJS: 50 de 50 fontes "detectadas"
    // na mesma máquina em que about:blank detecta 23.
    let doc = document;
    let frame = null;
    let isolado = false;
    try {
      frame = document.createElement('iframe');
      frame.style.cssText =
        'position:absolute;left:-9999px;top:-9999px;width:50px;height:50px;' +
        'border:0;visibility:hidden;';
      frame.setAttribute('aria-hidden', 'true');
      document.documentElement.appendChild(frame);
      if (frame.contentDocument && frame.contentDocument.body) {
        doc = frame.contentDocument;
        isolado = true;
      }
    } catch (e) { /* CSP pode bloquear; cai no documento principal */ }

    const span = doc.createElement('span');
    // all:initial descarta qualquer herança de estilo remanescente,
    // necessário no caminho de fallback sem iframe.
    span.style.cssText =
      'all:initial;position:absolute;left:-9999px;top:-9999px;' +
      'visibility:hidden;white-space:nowrap;font-size:' + SIZE + ';';
    span.textContent = TEXT;
    doc.body.appendChild(span);

    const baseline = {};
    for (const b of BASE) {
      span.style.fontFamily = b;
      baseline[b] = { w: span.offsetWidth, h: span.offsetHeight };
    }

    const detected = [];
    for (const f of CANDIDATES) {
      let present = false;
      for (const b of BASE) {
        span.style.fontFamily = `'${f}',${b}`;
        if (span.offsetWidth !== baseline[b].w ||
            span.offsetHeight !== baseline[b].h) {
          present = true;
          break;
        }
      }
      if (present) detected.push(f);
    }

    span.remove();
    if (frame) frame.remove();

    // Se TODAS as candidatas forem detectadas, é quase certo que a
    // medição foi contaminada: nenhum sistema real traz as fontes
    // exclusivas de Windows, macOS e Linux ao mesmo tempo.
    const suspeito = detected.length === CANDIDATES.length;

    return {
      detected,
      total: CANDIDATES.length,
      count: detected.length,
      isolatedFrame: isolado,
      suspectContamination: suspeito,
    };
  });

  // ---- vozes de síntese de fala ---------------------------------------
  // Específicas por SO. Par de consistência com userAgent.
  out.voices = await safe('voices', async () => {
    const read = () => speechSynthesis.getVoices().map(v => ({
      name: v.name, lang: v.lang, localService: v.localService,
      default: v.default,
    }));
    let v = read();
    if (v.length === 0) {
      await new Promise(r => {
        const t = setTimeout(r, 1500);
        speechSynthesis.onvoiceschanged = () => { clearTimeout(t); r(); };
      });
      v = read();
    }
    return v;
  });

  // ---- AudioContext ----------------------------------------------------
  out.audio = await safe('audio', async () => {
    const ctx = new (window.OfflineAudioContext ||
                     window.webkitOfflineAudioContext)(1, 44100, 44100);
    const osc = ctx.createOscillator();
    osc.type = 'triangle';
    osc.frequency.setValueAtTime(10000, ctx.currentTime);
    const comp = ctx.createDynamicsCompressor();
    comp.threshold.setValueAtTime(-50, ctx.currentTime);
    comp.knee.setValueAtTime(40, ctx.currentTime);
    comp.ratio.setValueAtTime(12, ctx.currentTime);
    comp.attack.setValueAtTime(0, ctx.currentTime);
    comp.release.setValueAtTime(0.25, ctx.currentTime);
    osc.connect(comp); comp.connect(ctx.destination);
    osc.start(0);
    const buf = await ctx.startRendering();
    const ch = buf.getChannelData(0);
    let sum = 0;
    for (let i = 4500; i < 5000; i++) sum += Math.abs(ch[i]);
    return { sum: sum.toFixed(10), sampleRate: buf.sampleRate };
  });

  // ---- sinais de automação --------------------------------------------
  out.automation = safe('automation', () => {
    const keys = Object.keys(window).filter(k =>
      /^(_|\$)?(sel|web|p[hu]|cdc|dom)[a-z_]*/i.test(k) &&
      /driver|selenium|puppeteer|playwright|cdc_|phantom|nightmare/i.test(k)
    );
    return {
      suspiciousWindowKeys: keys,
      hasChromeObject: 'chrome' in window,
      permissionsQueryType: typeof navigator.permissions?.query,
      notificationPermission: typeof Notification !== 'undefined'
        ? Notification.permission : null,
      errorStackSample: (() => {
        try { null.f(); } catch (e) { return (e.stack || '').split('\n')[0]; }
      })(),
      functionToString: Function.prototype.toString.call(
        navigator.permissions?.query ?? function () {}),
    };
  });

  return out;
}
"""

# ---------------------------------------------------------------------------
# Sonda de WebRTC. Assíncrona: precisa esperar a coleta de candidatos ICE.
# É aqui que mora o vetor mais interessante do trabalho.
# ---------------------------------------------------------------------------
WEBRTC_PROBE = r"""
async (stunUrls) => {
  const out = { candidates: [], ips: { host: [], srflx: [], relay: [] } };

  // dispositivos de mídia: contêiner headless costuma ter zero.
  // navigator.mediaDevices só existe em contexto seguro (HTTPS); em
  // about:blank fica indefinido, então a ausência aqui NÃO é sinal de bot.
  out.secureContext = typeof isSecureContext !== 'undefined'
    ? isSecureContext : null;
  out.mediaDevicesAvailable = !!(navigator.mediaDevices &&
                                 navigator.mediaDevices.enumerateDevices);
  try {
    if (!out.mediaDevicesAvailable) {
      throw new Error('mediaDevices indisponível (contexto não seguro?)');
    }
    const devs = await navigator.mediaDevices.enumerateDevices();
    out.devices = devs.map(d => ({
      kind: d.kind,
      hasLabel: !!d.label,
      deviceId: d.deviceId ? d.deviceId.slice(0, 12) : null,
    }));
    out.deviceCounts = out.devices.reduce((a, d) => {
      a[d.kind] = (a[d.kind] || 0) + 1; return a;
    }, {});
  } catch (e) {
    out.devices = { __error: String(e) };
  }

  // capacidades de codec: alta entropia, raramente falsificado
  try {
    out.capabilities = {
      audio: RTCRtpSender.getCapabilities('audio'),
      video: RTCRtpSender.getCapabilities('video'),
    };
  } catch (e) {
    out.capabilities = { __error: String(e) };
  }

  // coleta de candidatos ICE
  try {
    const pc = new RTCPeerConnection({
      iceServers: [{ urls: stunUrls }],
      iceCandidatePoolSize: 1,
    });
    pc.createDataChannel('probe');

    const done = new Promise(resolve => {
      const finish = () => resolve();
      pc.onicegatheringstatechange = () => {
        if (pc.iceGatheringState === 'complete') finish();
      };
      pc.onicecandidate = ev => {
        if (!ev.candidate) { finish(); return; }
        const c = ev.candidate;
        if (!c.candidate) return;   // candidato vazio marca fim da coleta
        out.candidates.push({
          candidate: c.candidate,
          type: c.type,
          protocol: c.protocol,
          address: c.address,
          port: c.port,
          relatedAddress: c.relatedAddress,
          foundation: c.foundation,
        });
        // Formato SDP (RFC 5245):
        //   candidate:<foundation> <component> <transport> <priority>
        //             <address> <port> typ <type> ...
        // Extrair por posição, nunca por regex solta: o campo <priority>
        // é um número longo que casa com padrões de IP e vem ANTES do
        // endereço, então uma regex gananciosa captura a prioridade.
        const parts = c.candidate.split(/\s+/);
        const typIdx = parts.indexOf('typ');
        const type = c.type || (typIdx > -1 ? parts[typIdx + 1] : null);
        const address = c.address || (parts.length > 4 ? parts[4] : null);
        if (type && address && out.ips[type] &&
            !out.ips[type].includes(address)) {
          out.ips[type].push(address);
        }
      };
      setTimeout(finish, 8000);
    });

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    out.sdpOffer = offer.sdp;
    // A linha o= do SDP identifica o MOTOR, não a versão útil: a Mozilla
    // congelou a versão em 99.0 para todos os Firefox desde ~2022, então
    // comparar versões gera falso positivo. O que discrimina é o motor:
    // um navegador que se declara Chrome mas emite SDP no formato do
    // Gecko está mentindo numa camada que o JavaScript não controla.
    const vm = offer.sdp.match(/THIS_IS_SDPARTA-([\d.]+)/);
    out.sdpBrowserVersion = vm ? vm[1] : null;
    out.sdpVersionIsFrozenDefault = out.sdpBrowserVersion === '99.0';

    out.sdpEngine = /THIS_IS_SDPARTA/.test(offer.sdp) ? 'gecko'
                  : /^o=- \d+ \d+ IN IP4 127\.0\.0\.1/m.test(offer.sdp) ? 'webrtc-chromium'
                  : 'desconhecido';
    const ua = navigator.userAgent;
    out.uaEngine = /Firefox\//.test(ua) ? 'gecko'
                 : /Chrome\/|Chromium\//.test(ua) ? 'webrtc-chromium'
                 : /Safari\//.test(ua) ? 'webkit'
                 : 'desconhecido';
    out.sdpEngineMismatch = out.sdpEngine !== 'desconhecido' &&
      out.uaEngine !== 'desconhecido' && out.sdpEngine !== out.uaEngine;

    // Assinaturas estruturais do SDP que variam entre motores e versões,
    // úteis mesmo sem a versão explícita.
    out.sdpShape = {
      hasIceOptionsTrickle: /a=ice-options:trickle/.test(offer.sdp),
      maxMessageSize: (offer.sdp.match(/a=max-message-size:(\d+)/) || [])[1] || null,
      sctpPort: (offer.sdp.match(/a=sctp-port:(\d+)/) || [])[1] || null,
      fingerprintAlgo: (offer.sdp.match(/a=fingerprint:(\S+)/) || [])[1] || null,
      msidSemantic: /a=msid-semantic:WMS \*/.test(offer.sdp),
    };
    await done;
    out.gatheringState = pc.iceGatheringState;
    pc.close();
  } catch (e) {
    out.iceError = String(e);
  }

  // ---- indicadores derivados -------------------------------------------
  const isMdns = a => /\.local$/i.test(a);
  const isPrivateV4 = a =>
    /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(a);
  const isPrivateV6 = a => /^(fe80:|fc|fd|::1$)/i.test(a);

  // mDNS: navegadores modernos trocam o IP local por hostname .local.
  // Se TODOS os candidatos host estão obfuscados, não houve vazamento local.
  out.mdnsObfuscated = out.ips.host.length > 0 &&
    out.ips.host.every(isMdns);
  out.leakedPrivateIp = out.ips.host.some(
    a => !isMdns(a) && (isPrivateV4(a) || isPrivateV6(a)));

  // srflx é o endereço visto pelo servidor STUN: o IP público de saída.
  // Com proxy no caminho, ele DEVERIA ser o IP do proxy. Comparar com o
  // IP de saída HTTP é o teste central do vetor de WebRTC.
  out.publicIps = out.ips.srflx.filter(
    a => !isMdns(a) && !isPrivateV4(a) && !isPrivateV6(a));
  out.publicIpv4 = out.publicIps.filter(a => a.includes('.'));
  out.publicIpv6 = out.publicIps.filter(a => a.includes(':'));
  // IPv6 merece destaque: costuma ser estável e derivado da interface,
  // portanto mais identificador que o IPv4, e proxies HTTP raramente o cobrem.
  out.ipv6Exposed = out.publicIpv6.length > 0;

  return out;
}
"""
