#!/usr/bin/env python3
"""
Coletor de fingerprints para o TCC — EA019.

Executa as sondas de fp_probes.py em diferentes configurações de navegador
e grava o resultado em JSON, uma execução por arquivo.

Uso:
    python collect.py --config B --runs 3
    python collect.py --config C --runs 10 --pages creepjs sannysoft
    python collect.py --config D --proxy http://user:pass@host:porta
    python collect.py --dump-js        # imprime a sonda para colar no console

Configurações:
    A  Firefox padrão, manual        -> use --dump-js e cole no console
    B  Playwright + Firefox          -> piso, sem ocultação
    C  Camoufox padrão               -> objeto de estudo
    D  Camoufox + proxy + geoip      -> cenário real, habilita teste de WebRTC
"""

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fp_probes import STATIC_PROBE, WEBRTC_PROBE

OUT_DIR = Path('data')

# Páginas públicas de autoteste. Criadas para serem testadas — não são
# sites de produção de terceiros.
PAGES = {
    'blank':      'about:blank',
    'creepjs':    'https://abrahamjuliot.github.io/creepjs/',
    'sannysoft':  'https://bot.sannysoft.com/',
    'browserscan': 'https://www.browserscan.net/',
    'rebrowser':  'https://bot-detector.rebrowser.net/',
    'pixelscan':  'https://pixelscan.net/',
    # Camada de rede: devolvem JSON com o fingerprint que o SERVIDOR
    # observou (TLS e HTTP/2). Não passa por JavaScript, então mede algo
    # que a sonda não alcança — e permite o par cruzado mais forte depois
    # do WebRTC: o JA4 corresponde ao SO declarado no user-agent?
    'tls_peet':   'https://tls.peet.ws/api/all',
    'tls_leaks':  'https://tls.browserleaks.com/json',
}

# Páginas que são API: o conteúdo útil é o corpo da resposta, não o DOM.
JSON_ENDPOINTS = {'tls_peet', 'tls_leaks'}

STUN_URLS = [
    'stun:stun.l.google.com:19302',
    'stun:stun1.l.google.com:19302',
]

# Páginas que podem travar. A issue #627 do repositório relata que a coleta
# do CreepJS nunca completa em alguns contextos. Timeout generoso e seguir.
PAGE_TIMEOUT_MS = 45_000


# ---------------------------------------------------------------------------
# Metadados do ambiente — essenciais para reprodutibilidade
# ---------------------------------------------------------------------------
def _pkg_version(name):
    try:
        from importlib.metadata import version
        return version(name)
    except Exception:
        return None


def environment_metadata():
    meta = {
        'host_os': platform.platform(),
        'host_python': sys.version.split()[0],
        'packages': {
            n: _pkg_version(n)
            for n in ('camoufox', 'playwright', 'browserforge')
        },
    }
    try:
        r = subprocess.run(['camoufox', 'version'], capture_output=True,
                           text=True, timeout=20)
        meta['camoufox_cli'] = (r.stdout or r.stderr).strip()[:500]
    except Exception as e:
        meta['camoufox_cli'] = f'indisponível: {e}'
    return meta


# ---------------------------------------------------------------------------
# Lançadores por configuração
# ---------------------------------------------------------------------------
def launch_playwright_firefox(headless):
    from playwright.sync_api import sync_playwright
    pw = sync_playwright().start()
    browser = pw.firefox.launch(headless=headless)
    return browser, (lambda: (browser.close(), pw.stop()))


def montar_proxy(server, usuario=None, senha=None):
    """
    Monta o dicionário de proxy no formato que o Playwright espera.

    Credenciais vão em campos próprios, não embutidas na URL: assim não
    aparecem em logs nem no JSON gravado, e caracteres especiais na senha
    não precisam de escape.

    Aceita também o formato usuario:senha@host:porta na própria URL, caso
    o proxy venha nesse formato — os campos são extraídos e separados.
    """
    if '@' in server and not usuario:
        esquema, _, resto = server.rpartition('://')
        cred, _, hostport = resto.partition('@')
        if ':' in cred:
            usuario, _, senha = cred.partition(':')
            server = f'{esquema}://{hostport}' if esquema else hostport
    d = {'server': server}
    if usuario:
        d['username'] = usuario
    if senha:
        d['password'] = senha
    return d


def launch_camoufox(headless, proxy=None, geoip=False):
    from camoufox.sync_api import Camoufox
    kwargs = {'headless': headless}
    if proxy:
        kwargs['proxy'] = proxy
        # geoip deriva fuso, locale e idioma do IP de saída. Sem isso o
        # perfil sairia por um IP e declararia o fuso da máquina local —
        # uma inconsistência introduzida pelo experimento, não pela
        # ferramenta.
        kwargs['geoip'] = True
    elif geoip:
        kwargs['geoip'] = True
    cm = Camoufox(**kwargs)
    browser = cm.__enter__()
    return browser, (lambda: cm.__exit__(None, None, None))


def make_browser(config, headless, proxy):
    if config == 'B':
        return launch_playwright_firefox(headless)
    if config == 'C':
        return launch_camoufox(headless)
    if config == 'D':
        if not proxy:
            sys.exit('Configuração D exige --proxy. Sem proxy não há '
                     'divergência de IP para medir.')
        return launch_camoufox(headless, proxy=proxy)
    sys.exit(f'Configuração desconhecida para execução automatizada: {config}')


# ---------------------------------------------------------------------------
# Coleta
# ---------------------------------------------------------------------------
def _morreu_o_driver(exc):
    """
    Distingue falha da página de morte do processo driver do Playwright.

    Quando o driver Node morre — por exemplo ao receber um evento de erro
    malformado do Juggler —, a conexão inteira cai e o navegador fica
    inutilizável. Qualquer página seguinte falharia por tabela, mascarando
    o motivo real. Nesse caso é preciso relançar o navegador.
    """
    t = f'{type(exc).__name__}: {exc}'.lower()
    marcas = (
        'target page, context or browser has been closed',
        'browser has been closed',
        'connection closed',
        'pipe closed',
        'target closed',
        'browser closed',
    )
    return any(m in t for m in marcas)


def collect_once(launcher, page_keys, run_id, config, proxy, label=None,
                 isolar=False):
    """
    Coleta as páginas pedidas.

    launcher: função sem argumentos que devolve (browser, close).

    Por padrão, um navegador atende todas as páginas da execução. Para o
    Camoufox isso é importante: cada lançamento sorteia uma identidade
    nova, e manter uma só identidade permite cruzar o veredito de cada
    página com os atributos daquele perfil.

    Com isolar=True, cada página ganha um navegador próprio. Mais robusto,
    porém cada página vê uma identidade diferente — use quando o objetivo
    for só obter a medição, não correlacionar páginas entre si.
    """
    record = {
        'run_id': run_id,
        'config': config,
        'label': label,
        # Registra que houve proxy e qual servidor, nunca a senha.
        'proxy': bool(proxy),
        'proxy_server': (proxy or {}).get('server'),
        'pages_requested': list(page_keys),
        'isolated': isolar,
        'collected_at': datetime.now(timezone.utc).isoformat(),
        'browser_restarts': 0,
        'pages': {},
    }

    browser = close = None

    def abrir():
        nonlocal browser, close
        browser, close = launcher()

    def fechar():
        nonlocal browser, close
        if close:
            try:
                close()
            except Exception:
                pass
        browser = close = None

    if not isolar:
        abrir()

    for key in page_keys:
        url = PAGES[key]
        entry = {'url': url, 'started_at': time.time()}
        if isolar or browser is None:
            abrir()

        context = page = None
        try:
            # Contexto novo por página: evita que o estado deixado por uma
            # página (canvas, conexões WebRTC, storage) contamine a próxima.
            # no_viewport=True: ver comentário em teste_camoufox.py.
            context = browser.new_context(no_viewport=True)
            page = context.new_page()

            page.goto(url, timeout=PAGE_TIMEOUT_MS,
                      wait_until='domcontentloaded')
            try:
                page.wait_for_load_state('networkidle', timeout=15_000)
            except Exception:
                entry['networkidle'] = 'timeout'

            if key in JSON_ENDPOINTS:
                # O valor está no corpo da resposta, observado do lado do
                # servidor. As sondas de JavaScript não acrescentam nada aqui.
                body = page.evaluate('document.body.innerText')
                try:
                    entry['network_fingerprint'] = json.loads(body)
                except (ValueError, TypeError):
                    entry['network_fingerprint_raw'] = (body or '')[:20000]
            else:
                entry['static'] = page.evaluate(STATIC_PROBE)
                entry['webrtc'] = page.evaluate(WEBRTC_PROBE, STUN_URLS)
            entry['title'] = page.title()
            entry['final_url'] = page.url
            entry['ok'] = True

        except Exception as e:
            entry['ok'] = False
            entry['error'] = f'{type(e).__name__}: {e}'
            if _morreu_o_driver(e):
                entry['driver_crash'] = True
                record['browser_restarts'] += 1
                print(f'    {key:12s} DRIVER CAIU — relançando navegador')
                fechar()

        entry['elapsed_s'] = round(time.time() - entry['started_at'], 1)
        record['pages'][key] = entry
        marca = 'ok' if entry.get('ok') else 'FALHOU'
        print(f'    {key:12s} {marca:8s} {entry["elapsed_s"]}s')

        if context is not None:
            try:
                context.close()
            except Exception:
                pass
        if isolar:
            fechar()

    fechar()
    return record


def manual_snippet():
    """
    Gera um trecho autocontido para colar no console do Firefox normal
    (configuração A). Roda as duas sondas, monta um registro no mesmo
    formato dos arquivos automatizados e dispara o download do JSON.
    """
    return f"""
(async () => {{
  const STATIC = {STATIC_PROBE.strip()};
  const WEBRTC = {WEBRTC_PROBE.strip()};
  const STUN = {json.dumps(STUN_URLS)};

  const t0 = performance.now();
  console.log('coletando... aguarde ~15s');

  const entry = {{ url: location.href, ok: true }};
  try {{
    entry.static = await STATIC();
    entry.webrtc = await WEBRTC(STUN);
    entry.title = document.title;
    entry.final_url = location.href;
  }} catch (e) {{
    entry.ok = false;
    entry.error = String(e);
  }}
  entry.elapsed_s = Math.round((performance.now() - t0) / 100) / 10;

  const key = location.href === 'about:blank' ? 'blank'
            : (location.hostname.split('.').slice(-2, -1)[0] || 'page');

  const record = {{
    run_id: (crypto.randomUUID ? crypto.randomUUID() : String(Date.now())),
    config: 'A',
    proxy: false,
    collected_at: new Date().toISOString(),
    pages: {{ [key]: entry }},
    environment: {{
      host_os: navigator.platform,
      note: 'coleta manual via console; Firefox operado por usuario',
      firefox_ua: navigator.userAgent,
    }},
  }};

  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const name = `A_${{stamp}}_${{key}}.json`;
  const blob = new Blob([JSON.stringify(record, null, 2)],
                        {{ type: 'application/json' }});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();

  console.log('pronto:', name, '| atributos:', Object.keys(entry.static || {{}}));
  window.__fp = record;   // tambem fica em window.__fp, por seguranca
  return name;
}})()
"""


def save(record, config, label=None):
    """
    Nome do arquivo: <config>[-<label>]_<data>-<hora>_<id>.json

    O label distingue variantes da mesma configuração — C com e sem
    geoip, A com e sem proteção reforçada. Ele também é gravado dentro
    do JSON: nome de arquivo se perde ao mover ou renomear, campo não.
    """
    OUT_DIR.mkdir(exist_ok=True)
    stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    tag = f'{config}-{label}' if label else config
    path = OUT_DIR / f'{tag}_{stamp}_{record["run_id"][:8]}.json'
    path.write_text(json.dumps(record, indent=2, ensure_ascii=False),
                    encoding='utf-8')
    return path


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--config', choices=['A', 'B', 'C', 'D'], default='C')
    ap.add_argument('--runs', type=int, default=1,
                    help='execuções independentes; o Camoufox sorteia '
                         'identidade nova a cada uma')
    ap.add_argument('--pages', nargs='*', default=['blank', 'creepjs',
                                                   'sannysoft', 'rebrowser'],
                    choices=list(PAGES))
    ap.add_argument('--label', default=None,
                    help='distingue variantes da mesma configuração, ex.: '
                         'geoip, fpp, semproxy. Entra no nome do arquivo e '
                         'no JSON. Use só letras, dígitos e hífen.')
    ap.add_argument('--proxy', default=None,
                    help='servidor do proxy, ex.: http://host:3128 ou '
                         'socks5://host:1080. Credenciais em --proxy-user e '
                         '--proxy-pass, ou embutidas como '
                         'esquema://user:senha@host:porta.')
    ap.add_argument('--proxy-user', default=None, help='usuário do proxy')
    ap.add_argument('--proxy-pass', default=None,
                    help='senha do proxy. Para não deixar no histórico do '
                         'shell, use a variável PROXY_PASS.')
    ap.add_argument('--isolate', action='store_true',
                    help='um navegador por página, em vez de um por execução. '
                         'Mais robusto a falhas, mas cada página vê uma '
                         'identidade diferente no Camoufox.')
    ap.add_argument('--headed', action='store_true',
                    help='abre janela visível; útil para depurar')
    ap.add_argument('--dump-js', action='store_true',
                    help='imprime um trecho autocontido para colar no console '
                         'do Firefox: coleta e baixa o JSON automaticamente')
    ap.add_argument('--dump-js-raw', action='store_true',
                    help='imprime as duas sondas separadas, sem download')
    args = ap.parse_args()

    senha = args.proxy_pass or os.environ.get('PROXY_PASS')
    proxy_cfg = (montar_proxy(args.proxy, args.proxy_user, senha)
                 if args.proxy else None)

    if args.label and not re.fullmatch(r'[A-Za-z0-9-]+', args.label):
        sys.exit('--label aceita apenas letras, dígitos e hífen '
                 '(ele compõe o nome do arquivo).')

    if args.dump_js:
        print(manual_snippet())
        return

    if args.dump_js_raw:
        print('// ---- sonda estática ----')
        print(f'await ({STATIC_PROBE.strip()})()')
        print()
        print('// ---- sonda de WebRTC ----')
        print(f'await ({WEBRTC_PROBE.strip()})({json.dumps(STUN_URLS)})')
        return

    if args.config == 'A':
        sys.exit('A configuração A é manual. Rode com --dump-js, cole no '
                 'console do Firefox e salve o resultado em data/ '
                 'como A_<data>.json')

    meta = environment_metadata()
    print(f'Configuração {args.config} · {args.runs} execução(ões) · '
          f'páginas: {", ".join(args.pages)}')
    print(f'Camoufox: {meta["packages"].get("camoufox")} · '
          f'Playwright: {meta["packages"].get("playwright")}')

    saved = []
    for i in range(args.runs):
        run_id = str(uuid.uuid4())
        print(f'\n[{i + 1}/{args.runs}] run {run_id[:8]}')
        def launcher():
            return make_browser(args.config, not args.headed, proxy_cfg)

        rec = collect_once(launcher, args.pages, run_id, args.config,
                           proxy_cfg, args.label, args.isolate)
        rec['environment'] = meta
        path = save(rec, args.config, args.label)
        saved.append(path)
        print(f'    -> {path}')

    print(f'\n{len(saved)} arquivo(s) em {OUT_DIR}/')


if __name__ == '__main__':
    main()
