#!/usr/bin/env python3
"""
Analisador dos dados coletados — EA019.

Lê os JSON de data/ e produz as tabelas de resultados do trabalho:

  1. Distribuição dos perfis gerados (sistema, resolução, núcleos, GPU)
  2. Consistência fontes x sistema declarado
  3. Pares de consistência entre camadas
  4. Vazamento de WebRTC sob proxy
  5. Camada de rede (TLS e TCP) por configuração

Uso:
    python analyze.py                  # tudo, em texto
    python analyze.py --csv saida/     # grava também as tabelas em CSV
    python analyze.py --dir data       # outro diretório de entrada

Nada aqui depende de biblioteca externa: só a biblioteca padrão.
"""

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Catálogo de fontes por sistema. Precisa espelhar fp_probes.py.
# ---------------------------------------------------------------------------
FONTES_WIN = {
    'Calibri', 'Cambria', 'Candara', 'Consolas', 'Constantia', 'Corbel',
    'Franklin Gothic Medium', 'Gabriola', 'Lucida Console', 'MS Gothic',
    'MV Boli', 'Segoe UI', 'Segoe Print', 'Sylfaen', 'Tahoma',
}
FONTES_MAC = {
    'American Typewriter', 'Avenir', 'Chalkboard', 'Cochin', 'Didot',
    'Futura', 'Geneva', 'Helvetica Neue', 'Hoefler Text', 'Menlo',
    'Monaco', 'Optima', 'Papyrus', 'SF Pro Text', 'Skia',
}
FONTES_LIN = {
    'Bitstream Vera Sans', 'Cantarell', 'DejaVu Sans', 'DejaVu Serif',
    'DejaVu Sans Mono', 'FreeMono', 'FreeSans', 'Liberation Mono',
    'Liberation Sans', 'Liberation Serif', 'Nimbus Roman', 'Ubuntu',
}

# Sistema da máquina de coleta. Define quais divergências entre o perfil
# declarado e a camada de rede são esperadas.
HOSPEDEIRO = 'macOS'


# ---------------------------------------------------------------------------
# Leitura
# ---------------------------------------------------------------------------
def so_do_ua(ua):
    if not ua:
        return '?'
    if 'Windows' in ua:
        return 'Windows'
    if 'Macintosh' in ua or 'Mac OS' in ua:
        return 'macOS'
    if 'X11' in ua or 'Linux' in ua:
        return 'Linux'
    return '?'


def so_do_p0f(p0f):
    """
    Infere o sistema a partir da assinatura TCP do SYN.

    Três sinais independentes, por ordem de confiabilidade:
      - TTL inicial: 64 em sistemas Unix, 128 em Windows
      - window scale: 6 no macOS, 7 no Linux, 8 no Windows
      - timestamps: presentes em Unix, ausentes no Windows por padrão

    Formato p0f: 4:TTL+?:0:MSS:WIN,WSCALE:opções:flags:0
    """
    if not p0f:
        return '?', {}
    partes = p0f.split(':')
    sinais = {}
    try:
        ttl = int(re.sub(r'\D', '', partes[1]))
        sinais['ttl'] = ttl
        sinais['ttl_inicial'] = 64 if ttl <= 64 else 128 if ttl <= 128 else 255
    except (IndexError, ValueError):
        pass
    m = re.search(r',(\d+):', p0f)
    if m:
        sinais['wscale'] = int(m.group(1))
    sinais['timestamps'] = ',ts' in p0f or ':ts' in p0f or ',timestamp' in p0f

    if sinais.get('ttl_inicial') == 128:
        return 'Windows', sinais
    ws = sinais.get('wscale')
    if ws == 6:
        return 'macOS', sinais
    if ws == 7:
        return 'Linux', sinais
    if ws == 8:
        return 'Windows', sinais
    return '?', sinais


def carregar(diretorio):
    regs = []
    for f in sorted(Path(diretorio).glob('*.json')):
        try:
            d = json.loads(f.read_text(encoding='utf-8'))
        except Exception as e:
            print(f'  aviso: {f.name} ilegível ({e})', file=sys.stderr)
            continue
        if 'pages' not in d:
            # pode ser um tls_peet salvo à mão, fora do formato do coletor
            if 'tls' in d and 'tcpip' in d:
                regs.append({'arquivo': f.name, 'config': f.name[0],
                             'label': 'avulso', 'pages': {
                                 'tls_peet': {'network_fingerprint': d}}})
            continue
        d['arquivo'] = f.name
        regs.append(d)
    return regs


def extrair(reg):
    """Reduz um registro a uma linha com os campos que interessam."""
    pages = reg.get('pages', {})
    # a sonda pode ter sido gravada sob chaves diferentes (blank, page, github…)
    pg = None
    for k in ('blank', 'page'):
        if k in pages and pages[k].get('static'):
            pg = pages[k]
            break
    if pg is None:
        for v in pages.values():
            if v.get('static'):
                pg = v
                break

    linha = {
        'arquivo': reg.get('arquivo'),
        'config': reg.get('config'),
        'label': reg.get('label'),
        'proxy': reg.get('proxy'),
    }

    if pg:
        s = pg['static']
        n = s.get('navigator', {})
        sc = s.get('screen', {})
        ft = s.get('fonts', {})
        det = set(ft.get('detected') or [])
        linha.update({
            'ua': n.get('userAgent'),
            'so_declarado': so_do_ua(n.get('userAgent')),
            'platform': n.get('platform'),
            'cores': n.get('hardwareConcurrency'),
            'webdriver': n.get('webdriver'),
            'langs': ','.join(n.get('languages') or []),
            'timezone': (s.get('locale') or {}).get('timeZone'),
            'resolucao': f"{sc.get('width')}x{sc.get('height')}",
            'dpr': sc.get('devicePixelRatio'),
            'gpu': (s.get('webgl') or {}).get('renderer'),
            'canvas': (s.get('canvas') or {}).get('hash'),
            'audio': (s.get('audio') or {}).get('sum'),
            'fontes_total': ft.get('count'),
            'fontes_win': len(det & FONTES_WIN),
            'fontes_mac': len(det & FONTES_MAC),
            'fontes_lin': len(det & FONTES_LIN),
            'fontes_isoladas': ft.get('isolatedFrame'),
            'fontes_suspeitas': ft.get('suspectContamination'),
        })
        w = pg.get('webrtc') or {}
        linha.update({
            'webrtc_srflx_v4': [a for a in (w.get('ips', {}).get('srflx') or [])
                                if '.' in a],
            'webrtc_srflx_v6': [a for a in (w.get('ips', {}).get('srflx') or [])
                                if ':' in a],
            'mdns': w.get('mdnsObfuscated'),
            'ipv6_exposto': w.get('ipv6Exposed'),
            'sdp_engine': w.get('sdpEngine'),
            'sdp_mismatch': w.get('sdpEngineMismatch'),
        })

    tp = pages.get('tls_peet', {})
    nf = tp.get('network_fingerprint') or {}
    if nf:
        tls = nf.get('tls') or {}
        tcp = nf.get('tcpip') or {}
        p0f = tcp.get('p0f')
        so_rede, sinais = so_do_p0f(p0f)
        linha.update({
            'ip_http': (nf.get('ip') or '').split(':')[0],
            'ua_rede': nf.get('user_agent'),
            'ja3': tls.get('ja3_hash'),
            'ja4': tls.get('ja4'),
            'akamai': (nf.get('http2') or {}).get('akamai_fingerprint_hash'),
            'p0f': p0f,
            'so_rede': so_rede,
            'ttl': sinais.get('ttl'),
            'wscale': sinais.get('wscale'),
            'tcp_timestamps': sinais.get('timestamps'),
        })
    return linha


# ---------------------------------------------------------------------------
# Apresentação
# ---------------------------------------------------------------------------
def titulo(t):
    print(f'\n{"=" * 74}\n{t}\n{"=" * 74}')


def tabela_freq(rotulo, valores, total=None):
    c = Counter(v for v in valores if v is not None)
    if not c:
        return []
    total = total or sum(c.values())
    print(f'\n{rotulo}  (n={total})')
    linhas = []
    for val, n in c.most_common():
        pct = 100 * n / total
        print(f'  {str(val):<34} {n:>4}  {pct:5.1f}%')
        linhas.append({'valor': val, 'n': n, 'pct': round(pct, 1)})
    return linhas


# ---------------------------------------------------------------------------
# Análises
# ---------------------------------------------------------------------------
def analise_perfis(linhas, csvs):
    titulo('1. DISTRIBUIÇÃO DOS PERFIS GERADOS')
    for cfg in ('C', 'D'):
        sub = [l for l in linhas if l.get('config') == cfg and l.get('ua')]
        if not sub:
            continue
        print(f'\n--- configuração {cfg} — {len(sub)} execuções ---')
        csvs[f'{cfg}_so'] = tabela_freq('Sistema declarado',
                                        [l['so_declarado'] for l in sub])
        divergem = sum(1 for l in sub if l['so_declarado'] != HOSPEDEIRO)
        print(f'\n  Divergem do hospedeiro ({HOSPEDEIRO}): '
              f'{divergem}/{len(sub)} = {100*divergem/len(sub):.1f}%')
        csvs[f'{cfg}_resolucao'] = tabela_freq('Resolução',
                                               [l['resolucao'] for l in sub])
        csvs[f'{cfg}_cores'] = tabela_freq('Núcleos',
                                           [l['cores'] for l in sub])
        csvs[f'{cfg}_tz'] = tabela_freq('Timezone',
                                        [l['timezone'] for l in sub])
        csvs[f'{cfg}_langs'] = tabela_freq('Idiomas',
                                           [l['langs'] for l in sub])


def analise_fontes(linhas, csvs):
    titulo('2. FONTES x SISTEMA DECLARADO')
    print('\nUm perfil que declara um sistema deveria expor as fontes dele.')
    print('Referência medida em máquinas reais: ver linhas de configuração A.\n')
    print(f'{"config":7s} {"SO decl.":9s} {"n":>3s} {"fontes":>7s} '
          f'{"win":>5s} {"mac":>5s} {"lin":>5s}')
    print('-' * 50)
    grupos = defaultdict(list)
    for l in linhas:
        if l.get('fontes_total') is None:
            continue
        grupos[(l['config'], l['so_declarado'])].append(l)
    saida = []
    for (cfg, so), g in sorted(grupos.items()):
        med = lambda k: sum(x[k] for x in g) / len(g)
        print(f'{cfg:7s} {so:9s} {len(g):>3d} {med("fontes_total"):>7.1f} '
              f'{med("fontes_win"):>5.1f} {med("fontes_mac"):>5.1f} '
              f'{med("fontes_lin"):>5.1f}')
        saida.append({'config': cfg, 'so_declarado': so, 'n': len(g),
                      'fontes_media': round(med('fontes_total'), 1),
                      'win_media': round(med('fontes_win'), 1),
                      'mac_media': round(med('fontes_mac'), 1),
                      'lin_media': round(med('fontes_lin'), 1)})
    csvs['fontes_por_so'] = saida

    susp = [l['arquivo'] for l in linhas if l.get('fontes_suspeitas')]
    if susp:
        print(f'\n  ATENÇÃO: {len(susp)} coleta(s) com suspeita de '
              f'contaminação na medição de fontes:')
        for a in susp[:5]:
            print(f'    {a}')


def analise_rede(linhas, csvs):
    titulo('3. CAMADA DE REDE: SISTEMA DECLARADO x ASSINATURA TCP')
    sub = [l for l in linhas if l.get('p0f')]
    if not sub:
        print('\n  nenhuma coleta com tls_peet')
        return
    print(f'\n{"arquivo":34s} {"decl.":8s} {"rede":8s} {"TTL":>4s} '
          f'{"wsc":>4s} {"ts":>5s}  contradiz?')
    print('-' * 86)
    saida = []
    contradiz = 0
    for l in sorted(sub, key=lambda x: (x['config'] or '', x['arquivo'])):
        decl = l.get('so_declarado') or so_do_ua(l.get('ua_rede')) or '?'
        rede = l.get('so_rede', '?')
        bate = (decl == rede) or '?' in (decl, rede)
        if not bate:
            contradiz += 1
        print(f'{l["arquivo"][:34]:34s} {decl:8s} {rede:8s} '
              f'{str(l.get("ttl")):>4s} {str(l.get("wscale")):>4s} '
              f'{str(l.get("tcp_timestamps")):>5s}  '
              f'{"SIM" if not bate else ""}')
        saida.append({'arquivo': l['arquivo'], 'config': l['config'],
                      'so_declarado': decl, 'so_rede': rede,
                      'ttl': l.get('ttl'), 'wscale': l.get('wscale'),
                      'timestamps': l.get('tcp_timestamps'),
                      'contradiz': not bate, 'ja4': l.get('ja4'),
                      'p0f': l.get('p0f')})
    print(f'\n  Contradições: {contradiz}/{len(sub)}')
    csvs['camada_rede'] = saida

    ja4s = Counter(l['ja4'] for l in sub if l.get('ja4'))
    print(f'\n  JA4 distintos: {len(ja4s)}')
    for v, n in ja4s.most_common():
        print(f'    {v}  ({n}x)')
    if len(ja4s) == 1:
        print('  -> o JA4 não discrimina sistema nem configuração.')


def analise_webrtc(linhas, csvs):
    titulo('4. VAZAMENTO DE WEBRTC SOB PROXY')
    sub = [l for l in linhas if l.get('proxy') and l.get('webrtc_srflx_v4')]
    if not sub:
        print('\n  nenhuma coleta com proxy e candidatos WebRTC')
        return
    vaz = 0
    saida = []
    for l in sub:
        ip_http = l.get('ip_http')
        srflx = l['webrtc_srflx_v4']
        # sem o IP de saída HTTP na mesma execução, compara-se com o
        # conjunto de IPs de proxy observados nas demais execuções
        vazou = bool(ip_http) and ip_http not in srflx
        if vazou:
            vaz += 1
        saida.append({'arquivo': l['arquivo'], 'ip_http': ip_http,
                      'webrtc_srflx': ';'.join(srflx),
                      'ipv6': ';'.join(l.get('webrtc_srflx_v6') or []),
                      'vazou': vazou})
    print(f'\n  Execuções com proxy e WebRTC: {len(sub)}')
    print(f'  Divergência entre IP HTTP e IP WebRTC: {vaz} '
          f'({100*vaz/len(sub):.1f}%)')
    ips_http = Counter(l.get('ip_http') for l in sub if l.get('ip_http'))
    ips_rtc = Counter(a for l in sub for a in l['webrtc_srflx_v4'])
    print(f'\n  IPs observados via HTTP : {dict(ips_http)}')
    print(f'  IPs observados via WebRTC: {dict(ips_rtc)}')
    csvs['webrtc_proxy'] = saida


def analise_pares(linhas, csvs):
    titulo('5. PARES DE CONSISTÊNCIA')
    print('\nCada par cruza dois atributos que deveriam concordar.')
    print('A coluna "A" é a linha de base: violações que aparecem nela')
    print('são próprias do navegador legítimo e NÃO contam como falha.\n')

    def par_ua_fontes(l):
        so = l.get('so_declarado')
        if so == 'Windows':
            return l.get('fontes_win', 0) < 5
        if so == 'macOS':
            return l.get('fontes_mac', 0) < 5
        return None

    def par_ua_gpu(l):
        so, gpu = l.get('so_declarado'), (l.get('gpu') or '')
        if not gpu:
            return None
        if so == 'Windows':
            return 'ANGLE' not in gpu and 'Direct3D' not in gpu
        if so == 'macOS':
            return 'Apple' not in gpu and 'ANGLE' in gpu
        return None

    def par_ua_platform(l):
        so, p = l.get('so_declarado'), l.get('platform')
        if not p:
            return None
        return not ((so == 'Windows' and p.startswith('Win')) or
                    (so == 'macOS' and p.startswith('Mac')) or
                    (so == 'Linux' and p.startswith('Linux')))

    def par_ua_rede(l):
        if not l.get('so_rede') or l['so_rede'] == '?':
            return None
        # Coletas que só têm tls_peet não trazem a sonda de JavaScript;
        # nesse caso o sistema declarado vem do user-agent da própria
        # requisição, registrado pelo servidor.
        decl = l.get('so_declarado') or so_do_ua(l.get('ua_rede'))
        if not decl or decl == '?':
            return None
        return decl != l['so_rede']

    def par_ip_webrtc(l):
        if not (l.get('ip_http') and l.get('webrtc_srflx_v4')):
            return None
        return l['ip_http'] not in l['webrtc_srflx_v4']

    PARES = [
        ('userAgent x fontes do sistema', par_ua_fontes),
        ('userAgent x renderizador WebGL', par_ua_gpu),
        ('userAgent x navigator.platform', par_ua_platform),
        ('userAgent x assinatura TCP', par_ua_rede),
        ('IP de saída x IP do WebRTC', par_ip_webrtc),
    ]
    cfgs = sorted({l['config'] for l in linhas if l.get('config')})
    print(f'{"par":34s}' + ''.join(f'{c:>12s}' for c in cfgs))
    print('-' * (34 + 12 * len(cfgs)))
    saida = []
    for nome, fn in PARES:
        celulas, reg = [], {'par': nome}
        for c in cfgs:
            sub = [l for l in linhas if l.get('config') == c]
            res = [fn(l) for l in sub]
            res = [r for r in res if r is not None]
            if not res:
                celulas.append('—')
                reg[c] = ''
            else:
                v = sum(res)
                celulas.append(f'{v}/{len(res)}')
                reg[c] = f'{v}/{len(res)}'
        print(f'{nome:34s}' + ''.join(f'{x:>12s}' for x in celulas))
        saida.append(reg)
    csvs['pares_consistencia'] = saida


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--dir', default='data')
    ap.add_argument('--csv', default=None,
                    help='diretório onde gravar as tabelas em CSV')
    args = ap.parse_args()

    regs = carregar(args.dir)
    if not regs:
        sys.exit(f'nenhum JSON legível em {args.dir}/')
    linhas = [extrair(r) for r in regs]

    print(f'{len(linhas)} arquivo(s) lido(s) de {args.dir}/')
    print('por configuração:',
          dict(Counter(l.get('config') for l in linhas)))

    csvs = {}
    analise_perfis(linhas, csvs)
    analise_fontes(linhas, csvs)
    analise_rede(linhas, csvs)
    analise_webrtc(linhas, csvs)
    analise_pares(linhas, csvs)

    if args.csv:
        out = Path(args.csv)
        out.mkdir(parents=True, exist_ok=True)
        for nome, dados in csvs.items():
            if not dados:
                continue
            p = out / f'{nome}.csv'
            with open(p, 'w', newline='', encoding='utf-8') as fh:
                wr = csv.DictWriter(fh, fieldnames=list(dados[0].keys()))
                wr.writeheader()
                wr.writerows(dados)
        print(f'\n{len(csvs)} tabela(s) em {out}/')

    print('\nLembrete: os JSON originais contêm IPs públicos reais. '
          'Rode anonymize.py antes de publicar.')


if __name__ == '__main__':
    main()
