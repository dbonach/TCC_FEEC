#!/usr/bin/env python3
"""
Gera uma cópia publicável dos dados coletados.

Substitui endereços IP públicos, hostnames mDNS e identificadores de
sessão por pseudônimos estáveis. "Estável" significa que o mesmo IP vira
sempre o mesmo rótulo dentro de um corpus, de modo que a análise de
consistência continua possível — você ainda consegue dizer "o IP do
WebRTC difere do IP de saída HTTP" sem revelar nenhum dos dois.

Uso:
    python anonymize.py                      # data/ -> data_publico/
    python anonymize.py --in data --out pub
    python anonymize.py --mapa mapa.json     # salva o mapeamento (NÃO publicar)

Rode isto antes de subir qualquer coisa para repositório ou anexo do TCC.
O diretório de origem permanece intacto e é o que você usa na análise.
"""

import argparse
import hashlib
import ipaddress
import json
import re
from pathlib import Path

SALT_FILE = Path('.anon_salt')

IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
IPV6_RE = re.compile(r'\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b', re.I)
MDNS_RE = re.compile(
    r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.local\b',
    re.I)
# ice-ufrag e ice-pwd identificam a sessão; fingerprint DTLS é por conexão
SDP_SECRETS_RE = re.compile(
    r'(a=(?:ice-pwd|ice-ufrag):)\S+|(a=fingerprint:\S+ )[0-9A-F:]{40,}', re.I)


def load_salt():
    """Sal persistente: mantém os pseudônimos estáveis entre execuções."""
    if SALT_FILE.exists():
        return SALT_FILE.read_text().strip()
    import secrets
    s = secrets.token_hex(16)
    SALT_FILE.write_text(s)
    print(f'sal novo gravado em {SALT_FILE} — não versionar este arquivo')
    return s


class Pseudonymizer:
    def __init__(self, salt):
        self.salt = salt
        self.map = {}
        self.counters = {}

    def label(self, value, kind):
        if value in self.map:
            return self.map[value]
        n = self.counters.get(kind, 0) + 1
        self.counters[kind] = n
        digest = hashlib.sha256(
            (self.salt + value).encode()).hexdigest()[:6]
        tag = f'<{kind}-{n:02d}-{digest}>'
        self.map[value] = tag
        return tag

    # -- classificação ----------------------------------------------------
    @staticmethod
    def _kind_for_ip(text):
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            return None
        if ip.is_loopback or ip.is_link_local:
            return None          # 127.0.0.1 e fe80:: não identificam ninguém
        if ip.is_private:
            return f'ipv{ip.version}-privado'
        return f'ipv{ip.version}-publico'

    def scrub_text(self, text):
        def ip_sub(m):
            raw = m.group(0)
            kind = self._kind_for_ip(raw)
            return self.label(raw, kind) if kind else raw

        text = MDNS_RE.sub(lambda m: self.label(m.group(0), 'mdns'), text)
        text = IPV4_RE.sub(ip_sub, text)
        text = IPV6_RE.sub(ip_sub, text)
        text = SDP_SECRETS_RE.sub(
            lambda m: (m.group(1) or m.group(2) or '') + '<removido>', text)
        return text

    def walk(self, node):
        if isinstance(node, dict):
            return {k: self.walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [self.walk(v) for v in node]
        if isinstance(node, str):
            return self.scrub_text(node)
        return node


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--in', dest='src', default='data')
    ap.add_argument('--out', dest='dst', default='data_publico')
    ap.add_argument('--mapa', default=None,
                    help='grava o mapeamento pseudônimo->real; '
                         'manter FORA do repositório')
    args = ap.parse_args()

    src, dst = Path(args.src), Path(args.dst)
    if not src.is_dir():
        raise SystemExit(f'diretório não encontrado: {src}')
    dst.mkdir(exist_ok=True)

    p = Pseudonymizer(load_salt())
    files = sorted(src.glob('*.json'))
    if not files:
        raise SystemExit(f'nenhum .json em {src}/')

    for f in files:
        data = json.loads(f.read_text(encoding='utf-8'))
        clean = p.walk(data)
        (dst / f.name).write_text(
            json.dumps(clean, indent=2, ensure_ascii=False), encoding='utf-8')
        print(f'  {f.name}')

    print(f'\n{len(files)} arquivo(s) -> {dst}/')
    if p.map:
        por_tipo = {}
        for real, tag in p.map.items():
            kind = tag.split('-')[0].lstrip('<')
            por_tipo[kind] = por_tipo.get(kind, 0) + 1
        print('substituições:', ', '.join(
            f'{k}={v}' for k, v in sorted(por_tipo.items())))
    else:
        print('nada a substituir')

    if args.mapa:
        Path(args.mapa).write_text(
            json.dumps(p.map, indent=2, ensure_ascii=False), encoding='utf-8')
        print(f'mapeamento em {args.mapa} — NÃO versionar, NÃO anexar ao TCC')


if __name__ == '__main__':
    main()
