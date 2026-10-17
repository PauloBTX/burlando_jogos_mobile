#!/usr/bin/env python3
"""
Runner do agente DE MODIFICAÇÃO — Multiplicador 100x de moedas (coins/rubies).

Faz três coisas:
  1. Lê _dump/alvos.json e deriva a lista TARGETS (RVA + decodificação de args),
     inferindo tipo/nome dos parâmetros a partir da assinatura verificada no dump;
  2. Concatena TARGETS + agent_100x.js (agente modificador) e anexa ao processo
     do jogo via Frida;
  3. Grava cada registro em agente/log/<timestamp>.jsonl e imprime resumo.

O agente anexado MODIFICA o parâmetro `amount` de CurrencyManager::Add,
multiplicando-o por 100 para as moedas `coins` e `rubies`.

Modos de conexão:
    python agente/runner.py                             # frida-server via USB
    python agente/runner.py --host 127.0.0.1:27042      # Frida Gadget via TCP
    python agente/runner.py --host 127.0.0.1:27042 --processo Gadget
    python agente/runner.py --host 127.0.0.1:27042 --pid 6577
    python agente/runner.py --dry-run                   # só valida alvos, sem device
"""
import argparse
import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ALVOS = ROOT / "_dump" / "alvos.json"
AGENTE_JS = Path(__file__).resolve().parent / "agent_100x.js"
LOG_DIR = Path(__file__).resolve().parent / "log"
PACOTE = "com.pockethaven.roguelegend"
GADGET = "Gadget"  # nome exibido pelo Frida quando o processo roda com gadget embutido

# Tipos primitivos que o agente sabe ler do registrador (w-reg de ARM64).
PRIMITIVOS = {"int", "uint", "long", "bool", "byte", "short"}

# Converte o tipo C#/IL2CPP da assinatura em algo que o agente decodifica.
MAPEAMENTO_TIPO = {
    "int": "int", "uint": "uint", "long": "long", "ulong": "long",
    "bool": "bool", "byte": "byte", "short": "short",
    "string": "string",  # objeto gerenciado — lido como string (com fallback manual)
}


def parsear_assinatura(assinatura: str):
    """
    Extrai tipo de retorno, nome e parâmetros de uma declaração do dump.cs.

    Ex.: "public void Add(string currencyId, int amount, bool shouldCap = False)"
      -> ret='void', params=[{'nome':'currencyId','tipo':'string'}, ...]
    """
    m = re.search(r"\(([^)]*)\)", assinatura)
    if not m:
        return "void", []
    dentro = m.group(1).strip()

    params = []
    if dentro:
        for parte in dentro.split(","):
            parte = parte.strip()
            if not parte:
                continue
            # Remove default value ("bool shouldCap = False" -> "bool shouldCap")
            parte = parte.split("=")[0].strip()
            tokens = parte.split()
            if len(tokens) < 2:
                continue
            tipo_c = tokens[0].rstrip("?!")          # descarta int?/ref-like markers
            nome = tokens[1].lstrip("*").strip()
            tipo = MAPEAMENTO_TIPO.get(tipo_c, "ptr")
            params.append({"nome": nome, "tipo": tipo})

    # Tipo de retorno: em "public void Add(...)", o nome do método é o último
    # token antes do "(", e o tipo de retorno é o imediatamente anterior.
    antes = assinatura[: assinatura.index("(")]
    toks = antes.split()
    if len(toks) >= 2:
        ret = toks[-2]
    elif len(toks) == 1:
        ret = "void"          # só o nome visível (ex.: método sem modificador)
    else:
        ret = "void"
    return ret, params


def carregar_alvos():
    """Lê alvos.json e monta o TARGETS que o agente consome.

    Inclui classe/metodo (para a lógica de modificação do agente) e uma chave
    'rva' numérica (além do rva_decimal original do dump).
    """
    dados = json.loads(ALVOS.read_text(encoding="utf-8"))
    targets = []
    for d in dados:
        ret, params = parsear_assinatura(d["assinatura"])
        targets.append({
            "nome": d["nome_completo"],
            "nome_completo": d["nome_completo"],
            "classe": d.get("classe", ""),
            "metodo": d.get("metodo", ""),
            "rva": d["rva_decimal"],
            "rva_decimal": d["rva_decimal"],
            "rva_hex": d["rva_hex"],
            "ret": ret,
            "params": params,
            "assinatura": d["assinatura"],
        })
    return targets


def validar_estaticamente(targets):
    """
    Sanidade sem device: RVA positivo e coerente com o tamanho do .so.
    Pega o tamanho do binário extraído — se o RVA for maior que o arquivo,
    algo está errado no pipeline.
    """
    so = ROOT / "_dump" / "input" / "libil2cpp.so"
    tam = so.stat().st_size if so.exists() else None
    print("=" * 68)
    print("VALIDAÇÃO ESTÁTICA (sem device)")
    print("=" * 68)
    problemas = []
    for t in targets:
        ok = 0 < t["rva"] < (tam or 1 << 62)
        marca = "[OK] " if ok else "[ERRO]"
        print(f"{marca} {t['nome']:38s} {t['rva_hex']:>10s}  ret={t['ret']:5s} "
              f"params={len(t['params'])}")
        for p in t["params"]:
            print(f"        {p['nome']:14s} <- {p['tipo']}")
        if not ok:
            problemas.append(t["nome"])
    if tam:
        print(f"\n[INFO] tamanho do .so: {tam:,} bytes "
              f"(todos os RVAs devem ser menores)")
    return not problemas


def montar_script(targets):
    """Pré-anexa a variável TARGETS ao agent_100x.js."""
    js = "var TARGETS = " + json.dumps(targets, indent=2) + ";\n\n"
    return js + AGENTE_JS.read_text(encoding="utf-8")


def conectar(host):
    """Conecta ao Frida via TCP remoto (--host) ou USB (default)."""
    import frida
    if host:
        print(f"[+] conectando via TCP em {host} ...")
        mgr = frida.get_device_manager()
        return mgr.add_remote_device(host)
    print("[+] conectando via USB (frida-server) ...")
    return frida.get_usb_device(timeout=10)


def anexar(device, spawn, processo, pid):
    """Anexa ao processo; com fallback automático para o nome 'Gadget'."""
    import frida
    if spawn:
        pid_spawn = device.spawn([processo])
        return device.attach(pid_spawn), pid_spawn
    try:
        alvo = pid if pid is not None else processo
        return device.attach(alvo), None
    except frida.ProcessNotFoundError:
        if pid is not None:
            raise
        print(f"[!] '{processo}' não encontrado — tentando '{GADGET}' como fallback...")
        return device.attach(GADGET), None


def rodar(targets, spawn: bool, host=None, processo=None, pid=None):
    try:
        import frida
    except ImportError:
        print("[ERRO] frida-python não instalado: pip install frida")
        sys.exit(1)

    processo = processo or PACOTE
    LOG_DIR.mkdir(exist_ok=True)
    caminho_log = LOG_DIR / (datetime.now().strftime("%Y%m%d_%H%M%S") + ".jsonl")
    fh = caminho_log.open("w", encoding="utf-8")
    contagem = {}
    erros = []

    def on_message(msg, data):
        try:
            if msg["type"] == "error":
                print(f"[ERRO JS] {msg.get('stack', msg)}")
                return
            if msg["type"] != "send":
                return
            reg = msg["payload"]
            if not isinstance(reg, dict):
                return
            fh.write(json.dumps(reg, ensure_ascii=False) + "\n")
            fh.flush()
            if reg.get("tipo") == "chamada":
                m = reg.get("metodo", "<desconhecido>")
                contagem[m] = contagem.get(m, 0) + 1
                args = ", ".join(f"{k}={v}" for k, v in reg.get("args", {}).items())
                extra = ""
                if reg.get("modificado"):
                    extra = (f"  <-- {reg.get('quantidadeOriginal')} -> "
                             f"{reg.get('quantidadeModificada')} "
                             f"(x{reg.get('fatorAplicado')})")
                print(f"  {m}({args}){extra}")
            elif reg.get("tipo") == "erro":
                erros.append(reg)
                print(f"[!] {reg.get('alvo')}: {reg.get('motivo')}")
            elif reg.get("tipo") == "pronto":
                print(f"[+] hooks {reg.get('instalados')}/{reg.get('total')} "
                      f"base={reg.get('base')}")
        except Exception as e:
            print(f"[!] on_message ignorou registro mal-formado: {e}")

    device = conectar(host)
    print(f"[+] device: {device.name} ({'TCP' if host else 'USB'})")

    session, pid_spawn = anexar(device, spawn, processo, pid)

    script = session.create_script(montar_script(targets))
    script.on("message", on_message)
    script.load()
    if spawn:
        device.resume(pid_spawn)

    try:
        # Mostra informações do processo anexado
        if pid_spawn is not None:
            info = device.get_process(pid_spawn)
        elif pid is not None:
            info = device.get_process(pid)
        else:
            info = device.get_process(processo)
        print(f"[+] anexado ao processo: {info.name} (PID={info.pid})")
    except Exception:
        pass

    print(f"[+] log em {caminho_log}")
    print("[*] Ctrl+C para encerrar\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            script.unload()
        except Exception:
            pass
        try:
            session.detach()
        except Exception:
            pass
        fh.close()
        imprimir_resumo(contagem, erros, caminho_log)


def imprimir_resumo(contagem, erros, caminho_log):
    print("\n" + "=" * 68)
    print("RESUMO DA SESSÃO")
    print("=" * 68)
    if not contagem:
        print("(nenhuma chamada capturada)")
    for m, n in sorted(contagem.items(), key=lambda x: -x[1]):
        print(f"  {n:6d}  {m}")
    if erros:
        print(f"\n[!] {len(erros)} erro(s) de alvo:")
        for e in erros:
            print(f"    {e.get('alvo')}: {e.get('motivo')}")
    print(f"\nlog: {caminho_log}")


def main():
    ap = argparse.ArgumentParser(description="Runner do agente modificador 100x")
    ap.add_argument("--spawn", action="store_true",
                    help="inicia o app e anexa (requer frida-server/USB)")
    ap.add_argument("--dry-run", action="store_true",
                    help="só valida alvos e monta o script, sem device")
    ap.add_argument("--host", default=None,
                    help="host:port do Frida remoto (ex.: 127.0.0.1:27042). Default: USB")
    ap.add_argument("--processo", default=None,
                    help=f"nome do processo (default: {PACOTE} ou {GADGET})")
    ap.add_argument("--pid", type=int, default=None,
                    help="PID do processo alvo (alternativa a --processo)")
    args = ap.parse_args()

    if not ALVOS.exists():
        print(f"[ERRO] {ALVOS} não existe — rode a Fase 1 primeiro")
        sys.exit(1)

    targets = carregar_alvos()
    if not validar_estaticamente(targets):
        print("\n[ERRO] validação estática falhou — não anexando")
        sys.exit(1)

    processo = args.processo or PACOTE

    if args.dry_run:
        print(f"\n[OK] validação estática passou. Script montado com {len(targets)} alvos.")
        print("     (dry-run: não conectou ao device)")
        return

    rodar(targets, spawn=args.spawn, host=args.host, processo=processo, pid=args.pid)


if __name__ == "__main__":
    main()