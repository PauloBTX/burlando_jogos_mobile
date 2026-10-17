// ============================================================
// AGENTE DE MODIFICAÇÃO v5 — Multiplicador 100.000x de Moedas
// Ponto: CurrencyManager::Add (RVA 0x2FB5354)
// MODO: runtime (Frida Gadget embutido no APK — sem root)
// ============================================================
// Diagnóstico (2026-10-16):
//   * Endereço CONFIRMADO correto — hook intercepta chamadas reais.
//   * Leitura de Il2CppString OK — currencyId decodificado com sucesso.
//   * MOEDAS REAIS observadas nos logs: coins, gems, energy,
//     tower_tickets, dungeon_dive_tickets, chaos_energy.
//   * BUG CORRIGIDO: "gems" (gemas) NÃO estava em MOEDAS_ALVO
//     (só "coins" e "rubies" — que nem existe no jogo).
// ============================================================
// Estratégia Frida 17:
//   * args[] é somente-leitura -> escrevemos o registrador ARM64
//     `x2` (= w2) via this.context.x2.
//   * Fallback: args[2] = ptr(...) (caso o runtime aceite).
//   * TUDO em try/catch com e.stack para diagnóstico.
// ============================================================
"use strict";

var CFG = {
  MODULO: "libil2cpp.so",
  // Moedas que recebem o multiplicador:
  //   coins = moedas | gems = gemas (rubys no jogo se chama "gems")
  MOEDAS_ALVO: ["coins", "gems", "rubies"],
  FATOR: 100000,
  LOG_DETALHADO: true
};

// ------------------------------------------------------------------
// Leitura de string gerenciada (Il2CppString, ARM64):
//   +0x00  object (klass ptr) + monitor  = 16 bytes
//   +0x10  length (int32)                <- comprimento UTF-16
//   +0x14  chars (uint16_t[])
// ------------------------------------------------------------------
function lerStringGerenciada(ptrString) {
  if (!ptrString || ptrString.isNull()) return null;
  try {
    var comprimento = ptrString.add(0x10).readS32();
    if (comprimento > 0 && comprimento <= 4096) {
      return ptrString.add(0x14).readUtf16String(comprimento);
    }
  } catch (e) { /* ponteiro inválido / memória não mapeada */ }
  return null;
}

// ------------------------------------------------------------------
// Instala o hook SOMENTE em CurrencyManager::Add
// ARM64/AAPCS64: x0=this, x1=currencyId, w2=amount, w3=shouldCap
// ------------------------------------------------------------------
function instalarHookAdd(modulo, rvaAdd) {
  var endereco = modulo.base.add(rvaAdd);

  // Proteção contra re-instalação (múltiplas sessões no mesmo processo)
  if (globalThis.__addHookInstalado) {
    console.log("[*] Hook Add já instalado — ignorando re-instalação");
    return false;
  }
  globalThis.__addHookInstalado = true;

  Interceptor.attach(endereco, {
    onEnter: function (args) {
      try {
        this.inicio = Date.now();
        this.thread = Process.getCurrentThreadId();

        // Lê currencyId (args[1] = ponteiro Il2CppString)
        var id = lerStringGerenciada(args[1]);
        this.currencyId = id !== null ? id : ("<ptr:" + args[1] + ">");

        this.amountOriginal = args[2].toInt32();
        this.shouldCap = args[3].toInt32() !== 0;
        this.modificado = false;

        // Só multiplica moedas alvo
        if (CFG.MOEDAS_ALVO.indexOf(this.currencyId) !== -1) {
          var novo = Math.min(2147483647, this.amountOriginal * CFG.FATOR);

          // --- Tentativa 1: registrador ARM64 via CpuContext (Frida 17) ---
          var ok = false;
          try {
            this.modifyContext = true;
            this.context.x2 = ptr(novo >>> 0);
            ok = true;
          } catch (e1) {
            console.log("[!] context.x2 falhou: " + e1);
            // --- Tentativa 2: write direto no array args (fallback) ---
            try {
              args[2] = ptr(novo >>> 0);
              ok = true;
            } catch (e2) {
              console.log("[!] args[2] falhou também: " + e2);
              console.log("    stack: " + (e2.stack || "n/d"));
            }
          }

          if (ok) {
            this.modificado = true;
            this.amountNovo = novo;
            if (CFG.LOG_DETALHADO) {
              console.log("[HOOK] " + this.currencyId + " " +
                          this.amountOriginal + " -> " + novo +
                          " [x" + CFG.FATOR + "] (shouldCap=" + this.shouldCap + ")");
            }
          }
        } else if (CFG.LOG_DETALHADO) {
          console.log("[--] " + this.currencyId + " " + this.amountOriginal +
                      " (não é moeda alvo)");
        }
      } catch (e) {
        console.log("[!] onEnter ERROR: " + e);
        console.log("    stack: " + (e.stack || "n/d"));
        this.modificado = false;
      }
    },

    onLeave: function (retval) {
      try {
        send({
          tipo: "chamada",
          metodo: "CurrencyManager$$Add",
          thread: this.thread,
          timestamp: new Date().toISOString(),
          duracao_ms: Date.now() - (this.inicio || Date.now()),
          argumentos: {
            currencyId: this.currencyId,
            amount: this.amountOriginal,
            shouldCap: this.shouldCap
          },
          modificado: !!this.modificado,
          quantidadeOriginal: this.amountOriginal,
          quantidadeModificada: this.amountNovo,
          fatorAplicado: CFG.FATOR
        });
      } catch (e) {
        console.log("[!] onLeave ERROR: " + e);
      }
    }
  });

  console.log("[+] HOOK Add instalado @ " + endereco +
              " (RVA 0x" + rvaAdd.toString(16) + ")");
  return true;
}

// ------------------------------------------------------------------
// Bootstrap
// ------------------------------------------------------------------
console.log("[*] AGENTE v5 — multiplicador " + CFG.FATOR + "x para [" +
            CFG.MOEDAS_ALVO.join(", ") + "]");

function instalar(modulo) {
  console.log("[*] " + CFG.MODULO + " base=" + modulo.base +
              " (tamanho: " + modulo.size + ")");

  // RVA do CurrencyManager::Add — preenchido pelo runner (TARGETS)
  // ou fallback hardcoded do dump (_dump/alvos.json).
  var rva = 50025300; // 0x2FB5354
  if (typeof TARGETS !== "undefined" && TARGETS) {
    for (var i = 0; i < TARGETS.length; i++) {
      if (TARGETS[i].metodo === "Add" && TARGETS[i].classe === "CurrencyManager") {
        rva = (TARGETS[i].rva !== undefined) ? TARGETS[i].rva : TARGETS[i].rva_decimal;
        break;
      }
    }
  }
  console.log("[*] CurrencyManager::Add RVA = " + rva + " (0x" + rva.toString(16) + ")");

  if (instalarHookAdd(modulo, rva)) {
    send({ tipo: "pronto", instalados: 1, total: 1, base: modulo.base.toString() });
  } else {
    send({ tipo: "pronto", instalados: 0, total: 1, base: modulo.base.toString() });
  }
}

var mod = Process.findModuleByName(CFG.MODULO);
if (mod) {
  instalar(mod);
} else {
  console.log("[*] Aguardando " + CFG.MODULO + " carregar...");
  var iv = setInterval(function () {
    var m = Process.findModuleByName(CFG.MODULO);
    if (m) {
      clearInterval(iv);
      instalar(m);
    }
  }, 100);
}

// ---------------------------------------------------------------
// (opcional) Padrão de linha de comando direto, SEM runner.py:
//   frida -H 127.0.0.1:27042 -n Gadget -l agent_100x.js
//   (usa o RVA hardcoded 0x2FB5354)
// ---------------------------------------------------------------