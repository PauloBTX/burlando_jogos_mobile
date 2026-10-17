# Engenharia Reversa e Instrumentação Dinâmica em Unity/IL2CPP: Injeção de Frida Gadget sem Root e Modificação em Runtime

> **Aviso Ético e Legal:** Este artigo possui finalidade estritamente educacional e de pesquisa em segurança defensiva de aplicações móveis. Os testes foram realizados em ambiente de laboratório isolado, utilizando dispositivo dedicado, conta descartável e binários sob análise controlada.

---

## 1. Introdução

Jogos desenvolvidos sobre a engine Unity compilados com o backend **IL2CPP (Intermediate Language to C++)** representam um padrão consolidado na indústria mobile. Diferente do runtime Mono tradicional — onde o código CIL (.NET bytecode) reside em assemblies `.dll` de fácil descompilação —, o IL2CPP converte o código C# gerenciado em C++ nativo, que é então compilado diretamente para código de máquina específico da arquitetura (neste caso, ELF compartilhado `libil2cpp.so` para `arm64-v8a`).

Embora essa compilação nativa aumente o desempenho e dificulte a engenharia reversa trivial, ela não elimina vulnerabilidades arquiteturais. Quando um aplicativo implementa lógica transacional sensível (como adição de saldo de moedas e controle de inventário) no lado do cliente (*client-side authority*), toda a integridade do sistema fica à mercê da integridade do dispositivo do usuário.

Neste artigo, documentamos a análise de ponta a ponta realizada no jogo **RogueLegend** (versão 0.610):
1. **Engenharia Reversa Estática (REA e Metadados)** para localização de choke points e cálculo de RVAs (*Relative Virtual Addresses*);
2. **Injeção do Frida Gadget** no APK via `objection` para instrumentação sem necessidade de *root*;
3. **Desenvolvimento do Script de Hooking** em JavaScript (`agent_100x.js`) explorando a ABI ARM64;
4. **Automação e Orquestração** com Python (`runner.py`) para conexões TCP e geração de telemetria;
5. **Mitigações e Boas Práticas Defensivas** para desenvolvimento seguro em Unity.

---

## 2. A Superfície de Ataque e Engenharia Reversa

### 2.1 A Estrutura do Binário IL2CPP

Em aplicações Unity IL2CPP, o aplicativo carrega dois componentes fundamentais:
* `lib/arm64-v8a/libil2cpp.so`: Binário ELF com o código de máquina gerado a partir do C#.
* `assets/bin/Data/Managed/Metadata/global-metadata.dat`: Arquivo de metadados contendo nomes de classes, métodos, campos, strings literais e tabelas de tipos.

Através do processo de análise e correlação de metadados (utilizando REA e ferramentas de dump como o *Il2CppDumper*), os símbolos gerenciados do C# são mapeados de volta aos seus respectivos offsets dentro do `.so`.

### 2.2 Localização do Choke Point (`CurrencyManager::Add`)

A análise de chamadas e fluxo de controle revelou um afunilamento (*choke point*) crítico: todas as premiações e adições de recursos no jogo convergem para o método `CurrencyManager::Add`.

A inspeção detalhada dos símbolos revelou:

| Atributo | Valor / Definição |
| :--- | :--- |
| **Classe** | `CurrencyManager` |
| **Método** | `Add` |
| **Nome Completo** | `CurrencyManager$$Add` |
| **RVA (Hexadecimal)** | `0x2FB5354` |
| **RVA (Decimal)** | `50025300` |
| **Módulo Alvo** | `libil2cpp.so` |
| **Assinatura C#** | `public void Add(string currencyId, int amount, bool shouldCap = False)` |

### 2.3 Mapeamento de Registradores na ABI ARM64 (AAPCS64)

Em sistemas Linux/Android ARM64 de 64 bits, os argumentos de funções seguem a convenção AAPCS64 (*Procedure Call Standard for the ARM 64-bit Architecture*):
* `x0`: Ponteiro para a instância do objeto (`this`).
* `x1`: Ponteiro gerenciado para o primeiro parâmetro (`currencyId`, do tipo `Il2CppString`).
* `w2` (ou registrador de 64 bits `x2` truncado): Inteiro de 32 bits correspondente a `amount`.
* `w3` (`x3`): Booleano correspondente a `shouldCap`.

Identificado que o parâmetro `amount` reside no registrador `x2`/`w2`, tornou-se possível planejar um hook de entrada para sobrescrever este registrador em runtime antes que o corpo do método processe a transação.

---

## 3. Instrumentação Dinâmica sem Root: Injeção do Frida Gadget

Tradicionalmente, o uso do **Frida** em Android exige um binário `frida-server` rodando como `root` no dispositivo (`/data/local/tmp/frida-server`). No entanto, em dispositivos de produção não rooteados ou ambientes corporativos restritos, essa abordagem é inviável.

A solução consiste em utilizar o **Frida Gadget**: uma biblioteca dinâmica compartilhada (`.so`) injetada diretamente dentro do pacote APK. Quando a aplicação é inicializada, o Gadget é carregado pelo runtime do Android e inicia uma thread em segundo plano que abre um socket TCP local (por padrão, na porta `27042`), permitindo que clientes Frida externos se conectem normalmente.

### 3.1 Automatizando o Repackaging com o `objection`

Para injetar o Gadget sem a necessidade de editar manualmente arquivos Smali, tabelas de manifesto e dependências nativas, utilizamos a ferramenta de segurança mobile **Objection**.

O processo de patch executa:
1. Descompilação do APK via `apktool`;
2. Injeção do arquivo `.so` do Frida Gadget dentro de `lib/arm64-v8a/libfrida-gadget.so`;
3. Modificação da Activity principal ou injeção de uma chamada `System.loadLibrary("frida-gadget")` no construtor da classe `Application` no código Smali;
4. Reempacotamento do APK;
5. Assinatura do novo pacote com uma chave de depuração.

#### Comandos Executados:

Identificando a arquitetura alvo (`arm64-v8a`):
```bash
objection patchapk \
  --source y_com.pockethaven.roguelegend_0.610_mod_signed.apk \
  --architecture arm64-v8a
```

Para garantir compatibilidade estrita de versão entre o client Python e o Gadget injetado (eliminando incompatibilidades de protocolo RPC), especificou-se o binário exato do Gadget compilado para ARM64:

```bash
objection patchapk \
  --source y_com.pockethaven.roguelegend_0.610_mod_signed.apk \
  --architecture arm64-v8a \
  --gadget-path .\frida-gadget-17.24.0-android-arm64.so
```

Após o patch, o APK resultante é instalado via `adb`:
```bash
adb install -r y_com.pockethaven.roguelegend_0.610_mod_signed.objection.apk
```

Ao abrir o jogo, a tela aguarda a conexão do Frida (ou continua conforme configurado em `frida-gadget.config.json`). O host pode então redirecionar a porta via ADB:
```bash
adb forward tcp:27042 tcp:27042
```

---

## 4. O Agente de Instrumentação (`agent_100x.js`)

O agente JavaScript injetado via Frida precisa resolver desafios específicos do runtime IL2CPP e das versões recentes do Frida (v17+).

### 4.1 Resolução Dinâmica do Endereço

Como o Android utiliza ASLR (*Address Space Layout Randomization*), o binário `libil2cpp.so` é carregado em um endereço base aleatório a cada inicialização:

```javascript
var modulo = Process.findModuleByName("libil2cpp.so");
var rvaAdd = 0x2FB5354; // RVA descoberto via engenharia reversa
var enderecoAlvo = modulo.base.add(rvaAdd);
```

### 4.2 Decodificação de `Il2CppString`

O argumento `args[1]` não é uma string C (`const char*`), mas um objeto gerenciado da Unity (`Il2CppString`). No layout de memória ARM64:
* `+0x00`: Ponteiro para a classe (`Il2CppClass*`) + estrutura de monitoramento (16 bytes).
* `+0x10`: Inteiro de 32 bits indicando o comprimento da string em caracteres UTF-16.
* `+0x14`: Array sequencial contendo os caracteres codificados em UTF-16.

Função de parsing implementada:
```javascript
function lerStringGerenciada(ptrString) {
  if (!ptrString || ptrString.isNull()) return null;
  try {
    var comprimento = ptrString.add(0x10).readS32();
    if (comprimento > 0 && comprimento <= 4096) {
      return ptrString.add(0x14).readUtf16String(comprimento);
    }
  } catch (e) { /* ponteiro inválido */ }
  return null;
}
```

Durante a execução inicial, o logging revelou as moedas reais utilizadas internamente pelo jogo:
- `coins` (moedas de ouro)
- `gems` (gemas/rubis — a chave interna é `gems`, ao invés de `rubies`)
- `energy`, `tower_tickets`, `dungeon_dive_tickets`, `chaos_energy`

### 4.3 Mutação de Registradores no Frida 17+

Em versões contemporâneas do Frida, modificar diretamente os slots do array `args[]` dentro do `onEnter` pode ser ineficaz ou gerar restrições de escrita de runtime dependendo do backend V8/QuickJS. A técnica mais robusta consiste em modificar diretamente o contexto de CPU da thread:

```javascript
Interceptor.attach(enderecoAlvo, {
  onEnter: function (args) {
    var currencyId = lerStringGerenciada(args[1]);
    var originalAmount = args[2].toInt32();

    // Filtra apenas moedas elegíveis para o multiplicador
    if (["coins", "gems"].indexOf(currencyId) !== -1) {
      var novoAmount = Math.min(2147483647, originalAmount * 100);

      // Mutação direta do registrador ARM64 x2 (w2)
      this.context.x2 = ptr(novoAmount >>> 0);
      this.modificado = true;
      this.amountNovo = novoAmount;
    }
  },
  onLeave: function (retval) {
    // Emite payload estruturado de volta para o orquestrador Python
    send({
      tipo: "chamada",
      metodo: "CurrencyManager$$Add",
      modificado: !!this.modificado,
      quantidadeOriginal: this.amountOriginal,
      quantidadeModificada: this.amountNovo
    });
  }
});
```

---

## 5. Orquestração e Telemetria com Python (`runner.py`)

Para manter o fluxo reprodutivo e rastreável, desenvolveu-se o script CLI `runner.py`. Ele atua como ponte entre a workstation de desenvolvimento e a instância do jogo.

```
+-----------------------------------------------------------+
|                        runner.py                          |
|  - Lê _dump/alvos.json                                    |
|  - Valida RVA vs tamanho do libil2cpp.so                  |
|  - Concatena TARGETS JSON + agent_100x.js                 |
|  - Conecta via TCP (127.0.0.1:27042) ou USB (frida-server)|
+-----------------------------+-----------------------------+
                              |
                              v
                +----------------------------+
                |    Frida Session (TCP)     |
                |   Processo: "Gadget" / PID |
                +-------------+--------------+
                              |
                              v
       +-----------------------------------------------+
       |             Dispositivo / Emulador            |
       |  APK com Frida Gadget injetado                |
       |  Processo: com.pockethaven.roguelegend        |
       |  libil2cpp.so!CurrencyManager::Add (0x2FB5354)|
       +-----------------------------------------------+
```

### 5.1 Principais Funcionalidades do `runner.py`:

1. **Validação Estática Pré-Execução (`--dry-run`):**
   Lê `alvos.json` e verifica se os RVAs calculados não extrapolam o tamanho físico do binário `libil2cpp.so` extraído, prevenindo crashes antes do deploy.

2. **Suporte Híbrido a Gadget e Server:**
   Suporta conexão padrão USB (`frida.get_usb_device()`) e conexão TCP remota (`--host 127.0.0.1:27042`).

3. **Fallback Resiliente de Processos:**
   Ao operar com APKs modificados pelo Objection, o Frida identifica o processo alvo frequentemente pelo nome genérico `"Gadget"` em vez do pacote `com.pockethaven.roguelegend`. O `runner.py` trata automaticamente a exceção `ProcessNotFoundError` e anexa-se ao processo do Gadget de forma transparente:
   ```python
   try:
       return device.attach(processo), None
   except frida.ProcessNotFoundError:
       print("[!] Processo não encontrado — tentando 'Gadget' como fallback...")
       return device.attach("Gadget"), None
   ```

4. **Persistência de Logs em Formato JSONL:**
   Cada evento emitido pelo `send()` do Frida é serializado em arquivos estruturados em `agente/log/<timestamp>.jsonl`, registrando data/hora, thread ID, valores originais, multiplicador aplicado e tempo de execução da rotina.

---

## 6. Resultados e Validação Prática

Ao executar o pipeline:

```bash
python agente/runner.py --host 127.0.0.1:27042
```

O log do console exibe o fluxo em tempo real:
```text
[+] conectando via TCP em 127.0.0.1:27042 ...
[+] device: TCP Device (TCP)
[!] 'com.pockethaven.roguelegend' não encontrado — tentando 'Gadget' como fallback...
[+] anexado ao processo: Gadget (PID=6577)
[+] hooks 1/1 base=0x746d847000
[*] CurrencyManager::Add RVA = 50025300 (0x2fb5354)
[+] HOOK Add instalado @ 0x74707fc354

  CurrencyManager$$Add(currencyId=coins, amount=50, shouldCap=False)  <-- 50 -> 5000 (x100)
  CurrencyManager$$Add(currencyId=gems, amount=10, shouldCap=False)   <-- 10 -> 1000 (x100)
  CurrencyManager$$Add(currencyId=energy, amount=5, shouldCap=False)  [não é moeda alvo]
```

A alteração refletiu-se imediatamente na interface do usuário do jogo: qualquer recompensa de batalha de 50 moedas creditava 5.000 moedas na carteira do jogador, sem requisições adicionais de conferência pelo servidor.

---

## 7. Recomendações e Mitigações Defensivas

Esta prova de conceito evidencia vulnerabilidades comuns em jogos e aplicações mobile client-heavy. Para arquitetar aplicações resistentes a instrumentação e adulteração, recomendam-se as seguintes defesas:

### 1. Autoridade Total no Servidor (*Server-Side Authority*)
Nenhuma transação que envolva moedas, itens cosméticos, progresso de missões ou caixas de recompensa (*loot boxes*) deve depender do cliente para definir o montante. O cliente deve enviar apenas a intenção de ação (ex.: `FinishDungeon(dungeonId)`), e o backend deve calcular a recompensa com base no estado validado do jogo.

### 2. Validação Criptográfica de Requisições (HMAC / Assinatura)
Se determinadas requisições precisarem trafegar informações contextuais, os payloads devem ser assinados utilizando chaves derivadas por sessão e tokens efêmeros, com validação anti-replay (nonces e timestamps).

### 3. Integração com a Google Play Integrity API
Utilizar a **Play Integrity API** para atestar a autenticidade do binário em tempo de execução. O servidor deve recusar sessões onde o veredito de integridade do app indicar que o APK foi recompilado, re-assinado com chave de terceiros ou executado sob ambientes comprometidos.

### 4. Ofuscação de Símbolos e Anti-Instrumentation
* Criptografia ou embaralhamento de strings e nomes no arquivo `global-metadata.dat` (utilizando proteções comerciais como DexGuard, DProtect ou soluções customizadas de IL2CPP).
* Checagem proativa em runtime da presença de sockets abertos em portas conhecidas do Frida (como `27042`), verificação do mapa de memória (`/proc/self/maps`) em busca de bibliotecas `frida-gadget.so` e detecção de pontos de parada em registradores de depuração.

---

## 8. Conclusão

A segurança em aplicações compiladas com Unity/IL2CPP não pode se apoiar na premissa de que o código nativo é imune à engenharia reversa. Conforme demonstrado neste estudo, a combinação de extração de metadados, identificação precisa de convenções de chamada ARM64 e injeção do Frida Gadget via Objection permite a inspeção e alteração cirúrgica do fluxo de execução mesmo em dispositivos sem privilégios de root.

Projetos de software modernos devem adotar uma abordagem *Zero Trust* em relação ao cliente, assumindo que qualquer lógica executada localmente no dispositivo pode — e eventualmente será — instrumentada.
