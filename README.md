# FlexScanner

FlexScanner é um scanner local para Android, feito para rodar pelo Termux e ajudar na análise de possíveis vestígios de executores, scripts e alterações relacionadas ao Roblox.

O scanner trabalha em modo somente leitura: ele não executa scripts encontrados, não apaga arquivos e não envia o conteúdo do aparelho para nenhum servidor.

## O que ele verifica

O FlexScanner analisa as áreas que o Android permite acessar e procura por sinais que merecem revisão, incluindo:

- pastas e arquivos associados a executores;
- diretórios como `autoexec` e `autoexecute`;
- arquivos `.lua`, `.luau` e alguns `.txt`;
- indicadores dentro de scripts, como `loadstring`, `HttpGet`, `getgenv` e outras APIs configuradas;
- cópias residuais em lixeiras e pastas de recycle acessíveis;
- pacote instalado do Roblox (`com.roblox.client`);
- aplicativo responsável pela instalação do Roblox;
- caminhos dos APKs instalados;
- SHA-256 dos APKs quando o Android permite a leitura;
- certificado de assinatura do APK usando `apksigner` quando disponível;
- `Android/data/com.roblox.client` quando acessível;
- `Android/obb/com.roblox.client` quando acessível.

As regras usadas pelo scanner ficam em `config/signatures.json`, então novos indicadores podem ser adicionados sem precisar reescrever o projeto.

## Instalação

Depois de subir este repositório no GitHub, troque `SEU_USUARIO` pelo seu usuário e rode no Termux:

```bash
pkg update -y && pkg install -y git && rm -rf ~/FlexScanner && git clone https://github.com/SEU_USUARIO/FlexScanner.git ~/FlexScanner && cd ~/FlexScanner && bash install_and_scan.sh
```

Na primeira execução, o Android pode pedir permissão para o Termux acessar o armazenamento compartilhado. Libere o acesso e volte para o Termux.

O instalador configura as dependências necessárias e inicia a primeira varredura automaticamente.

## Rodar novamente

Depois da instalação:

```bash
cd ~/FlexScanner && bash scan.sh
```

Por padrão, a tela do Termux é limpa antes do relatório final aparecer. Isso deixa somente o resultado da análise visível.

Para manter o conteúdo anterior do terminal:

```bash
bash scan.sh --no-clear
```

## Classificação de risco

Os resultados são separados em três níveis:

### Low Risk

Indícios fracos ou isolados. Podem ser arquivos comuns, nomes genéricos ou situações que sozinhas não indicam uso de exploit.

### Medium Risk

Itens que merecem investigação. Normalmente representam uma combinação mais relevante de caminho, nome, conteúdo ou instalação fora do padrão esperado.

### High Risk

Evidências fortes, como múltiplos indicadores compatíveis entre si ou uma divergência de assinatura configurada como confiável.

Um único arquivo Lua ou uma instalação fora da Play Store não é tratado automaticamente como prova.

## Veredito final

No fim da análise o FlexScanner mostra um dos seguintes códigos:

- `NO_STRONG_EVIDENCE`: nenhum conjunto forte de evidências foi encontrado;
- `INVESTIGATE_FURTHER`: existem sinais suficientes para revisar o aparelho com mais atenção;
- `STRONG_EVIDENCE_REVIEW_FOR_BAN`: foram encontrados múltiplos sinais fortes e independentes, ou uma divergência crítica configurada nas regras.

O último nível significa que o caso possui evidência forte para revisão pelas regras da competição. O scanner não executa ban automaticamente.

## Relatórios

Cada execução gera dois arquivos:

```text
reports/scan-report.txt
reports/scan-report.json
```

O relatório do terminal é dividido em:

```text
HIGH RISK
MEDIUM RISK
LOW RISK
SCAN COVERAGE
FINAL VERDICT
```

O JSON guarda os mesmos dados em formato estruturado para análise ou integração futura.

## Certificado oficial do Roblox

A lista `official_roblox_cert_sha256` dentro de `config/signatures.json` começa vazia de propósito.

Para usar verificação rígida de assinatura, adicione somente fingerprints SHA-256 obtidos de uma instalação oficial que você considera confiável. Quando o APK puder ser lido, uma assinatura diferente da allowlist será marcada como evidência de alto risco.

## Limitações do Android

Android 11 ou superior pode bloquear o acesso de aplicativos comuns a `Android/data`, `Android/obb` e arquivos internos de outros aplicativos.

Quando uma dessas áreas não pode ser lida, o FlexScanner mostra a região como não verificada. Ele nunca considera uma área bloqueada como limpa.

Também não é possível garantir a recuperação de arquivos que já foram realmente apagados da memória do aparelho. O scanner consegue procurar apenas cópias e vestígios que ainda estejam presentes em locais acessíveis, como lixeiras, pastas residuais ou armazenamento compartilhado.

## Privacidade

A varredura acontece localmente no aparelho.

O FlexScanner não:

- envia arquivos encontrados;
- faz upload do conteúdo dos scripts;
- executa Lua encontrado no aparelho;
- modifica os arquivos analisados;
- remove vestígios automaticamente.

## Atualizando as regras

Os principais indicadores ficam em:

```text
config/signatures.json
```

Nesse arquivo é possível manter:

- nomes de executores;
- nomes de pastas suspeitas;
- indicadores Lua/Luau;
- nomes de lixeiras e diretórios residuais;
- termos de contexto;
- fingerprints confiáveis de certificado APK.

## Testes

Para verificar as regras principais de classificação:

```bash
python -m unittest discover -s tests -v
```

## Estrutura

```text
FlexScanner/
├── config/
│   └── signatures.json
├── flexscanner/
│   ├── cli.py
│   ├── models.py
│   ├── package.py
│   ├── report.py
│   ├── rules.py
│   ├── storage.py
│   └── util.py
├── tests/
│   └── test_report.py
├── install_and_scan.sh
├── scan.sh
├── LICENSE
└── README.md
```
