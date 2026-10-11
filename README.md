# FlexScanner

FlexScanner é uma ferramenta para Android feita para rodar no Termux e ajudar na verificação de possíveis vestígios de executores, scripts e alterações relacionadas ao Roblox.

Ele faz a varredura das áreas que consegue acessar, organiza os achados por nível de risco e mostra um veredito final de forma simples.

## Origem da instalação

O FlexScanner identifica se o Roblox foi instalado pela Google Play Store ou por uma origem externa. Quando o Android fornece os dados, também mostra qual pacote iniciou a instalação.

Uma instalação externa aparece como indício, não como confirmação de APK modificado. A confirmação forte depende da assinatura do APK ser comparada com uma assinatura oficial confiável configurada no scanner.

## O que ele verifica

- pastas conhecidas de executores;
- diretórios como `autoexec` e `autoexecute`;
- arquivos `.lua`, `.luau` e alguns `.txt`;
- padrões suspeitos dentro de scripts, como `loadstring`, `HttpGet`, `getgenv` e outros indicadores;
- arquivos e pastas residuais que ainda estejam acessíveis;
- instalação do Roblox (`com.roblox.client`);
- data da primeira instalação e da última atualização, quando o Android informar;
- instalador do aplicativo;
- APKs instalados, SHA-256 e certificado quando disponíveis;
- `Android/data/com.roblox.client` e `Android/obb/com.roblox.client` quando o Android permite acesso;
- data de criação das pastas quando o sistema de arquivos disponibilizar essa informação;
- última alteração das pastas acessíveis.

O scanner não executa os arquivos encontrados e não apaga nada do aparelho.

## Instalação

Abra o Termux e rode:

```bash
pkg update -y && pkg install -y git && rm -rf ~/FlexScanner && git clone https://github.com/MyJhonDev/FlexScanner.git ~/FlexScanner && cd ~/FlexScanner && bash install_and_scan.sh
```

Na primeira execução, permita o acesso ao armazenamento quando o Android solicitar.

Depois disso, o FlexScanner instala o necessário e inicia a varredura.

## Rodar novamente

```bash
cd ~/FlexScanner && bash scan.sh
```

Antes de mostrar o resultado, o scanner limpa a tela do Termux para deixar somente o relatório final visível.

## Níveis de risco

### Baixo Risco

Indícios fracos ou isolados que, sozinhos, não são suficientes para considerar o aparelho suspeito.

### Médio Risco

Achados que merecem atenção e podem indicar presença de scripts, executores ou alterações fora do padrão.

### Alto Risco

Evidências mais fortes, principalmente quando vários indicadores suspeitos aparecem juntos.

## Veredito final

No final da varredura, o FlexScanner mostra um resumo com:

```text
ALTO RISCO
MÉDIO RISCO
BAIXO RISCO
COBERTURA DA VARREDURA
VEREDITO FINAL
```

O resultado final fica em uma destas situações:

- `SEM BASE FORTE PARA BAN`: não apareceram indícios fortes na varredura;
- `INVESTIGAR ANTES DE DECIDIR`: existem achados relevantes que ainda precisam ser confirmados;
- `CASO FORTE PARA REVISÃO DE BAN`: foram encontrados sinais fortes em mais de uma categoria.

O FlexScanner mostra os caminhos, arquivos e evidências que levaram ao resultado para facilitar a revisão do caso.

## Relatórios

Cada execução gera:

```text
reports/scan-report.txt
reports/scan-report.json
```

O arquivo `.txt` contém o relatório legível e o `.json` guarda os mesmos dados em formato estruturado.

## Limitações

Algumas versões do Android podem bloquear o acesso a `Android/data`, `Android/obb` e arquivos internos de outros aplicativos. O FlexScanner também não tenta acessar histórico privado de navegadores ou dados internos de outros apps.

Quando isso acontece, o FlexScanner mostra a área como não verificada em vez de considerar que ela está limpa.

Arquivos realmente apagados também podem não ser recuperáveis. O scanner procura apenas vestígios que ainda existam em áreas acessíveis.

## Projeto

Repositório oficial:

https://github.com/MyJhonDev/FlexScanner
