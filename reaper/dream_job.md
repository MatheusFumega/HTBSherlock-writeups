# Solution
Our SIEM (Security Information and Event Management, Analisar e responder) alerted us to a suspicious logon event which needs to be looked at immediately . The alert details were that the IP Address and the Source Workstation name were a mismatch .You are provided a network capture and event logs from the surrounding time around the incident timeframe. Corelate the given evidence and report back to your SOC Manager.

Há dois arquivos:
`ntlmrelay.pcapng`: Diz respeito a um arquivo formato de captura de pacotes que armazena o tráfego de rede bruto para posterior análise.
`Security.evtx`: Diz respeito a um arquivo formato nativo de logs de eventos do Windows, criado pelo Event Viewer para registrar eventos de sistema, segurança e aplicativos

Sabemos que foi um ataque relativo ao OS Windows, uma vez que temos um .evtx

172.17.79.136 -> Forela-WKSTEN002
172.17.79.129 -> Forela-WKSTN001
172.17.79.135 -> Threat Actor
172.17.79.1 -> Router
172.17.79.4 -> ?
172.17.79.2 -> ?
## 1. What is the IP Address for Forela-Wkstn001?

172.17.79.1 -> Router
172.17.79.129 -> Forela-WKSTN001

## 2. What is the IP Address for Forela-Wkstn002?

172.17.79.136 -> Forela-WKSTEN002

## 3. What is the username of the account whose hash was stolen by attacker?

Visualizando no event viewer, pode-se perceber que:

Um objeto de compartilhamento de rede foi acessado.
	
Assunto:
	Identificação de segurança:		S-1-5-21-3239415629-1862073780-2394361899-1601
	Nome da conta:		arthur.kyle
	Domínio da conta:		FORELA
	Identificação de logon:		0x64A799

Informações sobre a rede:	
	Tipo de objeto:		File
	Endereço de origem:		172.17.79.135
	Porta de origem:		40252
	
Informações sobre compartilhamento:
	Nome de compartilhamento:		\\*\IPC$
	Caminho de compartilhamento:		

Informações sobre solicitação de acesso:
	Máscara de acesso:		0x1
	Acessos:		ReadData (ou ListDirectory)


O usuário arthur.kyle tentou ler o SMB do share IPC$. Pass-the-hash costuma gerar no evento 4624 um Logon Type 9 (NewCredentials) com o Logon Process definido como seclogo, sinalizadores raros em cenários legítimos.
Seu evento 4624, porém, apresenta Logon Type 3 (rede) com Logon Process NtLmSsp e Authentication Package NTLM, padrão de NTLMv2 sem uso de seclogo.
Além disso, não há registro de um Sysmon Event ID 10 (acesso ao processo LSASS), outro forte indicador de pass-the-hash quando correlacionado em tempo real.

An NTLM relay attack happens when an attacker can get a target to authenticate to a host they control. They can capture the hash (typically a NetNTLMv2), or relay it to another host.

The NetNTLMv2 hash is not really a hash, but really a cryptographic challenge response. The server asks the client to encrypt some nonce (dummy value, never reused) with their NTLM hash, and then the client does so. When an attacker captures this, they can brute force passwords, for each password generating the NTLM hash, and then trying to decrypt the nonce. If it works, they found the correct password.

Relaying eliminates the need to crack the challenge. Instead, the attacker waits for the victim to attempt to authenticate. Then they start their own authentication to another server. When that server returns a nonce to be encrypted, the attacker passes that on to the victim, who thinks they are authenticating to the attacker. The result is returned to the attacker who returns it to the target server, and the attacker is now authenticated as the relayed user.

A common technique is to poison LLMNR. When a host on a Windows domain tries to visit a host by DNS name, it first queries DNS, but if that fails, it tries link-local multicast name resolution (LLMNR).

## 4. What is the IP Address of Unknown Device used by the attacker to intercept credentials?

No próprio log acima 

## 5. What was the fileshare navigated by the victim user account?

É possível visualizar pelo poison no LLMNR (Link-Local Multicast Name Resolution). É um protocolo de resolução de nomes que permite a hosts Windows descobrirem endereços IP de outros dispositivos na mesma rede local quando o DNS falha.

É também possível visualizar que, no momento que o 172.17.79.136 -> Forela-WKSTEN002 tenta se comunicar com um endereço que o DNS falhou, mas o LLMNR estava poisoned, o threat actor responde com seu próprio IP.

About 15 seconds after the relaying issue where the user mistyped the name of the server, the user on WKSTN002 makes a successful connection to the domain controller, DC01 (172.17.79.4) requesting the share \\DC01\Trip (Task 5). This is likely the share that the user was trying to connect to when they entered D as the hostname instead of DC01

\\DC01\Trip

## 6. What is the source port used to logon to target workstation using the compromised account?

40252 (LOG)

## 7. What is the Logon ID for the malicious session?

0x64A799 (LOG)

## 8. The detection was based on the mismatch of hostname and the assigned IP Address.What is the workstation name and the source IP Address from which the malicious logon occur?

FORELA-WKSTN002, 172.17.79.135; Esse usário que caiu no poison do LLMNR 

## 9. At what UTC time did the the malicious logon happen?

2024-07-31 04:55:16

## 10. What is the share Name accessed as part of the authentication process by the malicious tool used by the attacker?


\\*\IPC$