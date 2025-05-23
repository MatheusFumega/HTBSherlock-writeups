# Solution

In this very easy Sherlock, you will familiarize yourself with Unix auth.log and wtmp logs. We'll explore a scenario where a Confluence server was brute-forced via its SSH service. After gaining access to the server, the attacker performed additional activities, which we can track using auth.log. Although auth.log is primarily used for brute-force analysis, we will delve into the full potential of this artifact in our investigation, including aspects of privilege escalation, persistence, and even some visibility into command execution.


Antes de prosseguirmos com as perguntas, cabe nos perguntamos: O que � cada arqivo dentro do .zip?

`wtmp`: � um arquivo bin�rio que salva todas as atividades de login, logouts e eventos do systema dentro de um Unix-like. Pode ser encontrado na pasta /var/log/wtmp ou /var/adm/wtmp. Cont�m um formato fixo de descri��o, como o nome de usu�rio, terminal, host name ou
ip, hora e tipo do evento. 

`auth.log`: 