---
title: Year of the Rabbit
author: piotr
date: 2024-01-15 15:00:00 +0800
categories: [rozwiązanie]
tags: [ctf, thm]
---

Rozwiązanie pokoju `Year of the Rabbit` z platformy https://tryhackme.com/.

# Podstawowe skanowanie:

## nmap scan

```
└─$ nmap 10.10.31.55
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-30 12:48 EST
Nmap scan report for 10.10.31.55
Host is up (0.044s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.77 seconds
```

## gobuster scan

```
└─$ gobuster dir -u 10.10.31.55 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.31.55
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/assets               (Status: 301) [Size: 311] [--> http://10.10.31.55/assets/]
/.htaccess            (Status: 403) [Size: 276]
/index.html           (Status: 200) [Size: 7853]
/server-status        (Status: 403) [Size: 276]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

Przyglądając się wynikom skanowania można zaobserwować udostępniony zasób:
![shared directory](/assets/img/year_of_the_rabbit/01.png)

zainteresowałem się tymi plikami i wewnątrz pliku style.css znalazłem komentarz:

```
/* Nice to see someone checking the stylesheets.
    Take a look at the page: /sup3r_s3cr3t_fl4g.php
*/
```

przeszedłem do strony wskazanej w komentarzu i tam znalazłem:
![shared directory](/assets/img/year_of_the_rabbit/02.png)

więc zgodnie z informacją podaną na stronie wyłączyłem obsługę JS w swojej przeglądarce. Korzystam z Firefox i w przypadku tej przeglądarki należy w pasku adresu wpisać about:config, zaakceptować ryzyko i kontynuować a następnie wyszukać javascript.enabled i wyłączyć tę wartość. Po tej operacji ponownie wszedłem na tę stronę i zobaczyłem na niej [ten](https://www.youtube.com/watch?v=dQw4w9WgXcQ) filmik. Na pierwszy rzut oka nie było na niej nic, jednak przyglądając się bliżej komunikacji zauważyłem:
![shared directory](/assets/img/year_of_the_rabbit/03.png)
więc odwiedziłem wskazaną stronę i na niej znalazłem obrazek:
![shared directory](/assets/img/year_of_the_rabbit/04.png)
podejrzewałem, że coś jest ukryte wewnątrz obrazka, postanowiłem to sprawdzić:

```
strings Hot_Babe.png
```

i okazało się, że miałem rację:
![shared directory](/assets/img/year_of_the_rabbit/05.png)
więc teraz miałem hasło do ftp, jednak nie znałem nazwy użytkownika. Do zdobycia hasła wykorzystałem narzędzie hydra:

```
hydra -l ftpuser -P ftp_pass_list.txt ftp://10.10.31.55
```

![shared directory](/assets/img/year_of_the_rabbit/06.png)

```
ftp username: ftpuser
password: 5iez1wGXKfPKQ
```

po uzyskaniu dostępu do ftp sprawdziłem jakie pliki są tam dostępne:
![shared directory](/assets/img/year_of_the_rabbit/07.png)
szczególnie zainteresował mnie plik `Eli's_Creds.txt`, postanowiłem go sprawdzić. Po pobraniu i sprawdzeniu tego pliku doszedłem do wniosku, że jest to program napisany w [Brainfuck](https://en.wikipedia.org/wiki/Brainfuck). Najlepszą opcją w tym przypadku jest po prostu uruchomienie tego kodu, skorzystałem z internetowego ![interpretera](https://www.tutorialspoint.com/execute_brainfk_online.php). Po uruchomieniu tego programu otrzymałem nazwę użytkownika (eli) i hasło (DSpDiM1wAEwid). Postanowiłem sprawdzić czy korzystając z tych danych mogę połączyć się przez ssh do maszyny:
![shared directory](/assets/img/year_of_the_rabbit/08.png)
Po uzyskaniu dostępu do maszyny znalazłem plik `user.txt`, jednak plik ten należy do użytkownika gwendoline, jednak nie mogłem odczytać tego pliku. Utknąłem tutaj na chwilę, jednak przypomniałem sobie o wiadomości powitalnej, domyśliłem się, że jest jakiś folder o tej nazwie:

```
find / -type d -name "s3cr3t" 2>/dev/null
```

i okazało się, że moje domysły były prawidłowe. Folder został znaleziony pod tą lokalizacją `/usr/games/s3cr3t` i znajdował się tam ukryty plik:
![shared directory](/assets/img/year_of_the_rabbit/09.png)

![shared directory](/assets/img/year_of_the_rabbit/10.png)

```
Your password is awful, Gwendoline.
It should be at least 60 characters long! Not just MniVCQVhQHUNI
Honestly!

Yours sincerely
   -Root

```

zmieniłem więc użytkownika na gwendoline korzystając z narzędzia su, dzięki temu byłem w stanie uzyskać dostęp do pliku user.txt. Aby zdobyć drugą flagę musiałem znaleźć sposób na podniesienie swoich uprawień, więc standardowo:

```
gwendoline@year-of-the-rabbit:~$ sudo -V
Sudo version 1.8.10p3
Sudoers policy plugin version 1.8.10p3
Sudoers file grammar version 43
Sudoers I/O plugin version 1.8.10p3
```

okazało się, że używana tutaj wersja sudo jest [podatna](https://www.exploit-db.com/exploits/47502). Korzystając z tego exploita podniosłem swoje uprawienia do root i przeczytałem flagę.
