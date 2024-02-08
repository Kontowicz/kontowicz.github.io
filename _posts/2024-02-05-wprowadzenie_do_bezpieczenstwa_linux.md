---
title: Wprowadzenie do bezpieczeństwa Linux część 1
author: piotr
date: 2024-02-05 15:00:00 +0800
categories: [notatki]
tags: [szkolenia, sekurakacademy]
---

# Co może chcieć zrobić intruz?

W zależności od rodzaju ataku:

- celowany: zaszyfrowanie danych, kradzież konkretnych danych, nieautoryzowana zmiana danych.
- zautomatyzowany: kopanie kryptowalut, hostowanie stron, wysyłanie spamu, generalnie wykorzystanie naszego komputera krótko i intensywnie lub dłużej ale w ukryciu.

# Typowe drogi ataku

Typową drogą ataku jest SSH/konsola w tym scenariuszu atakujący w jakiś sposób wchodzą w posiadanie danych do logowania. Dane do logowania atakujący mogą uzyskać w wyniku ataku bruteforce lub po prostu jakiegoś wycieku danych. Kolejną typową drogą ataku są wszelkie aplikacje/usługi działające w naszej infrastrukturze.

# Skąd się biorą logi:

Podczas szkolenia omawiane były dwie dystrybujce Ubuntu oraz Alma. Do tej pory Logi systemowe można znaleźć w lokalizacji /var/log. Logi najczęściej powstają w wyniku zapisu bezpośredniego - proces otwiera plik logu i zapisuje do niego dane. Druga typowa ścieżka to mechanizm syslog - czyli program wywołuje funkcję systemową zapisującą dane do pliku. Mechanizm ten ma swoje właściwości - przykładowo priorytet zapisu. Aktualnie jest wykorzystywany journald który zbiera dane diagnostyczne oraz może dodatkowo je przetwarzać - np. zapisywać we własnych logach (nie są to pliki tekstowe) przeważnie (choć nie zawsze) przekazuje logi danej do sysloga, który zapisuje je do pliku.

### Ubuntu

Narzędziem do przeglądania logów jest journalctl - warto zwracać uwagę z jakimi uprawieniami uruchamiamy aplikację, czy użytkownika standardowego czy root. Na Ubuntu pliki binarne, w których te dane są trzymane są w `/var/log/journal`.

### Alma

W przypadku tej dystrybucji logi położone są w `/run/log/journal` w **domyślnej konfiguracji logi te nie są trwałe**.

Pamiętaj: Zwróć uwagę na konfigurację journala - czy dane są trwałe czy nie i pamiętaj o nich podczas analizy powłamaniowej - atakujący czyszcząc swoje ślady mógł po prostu o nich zapomnieć.

# Więcej o logach ssh

Właściwie w pliku konfiguracyjnym nie znajdziemy ścieżki wskazującej na plik, w którym dane mają być zapisywane. Znajdziemy dwie wartości `SyslogFacility` oraz `LogLevel`. Wartości te z góry są określone i mogą zostać wyciągnięte z narzędzia `logger`. Istotna jest konfiguracja samego narzędzia syslog, w zależności od jej konfiguracji różne dane mogą trafiać do logów. Warto jest sprawdzić gdzie trafiają dane oraz z jakich procesów/narzędzi. Dodatkowo sam fakt logowania do systemu jest jeszcze logowany w plikach `wtmp` i `btmp` w lokalizacji `/var/log` są to pliki binarne i do ich przeglądania należy korzystać z narzędzi `last` (udane logowania) `lastb` (nieudane logowania). Zostanie też zarejestrony fakt restartu systemu w logu tym będzie informacja o wersji kernela z którym zostanie uruchomiona.

# Logi poza mechanizmem syslog

Nie jest niczym niespotykanym, że jakaś aplikacja loguje dane w niestandardowej lokalizacji, dlatego dobrą praktyką jest przeszukanie folderów na dysku, można użyć komendy:

```
find . -iname '*log' 2>&1
```

Warto też sprawdzić `*err`, `*out`. Pliki takie mogą choćby powstać w wypadku przekierowania wyjścia z wykonania jakiegoś skryptu np. wykonywanego w cronie.

Kolejnymi miejscami, w które warto zajrzeć to:

- historia powłok, także kont usługowych (często leżą poza /home)
- .viminfo, .lesshst
- /var/log/audit/auditd.log jeśli zostało konfigurowane może zawierać dużo danych, które będą przydatne podczas analizy. Plik ten jest zwykłym plikiem tekstowym więc można korzystać z `cat` lub `less`, jednak nie jest to wygodne, lepiej skorzystać z `ausearch` podczas korzystania z tego narzędzia warto dodawać opcję `-i` -> konwertuje ona identyfikatory na przyjemniejsze (np. wstawienie nazwy użytkownika zamiast identyfikatora), `ccze` służy do kolorowania tekstu.

Należy pamiętać o tym, że są to pliki w katalogach użytkowników i mogą oni zrobić z nimi wszystko (w tym zapomnieć o ich istnieniu).

# Użytkownicy, prawa, dostępu

Powinniśmy sprawdzić czy atakujący nie zostawili sobie jakiejś tylnej furtki do naszego systemu, zweryfikujmy:

- kto jest rootem (uid = 0) - włamywacze mogą zmienić uid w `/etc/passwd` i nadać prawa root dowolnemu użytkownikowi,
- kto ma nadane hasła i klucze,
- warto logować dostęp do pliku `/etc/passwd` jak i `/etc/shadow` -> podejrzane może już być sama chęć odczytania tego pliku. Dobrze sprawdzić czy konta usług nie mają nadanych haseł - nie powinny mieć ich nadanych.
- warto zwrócić uwagę na klucze logowania,
- grupy użytkowników: użytkownik może należeć do więcej niż jednej grupy, sprawdzajmy co wynika z tego faktu co czego uprawnia przynaleźność do danej grupy, polecenia komendy,
- sudo: `/etc/sudoers` kontrolowanie poleceń, które użytkownicy mogą wykonywać z uprawieniami root. Standardowi użytkownicy nie powinni móc wykonywać poleceń do odczytywania plików czy też edytorów tekstu z uprawieniami root. **W redhat domyślnie członkowie grupy whell mają uprawienia do sudo**.
- uprawienia do plików: sprawdzajmy uprawienia na plikach, folderach, szczególnie zwracajmy uwagę na istotne dla bezpieczeństwa pliki, należy pamiętać również o setuid/setgid.

Setuid pozwala na uruchomienie programu przez użytkownika systemu z prawami właściciela pliku i następującym poleceniem możemy sprawdzić które pliki mają nadane te uprawienia:

```
find / -perm /u+s, /g+s
```

# Kto jest w systemie

- w:
- who:
- loginctl:
- zadania w tle:

Lista procesów mówi nam najwięcej jeśli wiemy jak system działa w stanie prawidłowym - czyli jakie usługi działają domyślnie, jak system jest skonfigurowany wiedząc to mamy szansę odnaleźć procesy uruchomione/zmienione przez włamywaczy. W folderze `/proc/` znajdują się informacje o procesach - nie jest to folder po prostu reprezentacja tego co się dzieje w sytemie, bardziej pasuje określenie folder wirtualny/tworzony przez system. W folderze możemy znaleźć między innymi kolejne foldery z pewnymi nazwami - nazwy te są takie same jak pid procesu, czyli jeśli mamy jakiś proces o pid x, możemy znaleźć też folder w `/proc/` o nazwie x. W folderze x możemy znelść dodatkowe informacje między innymi jaka binarka działa, z jakiej lokalizacji została uruchomiona, faktyczną nazwę programu który został uruchomiony - może to być przydatne do wyszukiwania procesów ukrywających swoją nazwę. Warto zwracać też uwagę na procesy jądra systemu (w nawiasach []) uruchomionych z konta używkownika - włamywacze mogą ukrywać swoje procesy nadając im nazwę umieszczoną w nawiasach kwadratowych.

```
bash -c "exec -a [kowerker/eth0-driver] vim
```

powyższego polecenia można użyć do ukrycia nazwy procesu.

Proces może wykonywać usunięty plik - czyli szkodliwe oprogramowanie zostaje uruchomione następnie usuwa plik, z którego zostało uruchomione, ale nadal będzie działał w systemie! Przynajmniej go jego restartu.

# Jak zniknąć z oczu admina?

Zaawansowany atakujący może korzystać z narzędzi i technik ukrywania jego działań:

- aliasy/funkcje: mogą zostać dodane aliasy "zmieniające" działanie komend,
- wstrzyknięcie bibliotek,
- podmiana binarek,
- ingenercja w działanie kernela,

Ważna zmienna środowiskowa PATH -> zawiera listę lokalizacji z binarkami, foldery te przeszukiwane są po kolei czyli jeśli atakujący doda coś do wcześniejszej to działanie komendy może zostać zmienione. Również niebezpieczna jest sytuacja, w której atakujący w jakiś sposób kontroluje to jak usawiana jest kolejność w PATH.

LD_PRELOAD - zmienna środowiskowa określająca biblioteki używane przez program. Czyli ktoś może podłożyć zmodyfikowaną bibliotekę która będzie wykorzystywana przez narzędzia

Jeśli podejrzewamy, że jakiś program został podmieniony (na przykład widzimy, że nie zgadza nam się data instalacji/zmiany). Możemy sprawdzić z jakiego pakietu pochodzi binarka:

```
dpkg-quiery -S /bin/ps
```

i zweryfikować czy pliki zainstalowane z tego pakietu nie zostały zmodyfikowane:

```
dpkg --verify /bin/ps
```

jeśli jakieś pliki zostały zmienione (nie zgadza się suma kontrolna, lub uprawienia) to zostanie to wykryte, zweryfikować możemy wszystkie zainstalowane paczki - mówiąc prosto jest to porównanie czy suma kontrolna tego co jest na komputrze zgadza się z tą w bazie danych.

Należy pamiętać, że przestępcy mogą pisać do tymczasowych katalogów: `/tmp`, `/run`, `/var/run`, `/var/tmp`, `/dev/shm`.

Atakujący może korzystać z technik pozwalających mu przetrwać restart systemu lub próby usunięcia szkodliwego oprogramowania:

- cron: `/etc/crontabl`, `/etc/cron.{d|hourly|daily|weekly|...|}`,
- timery systemd,
- daemon atd - uruchamia coś w przyszłości, ale jednoktotnie, współcześnie jest coraz mniej spotykane.

Bardzo częstą sytuacją jest sytuacja, w której wektorem ataku jest aplikacja webowa. Oglądając logi z Apacha, Ngnix naszą uwagę powinny zwracać bardzo długie żądania, do jakich zasobów są kierowane żądania (do jakiego pliku, mogło się okazać, że ktoś już zdążył podłożyć nam jakiś plik, dodatkowo często ono mogą być zaciemnione np. z wykorzystaniem base64). Powinniśmy zwrócić uwagę też na procesy-dzieci serwera WWW jak i również na inicjowanie połączeń - często to nie jest prawidłowe działanie (jeśli aplikacja nie ma takiej funkcjonalności). Powinniśmy też zwrócić uwagę na logi świadczące o wyłączeniu mechanizmów bezpieczeństwa (`setenforce 0`, `/etc/selinux/config`, `selinux=0`, `systemctl stop apparmor`, `aa-disable`, `aa-complain`).

# Kernel i jego moduły

Jak zbadać moduł jądra:
Dla każdego z modułów można wywołać polecenie `modinfo`, dowiemy się z jakiego pliku (lokalizacji) został on załadowany, aktualnie moduły są podpisywane i kernel weryfikuje te podpisy (ale można to wyłączyć) i wszystkie moduły prawdopodobnie będą podpisane tym samym kluczem - istnieje bardzo mała szansa że włamywacz będzie miał moduł podpisany tym samym kluczem. `cat /proc/modules` wypisze listę załadowanych modułów będą tam też flagi, koniecznie trzeba zwrócić uwagę na flagi (0, E) w dowolnej konfiguracji. Kernelowi linuxowemu podczas uruchamiania można podać parametry - przełączeniki zupełnie jak podczas uruchamiania zwykłego programu. Można je sprawdzić w `/proc/cmdline` administrator powinien wiedzieć jakie parametry i dlaczego tam się pojawiają w przypadku jakiś nieprawidłowości mogą one świadczyć o zainfekowaniu komputera.

# Na co jeszcze zwracać uwagę?

Powinniśmy zwracać uwagę na następujące rzeczy:

- `curl/wget` do publicznych adresów ip,
- `curl http://... | sh`: bardzo często malware jest instalowany w ten sposób,
- `cm/ncat`, `socat`, `/dev/tcp`,
- połączenia do githuba - atakujący mogą korzystać z tego serwisu do pobierania szkodliwego oprogramowania,
- pliki coredump: atakujący mogli kompilować coś na komputerze, wynik kompilacji mógł się nie powieść i został stworzony plik coredump.

**Jeśli zauważymy, że już doszło do włamania na nasz komputer powinniśmy zidentyfikować i załatać podatność. Pełną integralność systemu przywraca tylko reinstalacja. Podczas stawiania systemu na nowo koniecznie trzeba zadbać o załatanie wcześniej zidentyfikowanej podatności.**
