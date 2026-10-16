# Acer Predator Connect X5 — Home Assistant

Lokalna integracja do sterowania listą blokad urządzeń w routerze Acer Predator Connect X5.

**Wersja 0.1.2 jest eksperymentalna.** Protokół odtworzono z kodu panelu X5. Testy offline sprawdzają kryptografię, obsługę sesji i granice sterowania. Pełny cykl blokowania na fizycznym routerze wymaga jeszcze sprawdzenia. Nie jest to oficjalny produkt Acer ani integracja wbudowana w Home Assistant.

## Co otrzymujesz

- Przełącznik „Dostęp do internetu” dla każdego wybranego urządzenia.
- ON: MAC nie jest zablokowany przez router. OFF: MAC jest na liście blokad.
- Konfigurację przez interfejs Home Assistant, wybór urządzeń, dodatkową listę chronionych MAC i zmianę hasła przez „Konfiguruj ponownie”.
- Odczyt stanu co 30 sekund, z możliwością ustawienia 30–600 sekund w opcjach.
- Logowanie i tokeny obsługiwane lokalnie, bez kopiowania ciasteczek przeglądarki.
- Blokadę poleceń spoza wybranej listy, ochronę klienta administracyjnego i sprawdzanie listy blokad po każdej zmianie.

Stan ON opisuje listę blokad, **nie potwierdza rzeczywistej łączności z internetem**. Urządzenie, którego nie ma na żadnej liście routera, ma stan niedostępny. Router identyfikuje urządzenia po MAC; zmiana lub losowanie MAC może ominąć przypisanie.

## Instalacja przez HACS

1. W HACS otwórz menu repozytoriów niestandardowych.
2. Dodaj `https://github.com/infoprojektps-web/ha-acer-predator-connect-x5`, typ **Integration**.
3. Pobierz integrację i uruchom ponownie Home Assistant.
4. Otwórz **Ustawienia → Urządzenia i usługi → Dodaj integrację → Acer Predator Connect X5**.
5. Wpisz adres panelu, łącznie z portem, oraz hasło administratora routera. Hasło podawaj wyłącznie lokalnie w formularzu Home Assistant, nigdy w zgłoszeniach GitHub.
6. Wybierz urządzenia, którymi chcesz sterować. Komputer widoczny dla routera jako klient tego połączenia jest automatycznie chroniony.
7. Opcjonalnie wskaż dodatkowe urządzenia chronione, np. komputer używany do administracji.

Jeśli HACS nie pokazuje nowego repozytorium, instalacja ręczna poniżej nie wymaga HACS. Repozytorium nie jest zgłoszone do domyślnego katalogu HACS.

## Instalacja ręczna

Skopiuj katalog `custom_components/acer_predator_connect` do `<config>/custom_components/acer_predator_connect` w Home Assistant. Uruchom ponownie Home Assistant i wykonaj kroki 4–7 powyżej. Nie kopiuj katalogu `tests` do konfiguracji HA.

Projekt korzysta z biblioteki `cryptography` dostarczanej przez Home Assistant. Nie uruchamia JavaScriptu routera ani zewnętrznych programów. Metody sieciowe działają poza pętlą zdarzeń Home Assistant.

## Pierwszy test

Wybierz jedno niekrytyczne urządzenie. Sprawdź stan w panelu routera, wyłącz przełącznik, porównaj listę blokad, następnie włącz go i potwierdź usunięcie MAC z listy blokad. Sprawdź łączność bezpośrednio na urządzeniu. Pozostaw niezależny dostęp do panelu routera na innym urządzeniu.

Integracja odmawia blokowania, jeśli nie potrafi jednoznacznie znaleźć klienta administracyjnego w odpowiedzi routera. Może to wystąpić np. przy NAT między Home Assistant a routerem. Nie ma opcji wyłączającej tę ochronę.

Nie wykonuje zmian blokad podczas startu, odczytu ani przeładowania integracji. Nie odblokowuje automatycznie urządzeń przy wyłączeniu HA — ustawienia routera pozostają aktywne.

## Harmonogram

Po sprawdzeniu pierwszego urządzenia użyj zwykłych automatyzacji Home Assistant: `switch.turn_off` blokuje dostęp, a `switch.turn_on` odblokowuje. Wybierz encję utworzoną dla konkretnego urządzenia. Nazwa encji zależy od języka i rejestru encji Twojego HA.

## Sesja i błędy

- Od wersji 0.1.1 otwarcie opcji urządzeń używa aktywnej sesji integracji zamiast tworzyć drugie logowanie.
- W wersji 0.1.2 wybrane urządzenia pozostają w opcjach nawet po zniknięciu z obu list routera (np. gdy komputer śpi lub jest offline). Zapis opcji nie usuwa już takich urządzeń ani przypisanych im encji. Ich przełączniki mogą jednak pokazywać „niedostępny”, dopóki router nie zgłosi urządzenia; nie oznacza to blokady.
- Jeśli wszystkie przełączniki są niedostępne, sprawdź **Ustawienia → System → Dzienniki** i komunikat `acer_predator_connect`. Wersje od 0.1.1 zachowują bezpieczny opis przyczyny: błąd połączenia, kod HTTP, błąd danych albo kod sesji routera (33/44/66/77). Nie zapisuje odpowiedzi routera ani danych uwierzytelniania.
- Po zamknięciu pozostałych sesji panelu routera odczekaj co najmniej 5 minut. Jeśli odczyt nie wraca, przeładuj integrację i sprawdź nowy komunikat. Sam stan niedostępny nie oznacza, że urządzenie zostało zablokowane.
- Błędne hasło lub blokada logowania zatrzymują automatyczne próby do ponownej konfiguracji poświadczeń.
- Wygaśnięcie lub uszkodzenie sesji powoduje co najmniej 60 sekund przerwy przed nowym logowaniem.
- Konflikt sesji zgłoszony przez router powoduje co najmniej 5 minut przerwy. Unikaj równoległego administrowania z wielu klientów podczas pierwszych testów.
- Zapis nie jest automatycznie powtarzany po błędzie lub utracie odpowiedzi. Sprawdź aktualną listę blokad przed kolejnym poleceniem.
- Błąd lub brak urządzenia powoduje stan niedostępny; integracja nie zgaduje stanu przełącznika.

## Prywatność i bezpieczeństwo

Hasło jest przechowywane w lokalnym wpisie konfiguracji Home Assistant zgodnie z jego mechanizmem konfiguracji; nie należy traktować go jak szyfrowanego sejfu. Zabezpiecz dostęp do HA i jego kopii zapasowych. Token i klucz sesji pozostają w pamięci procesu. Klient obsługuje ewentualne ciasteczka w pamięci, nie eksportuje ich i nie ma diagnostyki zawierającej sekrety.

Połączenia HTTPS zachowują weryfikację certyfikatu. Przekierowania HTTP są odrzucane, aby nie wysłać nagłówka uwierzytelniania do innego hosta. Używaj panelu tylko we własnej, zaufanej sieci lokalnej. Szyfrowanie aplikacyjne starego firmware nie zastępuje TLS; router używa słabego klucza RSA i niestandardowego wariantu AES. Integracja odtwarza ten protokół wyłącznie dla zgodności.

Nie publikuj hasła, `Authorization`, `enData`, tokenów, ciasteczek, plików HAR ani zrzutów pamięci w zgłoszeniach. Repozytorium nie zawiera danych sesji ani listy urządzeń autora.

## Zgodność i ograniczenia

- Odtworzono wariant panelu zawierający pliki `app.3be44859.js` i `chunk-0c29480a.273975fd.js`. Nie znamy numeru firmware odpowiadającego tym plikom.
- Nie deklarujemy zgodności z X3, X7, innym firmware ani panelami o innym protokole.
- Kod oczekuje pól `ConnectedDevicesList`, `BlockedDevicesList`, `clientIpAddress` oraz pól urządzeń `Mac`, `Name`, `Ip`, opcjonalnie `Ipv6`.
- Aktualny zakres walidacji: patrz [VALIDATION.md](VALIDATION.md).

## Testy dla programistów

Python 3.12+ i `cryptography`:

```text
python -m pip install cryptography
python -m unittest discover -s tests -v
python -m compileall -q custom_components
```

Wektory `tests/cryptojs_vectors.json` powstały przy użyciu oryginalnej biblioteki CryptoJS 4.2.0. Klucze testowe i dane w testach są sztuczne. Testy nie łączą się z routerem. Osobny skrypt `tests/ha_smoke.py` wymaga zainstalowanego Home Assistant i sprawdza importy, schematy formularzy oraz zachowanie przełącznika. CI wykonuje go w Linuksie na aktualnym HA, rozwiązywanym przez pip.

## Źródła protokołu i dokumentacji

Protokół opisuje [PROTOCOL.md](PROTOCOL.md). Kod klienta napisano od podstaw na podstawie obserwowanego zachowania i analizy modułów panelu; nie publikujemy pakietów firmware.

- [Home Assistant: config flow](https://developers.home-assistant.io/docs/core/integration/config_flow/)
- [Home Assistant: switch](https://developers.home-assistant.io/docs/core/entity/switch/)
- [HACS: integracje](https://www.hacs.xyz/docs/publish/integration/)
- [CryptoJS 4.2.0](https://github.com/brix/crypto-js/tree/4.2.0)

Licencja kodu integracji: MIT. Acer i Predator są znakami swoich właścicieli.
