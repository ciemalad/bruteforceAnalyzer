# Bruteforce Analyzer

Bruteforce Analyzer to projekt do analizy logów i wykrywania ataków bruteforce. Program sprawdza również adresy IP powiązane z atakiem oraz podaje numer i usługę na atakowanym porcie. 

## Funkcje

- Wykrywanie ataków bruteforce w logach
- Graficzny interfejs
- Możliwość zmiany wyszukiwanych wzorców ataku
- Wyświetlenie reputacji adresów IP podejrzanych o atak
- Reputacja określana na podstawie danych z lokalnej bazy danych lub ze stron Virustotal i AbuseIPDB

## Wymagania

- Python
- PostgreSQL

## Instalacja

1. Zklonuj repozytorium:

    ```bash
    git clone https://github.com/ciemalad/bruteforceAnalyzer.git
    ```

2. Zainstaluj zależności:

    ```bash
    pip install requirements.txt
    ```

3. Zaimportuj plik ip_rep.sql do PostgreSQL:

    
5. Uruchom aplikację:

    ```bash
    python main.py
    ```
