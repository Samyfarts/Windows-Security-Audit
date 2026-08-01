\# Windows Security Audit



Et PowerShell-prosjekt som samler systeminformasjon og gjennomfører en enkel sikkerhetskontroll av en Windows-maskin.



Prosjektet ble laget som praktisk øvelse i PowerShell, Windows-administrasjon, nettverk og grunnleggende cybersikkerhet.



\## Formål



Målet med prosjektet er å:



\- samle relevant systeminformasjon automatisk

\- kontrollere grunnleggende sikkerhetsinnstillinger

\- identifisere mulige sikkerhetsrisikoer

\- dokumentere status i en lesbar rapport

\- øve på PowerShell-pipelines, objekter og automatisering



\## Funksjoner



PowerShell-scriptet samler informasjon om:



\- operativsystem og buildnummer

\- aktive nettverksadaptere

\- IPv4- og IPv6-adresser

\- standard gateway og DNS-servere

\- aktiv nettverksprofil

\- Windows-brannmur

\- Microsoft Defender

\- lokale brukerkontoer

\- medlemmer av administratorgruppen

\- ledig diskplass

\- aktive TCP-forbindelser

\- prosessene som eier nettverksforbindelsene



\## Prosjektstruktur



```text

Windows-Security-Audit/

├── Windows-Security-Audit.ps1

├── systemrapport.txt

└── README.md

