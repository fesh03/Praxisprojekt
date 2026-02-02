# Praxisprojekt – LLM-gestützte Anomaly Detection in NetFlow-Daten

**Beschreibung:** v1.0-praxisprojekt

Dieses Repository enthält die Artefakte des Praxisprojekts **„LLM‑gestützte Anomaly Detection in Netzwerkdatenpaketen“**. Es umfasst einen MCP‑Server zur Analyse von NetFlow‑Daten, eine REST‑API auf Basis von DuckDB sowie begleitende JSON‑Referenzen und Analyseergebnisse.

## Inhalt & Struktur

- **`mcp/`** – Implementierung des MCP‑Servers für die NetFlow‑Analyse.
  - **`mcp/mcp_server.py`**: FastMCP‑Server mit Tools/Resources (z. B. NetFlow‑Felder, Angriffssignaturen, GeoIP‑Aufrufe).
  - **`mcp/netflow_directory/`**: JSON‑Referenzen (NetFlow‑Spezifikation, Protokoll‑Mapping, Angriffssignaturen).
- **`rest_api/`** – REST‑API für Abfragen auf einer DuckDB‑NetFlow‑Datenbank.
  - **`rest_api/rest_api_server.py`**: FastAPI‑Server mit Endpunkten zur Datenabfrage.
- **`results - Opus 4.5/`** – Beispielhafte Auswertungen/Analyseberichte (Textdateien) zu NetFlow‑IDs.
- **`requirements.txt`** – Python‑Abhängigkeiten.
- **`.env`** – Konfiguration (z. B. Pfade zur DuckDB‑Datei, Ports, JSON‑Ressourcen, REST/MCP‑URL).

## Hinweis zu den Batch‑Dateien

Die Dateien **`start.bat`** und **`stop.bat`** sind **nicht** Teil des Praxisprojekts selbst. Sie dienen lediglich als einfache Start/Stop‑Hilfen, um die Dienste lokal zu starten.

## Voraussetzungen (kurz)

- Python‑Umgebung mit den Abhängigkeiten aus `requirements.txt`.
- Eine DuckDB‑NetFlow‑Datenbankdatei und passende Konfiguration in `.env`.
