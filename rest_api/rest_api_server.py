"""
REST API Server für DuckDB NetFlow-Datenbank
Stellt Endpunkte bereit, um NetFlow-Daten abzufragen
"""
from fastapi import FastAPI, Depends, HTTPException, Query # Quary: Parameter in der URL werden mit ?param=value übergeben
from fastapi.routing import APIRoute
import duckdb, logging
from typing import Generator
from dotenv import load_dotenv
from pathlib import Path
import os

#=======================================================================
# KONFIGURATION
#=======================================================================

# Lädt die Variablen aus der .env-Datei
load_dotenv()

# Hauptvariable aus Umgebungsvariable lesen
DATASET_PATH = os.getenv("DATASET_PATH")

# Datentyp der Datenbank: DuckDB
DATATYPE_DATASET = Path(DATASET_PATH).suffix.lstrip(".")

# Name, den die Tabelle in DuckDB schon hat!
TABLE_NAME = os.getenv("TABLE_NAME", "data")

# Datenbank: Name der Datenbank (für DuckDB nicht relevant, aber für API-Antworten nützlich)
DATABASE_NAME = Path(DATASET_PATH).stem # stem gibt den Dateinamen ohne Erweiterung zurück

# Logging konfigurieren
logger = logging.getLogger(__name__)

#=======================================================================
# FASTAPI APP INITIALISIERUNG
#=======================================================================
app = FastAPI(
    title="DuckDB NetFlow Datenbank",
    description="REST API Server für DuckDB NetFlow-Datenbank",
    version="1.0.0"
)

#=======================================================================
# 0. VERBINDUNGSVERWALTUNG
#=======================================================================

# Diese Funktion verwaltet die Verbindung zu DuckDB.
def get_db_connection() -> Generator[duckdb.DuckDBPyConnection, None, None]:
    """
    Erstellt die DuckDB-Verbindung und gibt eine klare HTTPException bei Fehler zurück.
    """
    con = None  # Deklaration der Variable außerhalb des try-Blocks
    try:
        con = duckdb.connect(database=DATASET_PATH, read_only=True)
        # Die Verbindung bleibt bis zum Ende der Anfrage offen
        yield con

    except duckdb.Error as e:
        # Fehlerbehandlung, falls die Datenbankverbindung fehlschlägt
        raise HTTPException(
            status_code=500,
            detail=f"Datenbankfehler: Konnte die DuckDB-Datei nicht öffnen oder verbinden. Prüfen Sie den Pfad ({DATASET_PATH}). Fehler: {e}"
        )
    finally:
        # Stellt sicher, dass die Verbindung nach der Anfrage IMMER geschlossen wird
        if con:
            con.close()

def database_type() -> str:
    """
    Gibt den Typ der Datenbank zurück.
    """
    return DATATYPE_DATASET

# Hilfsfunktion zur Typkonvertierung
def get_parameter_type(annotation) -> str:
    """Konvertiert Python-Typen zu JSON-Schema-Typen"""
    type_mapping = {
        int: "integer",
        str: "string",
        float: "number",
        bool: "boolean",
        list: "array",
        dict: "object"
    }

    origin = getattr(annotation, "__origin__", None)
    if origin is not None:
        annotation = origin

    return type_mapping.get(annotation, "string")

# Hilfsfunktion zur IP-Validierung
def validate_ip_address(ip: str) -> None:
    """Basic IP address validation."""
    if len(ip.strip().split('.')) != 4:
        raise HTTPException(
            status_code=406,
            detail ="IPv4-Adresse muss aus 4 Oktetten bestehen."
        )
    elif not all(0 <= int(part) <= 255 for part in ip.strip().split('.')):
        # Prüft, ob alle Teile Zahlen zwischen 0 und 255 sind
        raise HTTPException(
            status_code=406,
            detail="Jedes Oktett der IPv4-Adresse muss zwischen 0 und 255 liegen."
        )
    return None

#=======================================================================
# API-ROUTEN: UTILITY ENDPOINTS
#=======================================================================
# Route zum Auflisten aller definierten API-Routen
@app.get("/", tags=["Utility"])
def root():
    """
        Listet alle verfügbaren API-Routen auf.
    """
    functions = []

    for route in app.routes:
        if not hasattr(route, "dependant"):
            continue

        parameters = {}
        required = []

        # Path-Parameter
        for param in route.dependant.path_params:
            # Pydantic v1: outer_type_, Pydantic v2: annotation
            param_type = getattr(param, "annotation", None) or getattr(param, "outer_type_", str)
            param_description = getattr(param.field_info, "description", None) if hasattr(param, "field_info") else None

            parameters[param.name] = {
                "type": get_parameter_type(param_type),
                "description": param_description or f"Path parameter: {param.name}",
            }

            # Required prüfen
            is_required = getattr(param, "required", True)
            if is_required:
                required.append(param.name)

        # Query-Parameter: Bspw. /data/netflow_id?id=123&show_attack=true
        for param in route.dependant.query_params:
            param_type = getattr(param, "annotation", None) or getattr(param, "outer_type_", str)
            param_description = getattr(param.field_info, "description", None) if hasattr(param, "field_info") else None

            parameters[param.name] = {
                "type": get_parameter_type(param_type),
                "description": param_description or f"Query parameter: {param.name}",
            }

            is_required = getattr(param, "required", False)
            if is_required:
                required.append(param.name)

        # Body-Parameter: Bspw. bei POST/PUT Anfragen
        if route.dependant.body_params:
            for param in route.dependant.body_params:
                param_type = getattr(param, "annotation", None) or getattr(param, "outer_type_", None)

                # Pydantic Model auflösen
                if param_type and hasattr(param_type, "__fields__"):
                    for field_name, field in param_type.__fields__.items():
                        field_type = getattr(field, "annotation", None) or getattr(field, "outer_type_", str)
                        field_desc = getattr(field.field_info, "description", None) if hasattr(field,
                                                                                               "field_info") else None

                        parameters[field_name] = {
                            "type": get_parameter_type(field_type),
                            "description": field_desc or f"Body field: {field_name}",
                        }

                        is_required = getattr(field, "required", False)
                        if is_required:
                            required.append(field_name)

        functions.append({
            "tag": route.tags[0] if route.tags else "default",
            "path": route.path,
            "name": route.name,
            "description": route.description or getattr(route, "summary", None) or "No description",
            "parameters": parameters,
            "required": required,
        })

    return {
        "api_name": "DuckDB REST API",
        "version": "1.0",
        "functions": functions
    }

@app.get("/data/netflow_id", tags=["Utility", "Analysis"])
def get_netflow_by_id(
        id: int = Query(..., description="Die ID des Netflows, die abgerufen werden soll."),
        show_attack: bool = Query(False, description="Ob die 'Attack'- und 'Label'-Spalte im Ergebnis angezeigt werden soll."),
        con: duckdb.DuckDBPyConnection = Depends(get_db_connection)
):
    """
        Ruft einen Netflow-Eintrag basierend auf der angegebenen netflow_id ab.
        :param id: Die ID des Netflows, der abgerufen werden soll.
        :param show_attack: Ob die 'Attack'- und 'Label'-Spalte im Ergebnis angezeigt werden soll.
        :param con: Die aktive DuckDB-Verbindung injiziert durch 'Depends()'.
        :return: Ein Dictionary mit dem Netflow-Eintrag.
        ️ Hinweis: Passen Sie den Spaltennamen 'netflow_id' in der Abfrage an den tatsächlichen Spaltennamen in Ihrer Tabelle an.
        ️ Hinweis: Standardmäßig werden 'Attack' und 'Label' ausgeblendet, um sensible Informationen zu schützen.
    """
    #
    ATTACK_COLUMN = os.getenv("ATTACK_COLUMN", "Attack")
    LABEL_COLUMN = os.getenv("LABEL_COLUMN", "Label")

    # query vorbereiten
    if show_attack:
        selected_columns = ", ".join([
            col[0] for col in con.execute(f"DESCRIBE {TABLE_NAME}").fetchall()
            if col[0] not in [LABEL_COLUMN]
        ])
    else:
        selected_columns = ", ".join([
            col[0] for col in con.execute(f"DESCRIBE {TABLE_NAME}").fetchall()
            if col[0] not in [ATTACK_COLUMN, LABEL_COLUMN]
        ])

    query = f"""
        SELECT 
            {selected_columns}
        FROM {TABLE_NAME} 
        WHERE netflow_id = ?;
    """

    try:
        # Führe die Abfrage aus und übergib die netflow_id als Parameter (Tupel)
        result = con.execute(query, (id,)).fetchone()

        if result is None:
            raise HTTPException(status_code=404, detail=f"Kein Netflow mit ID {id} gefunden.")

        # Spaltennamen dynamisch abrufen
        columns = [desc[0] for desc in con.execute(query, (id,)).description]

        # Konvertierung des Ergebnisses in ein Dictionary
        netflow_entry = dict(zip(columns, result))

        return {
            "status": "success",
            "netflow_entry": netflow_entry
        }
    except duckdb.Error as e:
        # Fehlerbehandlung, falls die Datenbank nicht reagiert oder die Abfrage fehlschlägt
        raise HTTPException(status_code=500, detail=f"Datenbankfehler: {e}")

@app.get("/data/info", tags=["Utility"])
def dataset_info(
        con: duckdb.DuckDBPyConnection = Depends(get_db_connection)
):
    """
        Gibt die Informationen zum Datensatz zurück.
        :param con: Die aktive DuckDB-Verbindung injiziert durch 'Depends()'.
        :return: Ein Dictionary mit Informationen zum Datensatz.
    """

    # Führe die Abfrage aus
    result = con.execute(f"SELECT COUNT(*) AS total_count FROM {TABLE_NAME}").fetchone()

    # Extrahieren des Zählwerts (erster Wert im zurückgegebenen Tupel)
    count = result[0] if result else 0

    return {
        "status": "success",
        "dataset_info": {
            "database_file": DATASET_PATH,
            "database_type": database_type(),
            "table_name": TABLE_NAME,
            "database_name": DATABASE_NAME,
            "entries": count
        }
    }

@app.get("/data/features", tags=["Utility"])
def list_features(
        con: duckdb.DuckDBPyConnection = Depends(get_db_connection)
):
    """
        Listet alle Spalten (Features) der Tabelle in der DuckDB-Datei auf.

        :param con: Die aktive DuckDB-Verbindung injiziert durch 'Depends()'.
        :return: Ein Dictionary mit der Liste der Spaltennamen.
    """

    # SQL-Abfrage zum Abrufen der Spalteninformationen
    query = f"DESCRIBE {TABLE_NAME}"

    # Führe die Abfrage aus und hole alle Ergebnisse
    result = con.execute(query).fetchall()

    # Extrahieren der Spaltennamen und -typen
    columns = [{"column_name": row[0], "data_type": row[1]} for row in result]

    # Rückgabe des Ergebnisses
    return {
        "status": "success",
        "total_columns": len(columns),
        "columns": columns
    }

#=======================================================================
# API-ROUTEN: ANALYSE ENDPOINTS
#=======================================================================
@app.get("/data/check_ip", tags=["Analysis"])
def check_ip_frequency(
        ip: str = Query(..., description="IP-Adresse"),
        con: duckdb.DuckDBPyConnection = Depends(get_db_connection)
):
    """
        Prüft, ob eine IP-Adresse im Datensatz existiert und wie oft sie auftritt.

        :param ip: Die gesuchte IP-Adresse (als Pfadparameter).
        :param con: Die aktive (lesbare) DuckDB-Verbindung.
        :return: Ein Dictionary mit der Zählung.
    """

    # Parameter Validierung
    validate_ip_address(ip)

    # WICHTIG: Passen Sie 'ip_spalte' an den tatsächlichen Spaltennamen in Ihrer Tabelle an!
    IP_SRC_COLUMN = os.getenv("IP_SRC_COLUMN", "IPV4_SRC_ADDR")
    IP_DST_COLUMN = os.getenv("IP_DST_COLUMN", "IPV4_DST_ADDR")

    # SQL-Abfrage mit Platzhaltern für die IP-Adresse: Wie oft kam die IP in dem Datensatz vor?
    query = f"""
        SELECT 
            COUNT(*) AS ip_count
        FROM {TABLE_NAME}
        WHERE {IP_SRC_COLUMN} = ? OR {IP_DST_COLUMN} = ?;
    """

    try:
        # Führe die Abfrage aus und übergib die IP-Adresse als Parameter (Tupel)
        result = con.execute(query, (ip, ip)).fetchone()

        # Extrahieren des Zählwerts (erster Wert im zurückgegebenen Tupel)
        ip_count = result[0] if result else 0

        return {
            "status": "success",
            "ip_address": ip,
            "occurrences": ip_count
        }
    except duckdb.Error as e:
        # Fehlerbehandlung, falls die Datenbank nicht reagiert oder die Abfrage fehlschlägt
        raise HTTPException(status_code=500, detail=f"Datenbankfehler: {e}")

@app.get("/data/ip_history_search", tags=["Analysis"])
async def get_ip_history(
        src_ip: str = Query(..., description="Quell-IP-Adresse"),
        dst_ip: str = Query(..., description="Ziel-IP-Adresse"),
        sample_size: int = Query(3, description="Anzahl der zufälligen Flows, die ausgegeben werden sollen."), # Standardwert 3, kann angepasst werden
        con: duckdb.DuckDBPyConnection = Depends(get_db_connection)
):
    """
        Sucht in der DuckDB-Tabelle nach 'sample-size'-ZUFÄLLIGEN STICHPROBEN
        von Flows, die EXAKT der angegebenen Quell- und Ziel-IP-Kombination entsprechen.

        :param src_ip: Die Quell-IP-Adresse.
        :param dst_ip: Die Ziel-IP-Adresse.
        :param sample_size: Die Anzahl der zufälligen Flows, die zurückgegeben werden sollen.
        :param con: Die aktive DuckDB-Verbindung injiziert durch 'Depends()'.
        :return: Ein Dictionary mit den gefundenen Flows.
    ️ Hinweis: Diese Abfrage verwendet die DuckDB 'SAMPLE' Funktion, um eine zufällige Stichprobe zu ziehen.
    """

    # 0. Wichtige Spaltennamen; Können so angepasst werden, dass diese beim Aufrufen der funktion geändert werden können
    IPV4_SRC_COLUMN = os.getenv("IPV4_SRC_COLUMN", "IPV4_SRC_ADDR")
    IPV4_DST_COLUMN = os.getenv("IPV4_DST_COLUMN", "IPV4_DST_ADDR")

    # 1. Parameter Validierung
    validate_ip_address(src_ip)
    validate_ip_address(dst_ip)
    if sample_size <= 0:
        raise HTTPException(status_code=400, detail="Die 'sample_size' muss größer als 0 sein.")

    # 2. SQL-Abfrage für exakte Treffer mit SAMPLE
    selected_columns = os.getenv("SELECTED_COLUMNS", "*")  # Standardmäßig alle Spalten auswählen

    # Abfrage mit SAMPLE
    query_sample = f"""
        SELECT 
            {selected_columns} -- Nur die gewünschten Spalten auswählen
        FROM (
            -- Innere Abfrage: Filtert die exakten src/dst IP-Treffer, um die Stichprobe zu ziehen
            SELECT * FROM {TABLE_NAME} 
            WHERE {IPV4_SRC_COLUMN} = ? AND {IPV4_DST_COLUMN} = ?
        ) AS filtered_flows
        -- Äußere Abfrage: Wählt das Sample aus den gefilterten Flows aus
        USING SAMPLE {sample_size} ROWS;
    """

    # Zusätzliche Abfrage, um die Gesamtanzahl der exakten Treffer zu zählen
    query_count = f"""
        SELECT 
            COUNT(*) AS total_count -- Zählt die Gesamtanzahl der exakten Treffer
        FROM {TABLE_NAME} -- Haupttabelle
        WHERE {IPV4_SRC_COLUMN} = ? AND {IPV4_DST_COLUMN} = ?;
    """

    params = (src_ip, dst_ip)

    # 3. Abfrage ausführen und Spaltennamen dynamisch abrufen
    try:
        # Führen Sie die Abfrage aus, um das Cursor-Objekt zu erhalten
        cursor = con.execute(query_sample, params) # 'sample_size' wird direkt in der Abfrage verwendet


        # Dynamisches Abrufen der Spaltennamen, da SELECT * verwendet wird
        columns = [desc[0] for desc in cursor.description]

        # Jetzt die Daten abrufen (Liste von Tupeln)
        related_flows_raw = cursor.fetchall()

    except duckdb.Error as e:
        logger.error(f"DuckDB Query Error: {e}")
        raise HTTPException(status_code=500, detail=f"Datenbankfehler während der Abfrage: {e}")

    # 4. Ergebnisse verarbeiten
    related_flows_count = len(related_flows_raw)

    if related_flows_count == 0:
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "message": f"Keine Flows gefunden, die EXAKT von {src_ip} nach {dst_ip} gehen.",
            "flows_total_count": 0,
            "flows_preview_count": 0,
            "flows": []
        }

    # Konvertierung der Tupel-Ergebnisse in Dictionaries
    flows_processed = [
        dict(zip(columns, flow)) for flow in related_flows_raw
    ]

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "flows_total_count": con.execute(query_count, params).fetchone()[0], # Gesamtanzahl der exakten Treffer
        "flows_preview_count": len(flows_processed), # Zeigt die Anzahl der tatsächlich abgerufenen Samples
        "flows": flows_processed # Gibt die verarbeiteten Dictionaries zurück
    }

@app.get("/data/ip_threats", tags=["Analysis"])
async def get_ip_labeled_threats(
        src_ip: str = Query(..., description="Quell-IP-Adresse"),
        dst_ip: str = Query(..., description="Ziel-IP-Adresse"),
        con: duckdb.DuckDBPyConnection = Depends(get_db_connection)
):
    """
        Listet alle Attack-Typen auf, die mit Label=1 für die Quell- und Ziel-IP (separat) verbunden sind.
    """

    # 0. Wichtige Spaltennamen; Können so angepasst werden, dass diese beim Aufrufen der funktion geändert werden können
    ATTACK_COLUMN = os.getenv("ATTACK_COLUMN", "Attack")
    LABEL_COLUMN = os.getenv("LABEL_COLUMN", "Label")

    # 1. Parameter Validierung
    validate_ip_address(src_ip)
    validate_ip_address(dst_ip)

    # Dictionary zum Speichern der aggregierten Ergebnisse
    threat_report = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_threats_labeled": {},  # Angriffe von src_ip
        "dst_threats_labeled": {},  # Angriffe auf dst_ip
    }

    try:
        # --- 1. Aggregation für die Quell-IP (Angriffe von src_ip) ---

        # SQL-Query: Zähle Attack-Typen, die von src_ip ausgehen UND Label=1 haben
        src_query = f"""
            SELECT 
                {ATTACK_COLUMN} AS threat_type, 
                COUNT(*) AS count
            FROM {TABLE_NAME}
            WHERE 
                IPV4_SRC_ADDR = ? 
                AND {LABEL_COLUMN} = 1 
                AND {ATTACK_COLUMN} IS NOT NULL 
                AND {ATTACK_COLUMN} != ''
            GROUP BY threat_type
            ORDER BY count DESC;
        """
        src_threats_raw = con.execute(src_query, (src_ip,)).fetchall()

        # Konvertierung des Ergebnisses in ein Dictionary
        threat_report["src_threats_labeled"] = [threat for threat, _ in src_threats_raw]

        # 2. Aggregation für die Ziel-IP (Angriffe auf dst_ip)

        # SQL-Query: Zähle Attack-Typen, die auf dst_ip abzielen UND Label=1 haben
        dst_query = f"""
            SELECT 
                {ATTACK_COLUMN} AS threat_type, 
                COUNT(*) AS count
            FROM {TABLE_NAME}
            WHERE 
                IPV4_DST_ADDR = ? 
                AND {LABEL_COLUMN} = 1 
                AND {ATTACK_COLUMN} IS NOT NULL 
                AND {ATTACK_COLUMN} != ''
            GROUP BY threat_type
            ORDER BY count DESC;
        """

        # Debug-Logging
        logger.info(f"Executing DST Query: {dst_query} with IP: {dst_ip}")

        # Führe die Abfrage aus
        dst_threats_raw = con.execute(dst_query, (dst_ip,)).fetchall()

        # Konvertierung des Ergebnisses in ein Dictionary
        threat_report["dst_threats_labeled"] = [threat for threat, _ in dst_threats_raw]

        # 3. Abschluss und Gesamtzusammenfassung
        total_src_count = len(threat_report["src_threats_labeled"])
        total_dst_count = len(threat_report["dst_threats_labeled"])

        if total_src_count + total_dst_count == 0:
            return {
                "status": "success",
                "message": f"Keine Bedrohungen für {src_ip} oder {dst_ip} gefunden.",
                **threat_report  # Fügt die leeren Dictionaries hinzu
            }

        return {
            "status": "success",
            **threat_report
        }

    except duckdb.Error as e:
        logger.error(f"DuckDB Query Error: {e}")
        raise HTTPException(status_code=500, detail=f"Datenbankfehler während der Abfrage: {e}")

### 3. WEITERE ENDPOINTS KÖNNEN HIER FOLGEN ###
# Zum Beispiel: Abfragen von Einträgen, Statistiken, benutzerdefinierte Abfragen, etc.
#=======================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host=os.getenv("REST_API_HOST", "127.0.0.1"),
        port=int(os.getenv("REST_API_PORT", "8081")),
    )