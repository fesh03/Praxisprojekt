from fastmcp import FastMCP
import httpx
import logging, sys, os, json, urllib.parse
from typing import Dict, Any
from dotenv import load_dotenv, find_dotenv
from pathlib import Path

# Laden der Umgebungsvariablen aus .env Datei
load_dotenv()

# Instanziierung des MCP-Servers
mcp = FastMCP(
    name="Netflow Analyzer Server",
    version="1.0.0"
)

# Konfiguration aus Umgebungsvariablen
GEOIP_API_URL = os.environ.get("GEOIP_API_URL", "http://ip-api.com/json/")
PROTOCOL_MAPPING_PATH = os.environ.get("PROTOCOL_MAPPING_PATH", "/netflow_directory/protocol_mapping.json")
NETFLOW_SPECS_PATH = os.environ.get("NETFLOW_SPECS_PATH", "/netflow_directory/netflow_specs.json")
ATTACK_LIST = os.environ.get("ATTACK_LIST", "/netflow_directory/possible_attack_list.json")
REST_API_URL = os.getenv("REST_API_URL", "http://localhost:8000")

# Logging-Konfiguration, um Logs auf stderr auszugeben
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)

# Logger für das MCP-Netflow-Analyser-Tool, um konsistente und formatierte Logs zu gewährleisten.
logger = logging.getLogger("netflow-analyzer-server")

# =======================================================================
# Hilfsfunktionen zum Laden von JSON-Daten
# =======================================================================

def load_protocol_mapping():
    """Lade Protokoll-Mapping aus JSON-Datei."""
    logging.info(f"Function load_protocol_mapping called")
    try:
        with open(PROTOCOL_MAPPING_PATH, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning(f"Protocol mapping not found at {PROTOCOL_MAPPING_PATH}")
        return {"layer4": {}, "layer7": {}}
    except Exception as e:
        logger.error(f"Error loading protocol mapping: {e}")
        return {"layer4": {}, "layer7": {}}


def load_netflow_specs():
    """Lade Netflow-Spezifikationen aus JSON-Datei."""
    logging.info(f"Function load_netflow_specs called")
    try:
        with open(NETFLOW_SPECS_PATH, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning(f"Netflow specs not found at {NETFLOW_SPECS_PATH}")
        return {}
    except Exception as e:
        logger.error(f"Error loading Netflow specs: {e}")
        return {}


def load_attack_list():
    """Lade Angriffsliste aus JSON-Datei."""
    logging.info(f"Function load_attack_list called")
    try:
        with open(ATTACK_LIST, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning(f"Attack list not found at {ATTACK_LIST}")
        return {}
    except Exception as e:
        logger.error(f"Error loading attack list: {e}")
        return {}


# =======================================================================
# GLOBALE DATENLADUNG (Wird einmalig beim Serverstart ausgeführt)
# =======================================================================

NETFLOW_SPECS_DATA = load_netflow_specs()
ATTACK_LIST_DATA = load_attack_list()

# =======================================================================
# MCP RESSOURCEN DEFINITIONEN
# =======================================================================

@mcp.resource(
    uri="resource://netflow/fields",
    name="netflow_fields",
    title="NetFlow-Felder Referenz",
    description="Referenz der Standard-Netflow-Felder und Bedeutung.",
    mime_type="application/json"
)
def get_netflow_fields_resource() -> dict:
    """Gibt die geladenen Netflow-Felder als JSON-Inhalt zurück."""
    return NETFLOW_SPECS_DATA.get("fields", {})

@mcp.resource(
    uri="resource://netflow/attack_signatures",
    name="netflow_attack_signatures",
    title="Netflow Angriffssignaturen",
    description="Liste und Details zu bekannten Angriffssignaturen in Netflow-Daten.",
    mime_type="application/json"
)
def get_netflow_attack_signatures_resource() -> dict:
    """Gibt die geladenen Angriffssignaturen als JSON-Inhalt zurück."""
    return ATTACK_LIST_DATA.get("attack_signatures", {})

# =======================================================================
# INTERNE BASIS-FUNKTIONEN: TOOL-LOGIK -> RESOURCEN
# =======================================================================

def _get_netflow_specifications() -> str:
    """Gibt eine Übersicht der Netflow-Spezifikationen zurück. Dazu gehören Feldernamen und deren Beschreibung. """
    logging.info("Function _get_netflow_specifications called")

    try:
        specs = NETFLOW_SPECS_DATA

        if not specs:
            return "Warning: Netflow specifications data not available"

        result = "=== NETFLOW SPEZIFIKATIONEN ÜBERSICHT ===\n\n"

        # Felder
        if "fields" in specs:
            result += "Netflow Felder:\n"
            for field, details in specs["fields"].items():
                dtype = details.get("type", "N/A")
                desc = details.get("description", "Keine Beschreibung")
                result += f"   - {field} ({dtype}): {desc}\n"
            result += "\n"
        return result

    except Exception as e:
        logging.error(f"Function-Error: _get_netflow_specifications: {e}")
        return "An error occurred while retrieving netflow specifications."

def _get_attack_signatures_list() -> str:
    """ Listet alle verfügbaren Angriffsarten auf. """
    logging.info("Function _get_attack_signatures_list called")

    try:
        specs = ATTACK_LIST_DATA

        if not specs or "attack_signatures" not in specs:
            return "Warning: Attack signatures data not available"

        result = "=== VERFÜGBARE ANGRIFFSARTEN ===\n\n"

        for attack_name in specs["attack_signatures"].keys():
            result += f"   - {attack_name}\n"
        return result
    except Exception as e:
        logging.error(f"Function-Error: _get_attack_signatures_list: {e}")
        return "An error occurred while retrieving attack signatures list."


def _get_attack_signature_details(attack_name: str) -> str:
    """ Gibt detaillierte Informationen zu einer spezifischen Angriffsart zurück. Dazu gehören Beschreibung, Kategorie und Indikatoren. """
    logging.info(f"Function _get_attack_signature_details called with: {attack_name}")

    try:
        specs = ATTACK_LIST_DATA

        if not specs or "attack_signatures" not in specs:
            return "Warning: Attack signatures data not available"

        attack_info = specs["attack_signatures"].get(attack_name)
        if not attack_info:
            return f"Angriffsart '{attack_name}' nicht gefunden."
        result = f"=== DETAILS ZUR ANGRIFFSART: {attack_name} ===\n\n"
        result += f"Beschreibung: {attack_info.get('description', 'Keine Beschreibung verfügbar')}\n"
        result += f"Kategorie: {attack_info.get('category', 'Keine Kategorie verfügbar')}\n"
        indicators = attack_info.get("indicators", [])
        if indicators:
            result += "Indikatoren:\n"
            for indicator in indicators:
                result += f"   - {indicator}\n"
        else:
            result += "Keine Indikatoren verfügbar.\n"
        return result
    except Exception as e:
        logging.error(f"Function-Error: _get_attack_signature_details: {e}")
        return "An error occurred while retrieving attack signature details."

# =======================================================================
# INTERNE BASIS-FUNKTIONEN: ANALYSETOOL-LOGIK
# =======================================================================

async def _get_ip_geolocation_base(ip_address: str) -> str:
    """ Gibt den geografischen Standort einer IP-Adresse zurück (Basis-Logik). """
    logging.info(f"Function _get_ip_geolocation_base called with IP: {ip_address}")

    if not ip_address.strip():
        logging.error("Invalid IP address provided.")
        return "Invalid IP address"

    try:
        logger.info(f"Executing _get_ip_geolocation_base for IP: {ip_address}")
        result = f"Geolocation Results:\n\n"
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(f"{GEOIP_API_URL}{ip_address}", timeout=10)
                response.raise_for_status()
                geo_data = response.json()

                if geo_data.get("status") == "success":
                    result += f"IP-Address ({ip_address}):\n"
                    result += f"  - Country: {geo_data.get('country', 'N/A')}\n"
                    result += f"  - Region: {geo_data.get('regionName', 'N/A')}\n"
                    result += f"  - City: {geo_data.get('city', 'N/A')}\n"
                    result += f"  - ISP: {geo_data.get('isp', 'N/A')}\n"
                    result += f"  - AS: {geo_data.get('as', 'N/A')}\n"
                    result += f"  - Coordinates: {geo_data.get('lat', 'N/A')}, {geo_data.get('lon', 'N/A')}\n\n"
                else:
                    result += f"IP-Address ({ip_address}): Lookup failed or internal IP Address\n\n"
            except httpx.RequestError as e:
                logging.error(f"HTTP -> Request error: {e}")
                result += f"IP-Address ({ip_address}): Request Error retrieving geolocation data\n\n"
            except httpx.HTTPStatusError as e:
                logging.error(f"HTTP -> Status error: {e}")
                result += f"IP-Address ({ip_address}): HTTP-Status Error retrieving geolocation data\n\n"
            except Exception as e:
                logging.error(f"Unexpected error: {e}")
                result += f"IP-Address ({ip_address}): Unexpected Error retrieving geolocation data\n\n"

        return result.strip()

    except Exception as e:
        logging.error(f"Function-Error: _get_ip_geolocation_base: {e}")
        return "An error occurred while retrieving geolocation data from the tool: get_ip_location."

def _get_protocol_name_base(layer_num: int, protocol_id: int, ) -> str:
    """ Gibt den Protokollnamen basierend auf Layer und Protokoll-ID zurück (Basis-Logik). """
    logging.info(f"Function _get_protocol_name_base called with layer: {layer_num}, protocol_number: {protocol_id}")

    # Normalisieren der Eingaben
    layer_num = str(layer_num)
    protocol_id = str(protocol_id)

    if layer_num == "4":
        layer = "layer4"
    elif layer_num == "7":
        layer = "layer7"
    else:
        logging.error("Invalid layer number provided.")
        return "Invalid layer number. Please provide 4 or 7."

    try:
        protocol_mapping = load_protocol_mapping()

        if not protocol_mapping:
            logging.error("Protocol mapping data is empty or could not be loaded.")
            return "Protocol mapping data is unavailable."

        logger.info(f"Executing _get_protocol_name_base for protocol number: {protocol_id}")

        layer_name = protocol_mapping.get(layer, {}).get(protocol_id, f"Unknown (ID: {protocol_id})")

        result = f"Protocol Information:\n\n"
        result += f"Layer 4 Protocol:\n"
        result += f"  - ID: {protocol_id}\n"
        result += f"  - Name: {layer_name}\n\n"

        return result
    except Exception as e:
        logging.error(f"Function-Error: _get_protocol_name_base: {e}")
        return "An error occurred while retrieving protocol name from the tool: get_protocol_name."

def _get_netflow_by_id_base(
        netflow_id: int,
        show_attack: bool = False,
        return_method: str = "json"
) -> Any:
    """ Gibt einen Netflow-Eintrag anhand seiner ID aus der Datenbank zurück (Basis-Logik). """
    logging.info(f"Function _get_netflow_by_id_base called with netflow_id: {netflow_id}, show_attack: {show_attack}")
    url = urllib.parse.urljoin(REST_API_URL, f"/data/netflow_id?id={netflow_id}&show_attack={str(show_attack).lower()}")
    try:
        with httpx.Client() as client:
            response = client.get(url)
            response.raise_for_status()
    except Exception as e:
        logging.error(f"Function-Error: _get_netflow_by_id_base: {e}")
        return {
            "status": "error",
            "error": str(e)
        }

    if return_method == "json":
        return response.json()
    elif return_method == "string":
        data = response.json().get("netflow_entry", {})
        return ", ".join([f"{key}: {value}" for key, value in data.items()])
    else:
        logging.error(f"Function-Error: _get_netflow_by_id_base: Invalid return_method: {return_method}")
        return {
            "status": "error",
            "error": f"Invalid return_method: {return_method}"
        }

def _get_ip_history_base(
        src_ip: str,
        dst_ip: str,
        sample_size: int
) -> Dict[str, Any]:
    """ Gibt die Historie von Netflow-Einträgen für eine IP-Adresse zurück (Basis-Logik). """
    logging.info(f"Function _get_ip_history_base called with src_ip: {src_ip}, dst_ip: {dst_ip}, and sample_size: {sample_size}")
    url = urllib.parse.urljoin(REST_API_URL, f"/data/ip_history_search?src_ip={src_ip}&dst_ip={dst_ip}&sample_size={sample_size}")
    try:
        with httpx.Client() as client:
            response = client.get(url)
            response.raise_for_status()
            return response.json()
    except Exception as e:
        logging.error(f"Function-Error: _get_ip_history_base: {e}")
        return {
            "status": "error",
            "error": str(e)
        }

def _get_ip_threats_base(
        src_ip: str,
        dst_ip: str,
) -> Dict[str, Any]:
    """ Retrieve threat information for an IP address (Basis-Logik). """
    # Unverändert
    logging.info(f"Function _get_ip_threats_base called with src_ip: {src_ip}, dst_ip: {dst_ip}")
    url = urllib.parse.urljoin(REST_API_URL, f"/data/ip_threats?src_ip={src_ip}&dst_ip={dst_ip}")
    try:
        with httpx.Client() as client:
            response = client.get(url)
            response.raise_for_status()
            return response.json()
    except Exception as e:
        logging.error(f"Function-Error: _get_ip_threats_base: {e}")
        return {
            "status": "error",
            "error": str(e)
        }

# =======================================================================
# MCP TOOLS
# =======================================================================

@mcp.tool(
    name="get_ip_geolocation",
    title="Geografische Abfrage",
    description="Bestimmung des geografischen Standorts aus der übergebenen IP (String)",
    tags={"IP"},
    enabled=True
)
async def get_ip_geolocation(ip_address: str) -> str:
    return await _get_ip_geolocation_base(ip_address)

@mcp.tool(
    name="get_protocol_name",
    title="Protokollnamen Abfrage",
    description="Bestimmung des Protokollnamen aus dem Layer (String) des Netflows und der Protokoll-ID (String).",
    tags={"IP", "Protocol", "Layer"},
    enabled=True
)
def get_protocol_name(layer_num: int, protocol_id: int, ) -> str:
    return _get_protocol_name_base(layer_num, protocol_id)

@mcp.tool(
    name="get_attack_signatures_list",  # Tool-Name
    title="Netflow-Angriffssignaturen",
    description="Liefert eine Liste gängiger Angriffssignaturen (z. B. Port Scan, DDoS, Syn Flood), die in Netflow-Daten identifiziert werden können.",
    tags={"attack", "netflow"},
    enabled=True
)
def get_attack_signatures_list() -> str:
    return _get_attack_signatures_list()

@mcp.tool(
    name="get_attack_signature_details",  # Tool-Name
    title="Details zu Netflow-Angriffssignaturen",
    description="Liefert detaillierte Informationen zu einer spezifischen angefragten Angriffssignatur in Netflow-Daten.",
    tags={"attack", "netflow"},
    enabled=True
)
def get_attack_signature_details(attack_name: str) -> str:
    return _get_attack_signature_details(attack_name)

@mcp.tool(
    name="get_netflow_specifications",
    title="Netflow-Spezifikationen",
    description="Gibt eine Übersicht der Netflow-Spezifikationen zurück.",
    tags={"netflow", "specifications"},
    enabled=True
)
def get_netflow_specifications() -> str:
    return _get_netflow_specifications()

# =======================================================================
# MCP Tools - Datenbankabfragen
# =======================================================================

@mcp.tool(
    name="get_ip_history",
    title="IP-Historie Abrufen",
    description="Ruft die Historie von Netflow-Einträgen für eine IP-Adresse ab.",
    tags={"database", "ip_history"},
    enabled=True
)
async def get_ip_history(
        src_ip: str,
        dst_ip: str,
        sample_size: int = 3
) -> str:
    """
        Ruft die aufrufbare Basis-Funktion auf und gibt das Ergebnis als String zurück.

        Formatierung:
        1. Related-Netflow; key1: value1, key2: value2, ...
        2. ...
    """
    logging.info(f"Function get_ip_history called for src_ip: {src_ip} and dst_ip: {dst_ip}")

    try:
        data = _get_ip_history_base(src_ip, dst_ip, sample_size)
        data_flows = data.get("flows", [])
        data_flows_total_count = data.get("flows_total_count", 0)

        if not data:
            return f"Keine Netflow-Einträge für src_ip={src_ip} und dst_ip={dst_ip} gefunden."

        result_lines = [
            f"{idx}.Related-Netflow; " + ", ".join(f"{key}: {value}" for key, value in entry.items())
            for idx, entry in enumerate(data_flows, start=1)
        ]

        # Gesamtanzahl der gefundenen Einträge hinzufügen
        result_lines.insert(0, f"Gefundene Netflow-Einträge: {data_flows_total_count}\n")
        result_lines.insert(1, f"Details der {sample_size}. Einträge:\n")

        return "\n".join(result_lines)

    except Exception as e:
        logging.error(f"Unexpected error in get_ip_history: {e}")
        return f"Unerwarteter Fehler: {e}"

@mcp.tool(
    name="get_ip_threats",
    title="IP-Bedrohungsinformationen Abrufen",
    description="Ruft Bedrohungsinformationen für eine IP-Adresse ab.",
    tags={"database", "ip_threats"},
    enabled=True
)
async def get_ip_threats(
        src_ip: str,
        dst_ip: str,
) -> str:
    """
        Ruft die aufrufbare Basis-Funktion auf und gibt das Ergebnis als String zurück.

        Formatierung:
        Bedrohungsinformationen für die IP-Adressen:
        Quell-IP: <src_ip> → [Liste der Bedrohungen oder 'Keine Bedrohungen gefunden']
        Ziel-IP: <dst_ip> → [Liste der Bedrohungen oder 'Keine Bedrohungen gefunden']
    """
    logging.info(f"Function get_ip_threats called for src_ip: {src_ip} and dst_ip: {dst_ip}")

    try:
        data = _get_ip_threats_base(src_ip, dst_ip)

        src_threats = data.get("src_threats_labeled", [])
        dst_threats = data.get("dst_threats_labeled", [])

        result = f"Bedrohungsinformationen für die IP-Adressen:\n\n"

        result += f"Quell-IP: {src_ip} (ausgehende Angriffe)→ "
        if src_threats:
            result += ", ".join(src_threats) + "\n"
        else:
            result += "Keine Bedrohungen gefunden\n"

        result += f"Ziel-IP: {dst_ip} (eingehende Angriffe)→ "
        if dst_threats:
            result += ", ".join(dst_threats) + "\n"
        else:
            result += "Keine Bedrohungen gefunden\n"

        return result.strip()
    except Exception as e:
        logging.error(f"Unexpected error in get_ip_threats: {e}")
        return f"Unerwarteter Fehler: {e}"

@mcp.tool(
    name="get_netflow_by_id",
    title="Netflow Eintrag Abrufen",
    description="Ruft einen Netflow-Eintrag anhand seiner ID aus der Datenbank ab.",
    tags={"database", "netflow_entry"},
    enabled=True
)
async def get_netflow_by_id(
        netflow_id: int,
        return_method: str = "json"
) -> Any:
    logging.info(f"Function get_netflow_by_id called with netflow_id: {netflow_id}")
    return _get_netflow_by_id_base(netflow_id=netflow_id, return_method=return_method, show_attack = False)

# =======================================================================
# MCP PROMPT REGISTRIERUNG
# =======================================================================
@mcp.prompt(
    name="specific_netflow_analysis",
    description="""
        Führt eine spezifische forensische Validierung von als bösartig markierten Netflow-Daten durch.

        Ziel: Ein strukturierter spezifischer Prompt für die objektive Analyse und Klassifizierungsvalidierung 
        von Network Intrusion Detection System (NIDS) Markierungen. Das LLM soll aktiv die 
        gelisteten Tools nutzen, um Kontext zu sammeln und eine fundierte Entscheidung zu treffen.
    """
)
async def specific_netflow_analysis(
        netflow_id: int
) -> str:
    return f"""
System-Rolle:
Du bist ein forensischer Netzwerk-Sicherheitsanalyst. 
Deine Aufgabe ist es, die vom Network Intrusion Detection System (NIDS) vorgenommene Klassifizierung bösartiger Aktivitäten objektiv zu validieren.
Dir stehen verschiedene Tools zur Verfügung, um Kontextinformationen zu sammeln und eine fundierte Analyse durchzuführen.

---

Tool-Nutzung (PRIORITÄT):
Bevor du die endgültige Analyse erstellst, nutze diese genannten Tools, um den Kontext der gegebenen NetFlow-Daten zu ermitteln:

1. get_ip_geolocation – Bestimme den geografischen Standort der Quell- und Ziel-IP
2. get_ip_threats – Prüfe bekannte Bedrohungsinformationen für die Quell- und Ziel-IP
3. get_ip_history – Analysiere die historische Kommunikation zwischen der Quell- und Ziel-IP
4. get_protocol_name – Identifiziere die verwendeten Protokolle und deren Bedeutung

Weitere Tools zur Unterstützung der Analyse:
5. get_netflow_specifications – Verstehe die Struktur und Bedeutung der NetFlow-Felder
6. get_attack_signatures_list – Erhalte eine Liste bekannter Angriffssignaturen
7. get_attack_signature_details – Erhalte detaillierte Informationen zu spezifischen Angriffssignaturen

---

Sollten dir Ressourcen zur Verfügung stehen, konsultiere diese für zusätzliche Informationen:
1. resource://netflow/fields – Referenz der Standard-Netflow-Felder
2. resource://netflow/attack_signatures – Liste und Details zu bekannten Angriffssignaturen in Netflow-Daten

---

Analyse- und Format-Vorgaben:
1. Entscheidung: Beginne deine Antwort mit einem klaren Urteil:
   - [KLASSIFIZIERUNG: BESTÄTIGT] – wenn der Flow tatsächlich bösartig ist
   - [KLASSIFIZIERUNG: WIDERLEGT] – wenn der Flow als gutartig eingestuft wird

2. Beweisführung: Liefere eine detaillierte Erklärung. Zitiere immer konkrete Werte aus der NetFlow-Probe, um deine Schlussfolgerung zu untermauern. Stütze dich und deine Ergebnisse auf die von den Tools und Resources gelieferten Informationen.

3. Kategorisierung (falls bösartig): Wenn du die Markierung bestätigst, benenne die genaue Art der Bedrohung. Gehe wie folgt vor:
- suche nach einer Resource/Tool, welches dir eine Liste bekannter Angriffssignaturen liefert (z.B. get_attack_signatures_list)
- falls du einen Angriffstyp findest, der zu den beobachteten Netflow-Muster passt, sollst du weitere Tools abfragen, um detaillierte Informationen zu dieser Angriffssignatur zu erhalten, um deine Analyse zu bestätigen.

4. Sprache: Die gesamte Antwort muss in **Deutsch** verfasst sein.

---

**Analyseanforderung:**
Analysiere den folgenden Flow und begründe objektiv, ob es sich um bösartigen Netzwerkverkehr handelt.
Sollten dir nicht genügend Informationen angeboten werden, erwähne dies in deiner Analyse und erkläre, welche zusätzlichen Daten du benötigen würdest, um eine fundierte Entscheidung zu treffen.

---

**Gegenstand der Analyse:**
```
{_get_netflow_by_id_base(netflow_id=netflow_id, return_method="string")}
```
"""

if __name__ == "__main__":
    mcp.run(
        transport=os.getenv("TRANSPORT_PROTOCOL"),
        host=os.getenv("MCP_HOST", "localhost"),
        port=int(os.getenv("MCP_PORT", 8080))
    )