from app.connectors import abuseipdb, ipinfo, otx, shodan, urlscan, virustotal
from app.connectors.abuseipdb import ABUSEIPDB
from app.connectors.ipinfo import IPINFO
from app.connectors.otx import OTX
from app.connectors.shodan import SHODAN
from app.connectors.urlscan import URLSCAN
from app.connectors.virustotal import VIRUSTOTAL

CONNECTOR_DEFINITIONS = (
    VIRUSTOTAL,
    ABUSEIPDB,
    OTX,
    SHODAN,
    URLSCAN,
    IPINFO,
)

CONNECTOR_HANDLERS = {
    "virustotal": virustotal.analyze,
    "abuseipdb": abuseipdb.analyze,
    "otx": otx.analyze,
    "shodan": shodan.analyze,
    "urlscan": urlscan.analyze,
    "ipinfo": ipinfo.analyze,
}
