import os
import httpx
from tools.base import BaseTool

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Common service names by port for building NVD keyword queries
_PORT_SERVICES = {
    21: "ftp", 22: "openssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "apache nginx http", 110: "pop3", 143: "imap", 443: "ssl tls https",
    445: "smb samba", 3306: "mysql", 3389: "rdp remote desktop",
    5432: "postgresql", 6379: "redis", 8080: "http tomcat spring",
    8443: "https tomcat", 27017: "mongodb",
}


class CVESearchTool(BaseTool):
    name = "cve_search"
    description = "Search NVD for CVEs matching a port or service"

    async def run(self, input: dict) -> dict:
        port = input.get("port")
        service = input.get("service", "")
        keyword = service or _PORT_SERVICES.get(port, str(port) if port else "")

        if not keyword:
            return {"port": port, "service": service, "cves": [], "error": "No keyword to search"}

        api_key = os.getenv("NVD_API_KEY", "")
        headers = {"apiKey": api_key} if api_key else {}

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    _NVD_URL,
                    headers=headers,
                    params={
                        "keywordSearch": keyword,
                        "resultsPerPage": 5,
                        "cvssV3Severity": "CRITICAL",
                    },
                )
                resp.raise_for_status()
                data = resp.json()

            cves = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                descriptions = cve.get("descriptions", [])
                description = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
                metrics = cve.get("metrics", {})
                cvss_score = None
                severity = "unknown"
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        cvss_data = metrics[key][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        severity = cvss_data.get("baseSeverity", "unknown").lower()
                        break
                cves.append({
                    "id": cve_id,
                    "severity": severity,
                    "description": description[:200],
                    "cvss": cvss_score,
                })

            return {"port": port, "service": service, "keyword": keyword, "cves": cves}

        except httpx.HTTPStatusError as e:
            return {"port": port, "service": service, "cves": [], "error": f"NVD API error: {e.response.status_code}"}
        except Exception as e:
            return {"port": port, "service": service, "cves": [], "error": str(e)}
