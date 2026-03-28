import httpx
from tools.base import BaseTool

_PRIVATE_PREFIXES = (
    "10.", "127.", "0.",
    "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
)


class IPLookupTool(BaseTool):
    name = "ip_lookup"
    description = "Look up geographic and ASN information for an IP address"

    async def run(self, input: dict) -> dict:
        ip = input.get("ip", "")

        if any(ip.startswith(p) for p in _PRIVATE_PREFIXES):
            return {"geo": "internal", "city": "", "asn": "internal", "org": "LAN", "risk": "low"}

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"http://ip-api.com/json/{ip}",
                    params={"fields": "status,message,country,countryCode,city,isp,org,as,proxy,hosting"},
                )
                data = resp.json()

            if data.get("status") == "success":
                risk = "high" if (data.get("proxy") or data.get("hosting")) else "medium"
                return {
                    "geo": data.get("countryCode", ""),
                    "country": data.get("country", ""),
                    "city": data.get("city", ""),
                    "asn": data.get("as", ""),
                    "org": data.get("org", ""),
                    "isp": data.get("isp", ""),
                    "proxy": data.get("proxy", False),
                    "hosting": data.get("hosting", False),
                    "risk": risk,
                }
            return {"geo": "unknown", "city": "unknown", "asn": "unknown", "org": "unknown", "risk": "unknown", "error": data.get("message", "lookup failed")}

        except Exception as e:
            return {"geo": "unknown", "city": "unknown", "asn": "unknown", "org": "unknown", "risk": "unknown", "error": str(e)}
