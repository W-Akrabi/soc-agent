import asyncio
from tools.base import BaseTool


class WHOISTool(BaseTool):
    name = "whois_lookup"
    description = "Look up WHOIS registration data for a domain"

    async def run(self, input: dict) -> dict:
        domain = input.get("domain", "")
        if not domain:
            return {"error": "No domain provided"}
        try:
            loop = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(None, self._do_whois, domain),
                timeout=15.0,
            )
            return result
        except asyncio.TimeoutError:
            return {"domain": domain, "error": "WHOIS lookup timed out"}
        except Exception as e:
            return {"domain": domain, "error": str(e)}

    def _do_whois(self, domain: str) -> dict:
        import whois
        w = whois.whois(domain)
        creation = w.creation_date
        expiration = w.expiration_date
        status = w.status
        return {
            "registrar": w.registrar or "unknown",
            "created": str(creation[0] if isinstance(creation, list) else creation) if creation else "unknown",
            "expires": str(expiration[0] if isinstance(expiration, list) else expiration) if expiration else "unknown",
            "country": w.country or "unknown",
            "status": str(status[0] if isinstance(status, list) else status) if status else "unknown",
            "name_servers": list(w.name_servers) if w.name_servers else [],
        }
