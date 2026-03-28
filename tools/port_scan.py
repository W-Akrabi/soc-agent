import asyncio
from tools.base import BaseTool


class PortScanTool(BaseTool):
    name = "port_scan"
    description = "Scan open ports and identify services on a host"

    async def run(self, input: dict) -> dict:
        ip = input.get("ip", "")
        if not ip:
            return {"ip": ip, "open_ports": [], "error": "No IP provided"}

        if not self._is_internal(ip):
            return {"ip": ip, "open_ports": [], "skipped": True,
                    "reason": "Port scanning external IPs is out of scope — use threat_feed for external IP intelligence"}

        try:
            loop = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(None, self._do_scan, ip),
                timeout=30.0,
            )
            return result
        except asyncio.TimeoutError:
            return {"ip": ip, "open_ports": [], "error": "Scan timed out after 30s"}
        except Exception as e:
            return {"ip": ip, "open_ports": [], "error": str(e)}

    def _is_internal(self, ip: str) -> bool:
        return ip.startswith((
            "10.", "127.", "192.168.",
            "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
            "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
            "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
        ))

    def _do_scan(self, ip: str) -> dict:
        import nmap
        nm = nmap.PortScanner()
        # -sT: TCP connect (no root needed)  -F: top 100 ports  --open: only open  -T4: fast
        nm.scan(ip, arguments="-sT -F --open -T4")
        open_ports = []
        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                for port, state in nm[ip][proto].items():
                    if state["state"] == "open":
                        open_ports.append({
                            "port": port,
                            "service": state.get("name", "unknown"),
                            "version": state.get("version", ""),
                        })
        return {"ip": ip, "open_ports": open_ports}
