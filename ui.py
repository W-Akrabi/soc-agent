from datetime import datetime, timezone
from rich.console import Console
from rich.text import Text
from rich.align import Align
from rich.table import Table
import pyfiglet


def _banner_text(model: str, watch_dir: str) -> Table:
    ascii_art = pyfiglet.figlet_format("SOC  AGENT", font="doom")
    grid = Table.grid(expand=True)
    grid.add_column()
    grid.add_row(Align.center(Text(ascii_art, style="bold cyan")))
    grid.add_row(Align.center(Text("Autonomous multi-agent security incident investigation", style="bold green")))
    grid.add_row(Align.center(Text(
        f"Model: {model}  │  Watching: {watch_dir}/  │  Ctrl+C to stop",
        style="dim green"
    )))
    grid.add_row("")
    return grid


class WatchUI:
    def __init__(self, console: Console, model: str, watch_dir: str, dry_run: bool = False):
        self.console = console
        self.model = model if not dry_run else f"{model} (dry-run)"
        self.watch_dir = watch_dir
        self._status = None

    def show_banner(self) -> None:
        self.console.clear()
        self.console.print(_banner_text(self.model, self.watch_dir))

    def start_watching(self, last_alert: str | None = None) -> None:
        if last_alert:
            self.console.print(f"  [dim]✓  Last: {last_alert}[/dim]")
        self._status = self.console.status(
            f"[green]Watching {self.watch_dir}/ for new alert files...[/green]",
            spinner="dots",
        )
        self._status.start()

    def stop_watching(self) -> None:
        if self._status:
            self._status.stop()
            self._status = None

    def alert_received(self, alert_type: str, severity: str, filename: str) -> None:
        self.stop_watching()
        severity_color = {
            "low": "green", "medium": "yellow",
            "high": "red", "critical": "bold red"
        }.get(severity.lower(), "white")
        self.console.print()
        self.console.rule(
            f"[bold]INCOMING ALERT[/bold]  │  [bold]{alert_type.upper()}[/bold]  │  "
            f"[{severity_color}]{severity.upper()}[/{severity_color}]  │  {filename}",
            style="yellow",
        )

    def investigation_done(self, alert_id: str) -> None:
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        self.console.rule("[dim]investigation complete[/dim]", style="dim")
        self.console.print()
        self.start_watching(last_alert=f"{alert_id[:8]} at {ts}")
