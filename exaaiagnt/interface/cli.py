import atexit
import signal
import sys
import threading
import time
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from exaaiagnt.agents.ExaaiAgent import ExaaiAgent
from exaaiagnt.llm.config import LLMConfig
from exaaiagnt.telemetry.tracer import Tracer, set_global_tracer

from .utils import build_final_stats_text, build_live_stats_text, get_severity_color


# Clean ASCII Banner
BANNER = r"""
 ______  _  _   ____    ____   _____ 
|  ____|| || | / __ \  / __ \ |_   _|
| |__   | || || |  | || |  | |  | |  
|  __|  |__   || |  | || |  | |  | |  
| |____    | || |__| || |__| | _| |_ 
|______|   |_| \____/  \____/ |_____|
"""


async def run_cli(args: Any) -> None:  # noqa: PLR0915
    console = Console()
    
    # Clear screen and show banner
    console.clear()
    console.print()
    console.print(BANNER, style="bold cyan", justify="center")
    console.print("[bold purple]Advanced AI-Powered Cybersecurity Agent[/]", justify="center")
    console.print("[dim]v2.0.0[/]", justify="center")
    console.print()

    # Target info table
    target_table = Table(show_header=True, header_style="bold cyan", border_style="cyan")
    target_table.add_column("Type", style="dim")
    target_table.add_column("Target", style="white")
    
    for target_info in args.targets_info:
        target_type = target_info.get("type", "URL")
        target_table.add_row(target_type, target_info["original"])
    
    console.print(Panel(target_table, title="[bold cyan]🎯 Targets", border_style="cyan"))
    console.print()

    # Config info
    config_text = Text()
    config_text.append("📁 Results: ", style="dim")
    config_text.append(f"exaai_runs/{args.run_name}\n", style="white")
    if args.instruction:
        config_text.append("📝 Instruction: ", style="dim")
        config_text.append(f"{args.instruction[:100]}{'...' if len(args.instruction) > 100 else ''}", style="white")
    
    console.print(Panel(config_text, title="[bold green]⚙️ Configuration", border_style="green"))
    console.print()

    scan_config = {
        "scan_id": args.run_name,
        "targets": args.targets_info,
        "user_instructions": args.instruction or "",
        "run_name": args.run_name,
    }

    llm_config = LLMConfig()
    agent_config = {
        "llm_config": llm_config,
        "max_iterations": 300,
        "non_interactive": True,
    }

    if getattr(args, "local_sources", None):
        agent_config["local_sources"] = args.local_sources

    tracer = Tracer(args.run_name)
    tracer.set_scan_config(scan_config)

    vuln_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    def display_vulnerability(report_id: str, title: str, content: str, severity: str) -> None:
        severity_lower = severity.lower()
        vuln_count[severity_lower] = vuln_count.get(severity_lower, 0) + 1
        severity_color = get_severity_color(severity_lower)

        vuln_panel = Panel(
            Text.assemble(
                ("🔴 ", "bold red") if severity_lower in ["critical", "high"] else ("🟡 ", "bold yellow"),
                (title, "bold white"),
                ("\n\n", ""),
                (f"Severity: {severity.upper()}", f"bold {severity_color}"),
                ("\n\n", ""),
                (content[:500] + "..." if len(content) > 500 else content, "dim white"),
            ),
            title=f"[bold {severity_color}]🐞 {report_id.upper()}",
            border_style=severity_color,
            padding=(1, 2),
        )

        console.print(vuln_panel)
        console.print()

    tracer.vulnerability_found_callback = display_vulnerability

    def cleanup_on_exit() -> None:
        tracer.cleanup()

    def signal_handler(_signum: int, _frame: Any) -> None:
        console.print("\n[bold yellow]⚠️ Scan interrupted by user[/]")
        tracer.cleanup()
        sys.exit(1)

    atexit.register(cleanup_on_exit)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, signal_handler)

    set_global_tracer(tracer)

    def create_live_status() -> Panel:
        status_text = Text()
        status_text.append("⏳ ", style="bold")
        status_text.append("Scanning in progress...", style="bold green")
        status_text.append("\n\n")

        # Live stats
        stats_text = build_live_stats_text(tracer, agent_config)
        if stats_text:
            status_text.append(stats_text)
        
        # Vulnerability summary
        total_vulns = sum(vuln_count.values())
        if total_vulns > 0:
            status_text.append("\n\n")
            status_text.append("Vulnerabilities Found: ", style="dim")
            status_text.append(f"{total_vulns}", style="bold red")

        return Panel(
            status_text,
            title="[bold green]🔍 Live Status",
            border_style="green",
            padding=(1, 2),
        )

    try:
        console.print("[bold cyan]🚀 Starting penetration test...[/]")
        console.print()

        with Live(
            create_live_status(), console=console, refresh_per_second=2, transient=False
        ) as live:
            stop_updates = threading.Event()

            def update_status() -> None:
                while not stop_updates.is_set():
                    try:
                        live.update(create_live_status())
                        time.sleep(2)
                    except Exception:  # noqa: BLE001
                        break

            update_thread = threading.Thread(target=update_status, daemon=True)
            update_thread.start()

            try:
                agent = ExaaiAgent(agent_config)
                result = await agent.execute_scan(scan_config)

                if isinstance(result, dict) and not result.get("success", True):
                    error_msg = result.get("error", "Unknown error")
                    console.print()
                    console.print(f"[bold red]❌ Scan failed: {error_msg}[/]")
                    console.print()
                    sys.exit(1)
            finally:
                stop_updates.set()
                update_thread.join(timeout=1)

    except Exception as e:
        console.print(f"[bold red]❌ Error: {e}[/]")
        raise

    # Final Summary
    console.print()
    console.print("[bold green]" + "=" * 60 + "[/]")
    console.print("[bold green]✅ PENETRATION TEST COMPLETED[/]", justify="center")
    console.print("[bold green]" + "=" * 60 + "[/]")
    console.print()

    # Vulnerability Summary Table
    summary_table = Table(show_header=True, header_style="bold white", border_style="cyan")
    summary_table.add_column("Severity", style="bold")
    summary_table.add_column("Count", justify="center")
    
    summary_table.add_row("[red]Critical[/]", str(vuln_count.get("critical", 0)))
    summary_table.add_row("[orange1]High[/]", str(vuln_count.get("high", 0)))
    summary_table.add_row("[yellow]Medium[/]", str(vuln_count.get("medium", 0)))
    summary_table.add_row("[green]Low[/]", str(vuln_count.get("low", 0)))
    summary_table.add_row("[blue]Info[/]", str(vuln_count.get("info", 0)))
    
    total = sum(vuln_count.values())
    summary_table.add_row("[bold white]TOTAL[/]", f"[bold white]{total}[/]")

    console.print(Panel(summary_table, title="[bold cyan]📊 Vulnerability Summary", border_style="cyan"))

    # Final stats
    console.print()
    final_stats_text = build_final_stats_text(tracer)
    if final_stats_text:
        console.print(Panel(final_stats_text, title="[bold green]📈 Statistics", border_style="green"))

    # Final report
    if tracer.final_scan_result:
        console.print()
        console.print(Panel(
            tracer.final_scan_result,
            title="[bold cyan]📄 Final Report",
            border_style="cyan",
            padding=(1, 2),
        ))

    console.print()
    console.print(f"[dim]Results saved to: exaai_runs/{args.run_name}[/]")
    console.print()
