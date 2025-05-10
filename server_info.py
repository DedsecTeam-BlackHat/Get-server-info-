#!/usr/bin/env python3

import requests
import socket
import ssl
import argparse
from urllib.parse import urlparse
import dns.resolver
import whois

def print_header():
    print(r"""
 ____  ____  _____ ____  ____ ____ 
|  _ \|  _ \| ____|  _ \| ___/ ___|
| | | | | | |  _| | | | |___ \___ \
| |_| | |_| | |___| |_| |___) |__) |
|____/|____/|_____|____/|____/____/ 
""")
    print("         TOOLS BY DEDSEC")
    print("="*36)

def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def get_dns_info(domain):
    info = {}
    try:
        info['A'] = [r.to_text() for r in dns.resolver.resolve(domain, 'A')]
    except:
        info['A'] = []
    try:
        info['CNAME'] = [r.to_text() for r in dns.resolver.resolve(domain, 'CNAME')]
    except:
        info['CNAME'] = []
    try:
        info['MX'] = [r.to_text() for r in dns.resolver.resolve(domain, 'MX')]
    except:
        info['MX'] = []
    return info

def get_ssl_info(hostname):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(3)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            return {
                "subject": dict(x[0] for x in cert['subject']),
                "issuer": dict(x[0] for x in cert['issuer']),
                "notBefore": cert['notBefore'],
                "notAfter": cert['notAfter']
            }
    except:
        return None

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": w.creation_date,
            "expiration_date": w.expiration_date,
            "name_servers": w.name_servers,
            "emails": w.emails
        }
    except Exception as e:
        return {"error": str(e)}

def get_server_info(url):
    print_header()
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "http://" + url
        parsed = urlparse(url)
    domain = parsed.hostname
    print(f"[+] Target URL : {url}")
    print(f"[+] Domain     : {domain}")

    ip = get_ip(domain)
    print(f"[+] IP Address : {ip}")

    try:
        r = requests.get(url, timeout=5)
        print(f"[+] HTTP Status: {r.status_code}")
        print(f"[+] Server     : {r.headers.get('Server', 'Unknown')}")
        print(f"[+] Powered by : {r.headers.get('X-Powered-By', 'Unknown')}")
    except Exception as e:
        print(f"[-] Error fetching HTTP headers: {e}")

    print("\n[+] DNS Records:")
    dns_info = get_dns_info(domain)
    for k, v in dns_info.items():
        print(f"  - {k}: {', '.join(v) if v else 'None'}")

    print("\n[+] SSL Certificate Info:")
    ssl_info = get_ssl_info(domain)
    if ssl_info:
        for k, v in ssl_info.items():
            print(f"  - {k}: {v}")
    else:
        print("  - Not available or no HTTPS")

    print("\n[+] WHOIS Info:")
    whois_info = get_whois_info(domain)
    for k, v in whois_info.items():
        print(f"  - {k}: {v}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Get server info from a target URL.")
    parser.add_argument("url", help="Target URL (e.g. https://example.com)")
    args = parser.parse_args()
    get_server_info(args.url)
