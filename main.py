#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import argparse
import ipaddress
import json
import socket
import sys
from typing import List, Dict, Any
from itertools import cycle

import dns.resolver
import dns.reversename
import requests
from colorama import init as colorama_init, Fore, Style

colorama_init(autoreset=True)
BANNER_RAW = r"""
 ________________/\\\\\\\\\\\\\\\\\\\\\\\\_____/\\\\\\\_____/\\\_____      
 _______________\/\\\////////\\\__\/\\\\\\___\/\\\___/\\\/////////\\\_      
  _______________\/\\\______\//\\\_\/\\\/\\\__\/\\\__\//\\\______\///__     
   __/\\/\\\\\\\\\__\/\\\_______\/\\\_\/\\\//\\\_\/\\\___\////\\\_________    
    _\/\\\/////\\\_\/\\\_______\/\\\_\/\\\\//\\\\/\\\______\////\\\______   
     _\/\\\___\///__\/\\\_______\/\\\_\/\\\_\//\\\/\\\_________\////\\\___  
      _\/\\\_________\/\\\_______/\\\__\/\\\__\//\\\\\\__/\\\______\//\\\__ 
       _\/\\\_________\/\\\\\\\\\\\\/___\/\\\___\//\\\\\_\///\\\\\\\\\\\/___ 
        _\///__________\////////////_____\///_____\/////____\///////////_____ 

                        m10sec@proton.me
                            Exploremos esa IP
""".strip("\n")

BANNER_LINES = BANNER_RAW.splitlines()

BANNER_COLORS = [
    Fore.MAGENTA + Style.BRIGHT,
    Fore.CYAN + Style.BRIGHT,
    Fore.YELLOW + Style.BRIGHT,
    Fore.GREEN + Style.BRIGHT,
    Fore.BLUE + Style.BRIGHT,
    Fore.RED + Style.BRIGHT,
]

def print_banner():
    color_cycle = cycle(BANNER_COLORS)
    for line, col in zip(BANNER_LINES, color_cycle):
        print(col + line)
    print(Style.DIM + ("-" * 80) + Style.RESET_ALL)

# -----------------------
# Helpers
# -----------------------
def validate_ip(ip: str):
    try:
        return ipaddress.ip_address(ip)
    except Exception:
        raise ValueError(f"'{ip}' no es una dirección IP válida")

def reverse_dns(ip: str, timeout: float = 5.0) -> List[str]:
    hostnames = []
    try:
        rev = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev, "PTR", lifetime=timeout)
        for r in answers:
            name = str(r).rstrip(".")
            if name:
                hostnames.append(name)
    except Exception:
        try:
            h = socket.gethostbyaddr(ip)[0]
            if h:
                hostnames.append(h)
        except Exception:
            pass
    return list(dict.fromkeys(hostnames))

def forward_dns(hostname: str, timeout: float = 5.0) -> Dict[str, List[str]]:
    out = {"A": [], "AAAA": []}
    for rtype in ("A", "AAAA"):
        try:
            answers = dns.resolver.resolve(hostname, rtype, lifetime=timeout)
            for a in answers:
                out[rtype].append(str(a))
        except Exception:
            pass
    out["A"] = list(dict.fromkeys(out["A"]))
    out["AAAA"] = list(dict.fromkeys(out["AAAA"]))
    return out

def get_domains_from_crtsh(ip: str) -> List[str]:
    """Busca dominios relacionados a una IP usando crt.sh (CT logs)"""
    url = f"https://crt.sh/?q={ip}&output=json"
    domains = set()
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            data = r.json()
            for entry in data:
                if "name_value" in entry:
                    # pueden venir varios en una línea separados por \n
                    for d in entry["name_value"].split("\n"):
                        domains.add(d.strip())
    except Exception as e:
        print(Fore.RED + f"[!] Error en crt.sh lookup: {e}")
    return sorted(domains)

def inspect_ip(ip: str, timeout: float = 5.0) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "input_ip": ip,
        "reverse": [],
        "forwards": {},
        "related_domains": []
    }
    try:
        _ = validate_ip(ip)
    except ValueError as e:
        result["error"] = str(e)
        return result

    hostnames = reverse_dns(ip, timeout=timeout)
    result["reverse"] = hostnames

    for h in hostnames:
        fwd = forward_dns(h, timeout=timeout)
        roundtrip = ip in fwd.get("A", []) or ip in fwd.get("AAAA", [])
        result["forwards"][h] = {
            "A": fwd.get("A", []),
            "AAAA": fwd.get("AAAA", []),
            "roundtrip_match": roundtrip,
        }

    # dominios relacionados via crt.sh
    result["related_domains"] = get_domains_from_crtsh(ip)
    return result

# -----------------------
# CLI
# -----------------------
def parse_args():
    p = argparse.ArgumentParser(description="Reverse DNS + Forward DNS + crt.sh related domains.")
    p.add_argument("ip", help="IP a inspeccionar (IPv4 o IPv6)")
    p.add_argument("-t", "--timeout", type=float, default=5.0, help="timeout DNS en segundos (default: 5.0)")
    p.add_argument("-j", "--json", action="store_true", help="Salida JSON")
    p.add_argument("--no-banner", action="store_true", help="No mostrar banner colorido")
    return p.parse_args()

def pretty_print(res: Dict[str, Any]):
    if "error" in res:
        print(Fore.RED + "[X] Error: " + res['error'])
        return

    print(Fore.CYAN + f"Input IP: {res['input_ip']}")
    if not res["reverse"]:
        print(Fore.YELLOW + "Reverse PTR: (ninguno encontrado)")
    else:
        print(Fore.GREEN + "Reverse PTR (hostnames):")
        for h in res["reverse"]:
            print(Style.BRIGHT + "  - " + h)

    if not res["forwards"]:
        print(Fore.MAGENTA + "Forward DNS: (no hubo hostnames para resolver)")
    else:
        print("\n" + Style.BRIGHT + "Forward DNS por hostname:")
        for h, info in res["forwards"].items():
            print(Fore.BLUE + f"\nHostname: {h}")
            print(Fore.WHITE + f"  A   : {', '.join(info['A']) if info['A'] else '(sin A)'}")
            print(Fore.WHITE + f"  AAAA: {', '.join(info['AAAA']) if info['AAAA'] else '(sin AAAA)'}")
            match_text = (Fore.GREEN + "YES") if info['roundtrip_match'] else (Fore.RED + "NO")
            print(Style.BRIGHT + f"  Round-trip match? {match_text}")

    if res["related_domains"]:
        print("\n" + Fore.CYAN + Style.BRIGHT + "Dominios relacionados (crt.sh):")
        for d in res["related_domains"]:
            print("  - " + d)
    else:
        print(Fore.YELLOW + "No se encontraron dominios relacionados en crt.sh")

# -----------------------
# Main
# -----------------------
def main():
    args = parse_args()
    if not args.no_banner:
        print_banner()

    try:
        result = inspect_ip(args.ip, timeout=args.timeout)
    except Exception as e:
        print(Fore.RED + f"[X] Error inesperado: {e}", file=sys.stderr)
        sys.exit(2)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        pretty_print(result)

if __name__ == "__main__":
    main()