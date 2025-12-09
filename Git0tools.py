#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import json
import socket
import ssl
import re
import datetime
import requests
import dns.resolver
import whois
import tldextract
from PIL import Image
from PIL.ExifTags import TAGS
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)

# =======================
# BANNER
# =======================
def banner():
    print(Fore.GREEN + r"""
  ____  ____  ___ _   _ _____ _____ 
 |  _ \|  _ \|_ _| \ | |_   _| ____|
 | | | | | | || ||  \| | | | |  _|  
 | |_| | |_| || || |\  | | | | |___ 
 |____/|____/|___|_| \_| |_| |_____|
    """)
    print(Fore.CYAN + "OSINT MULTITOOL")
    print(Fore.MAGENTA + "dev by brzx_xx\n")

# =======================
# DISCORD OSINT
# =======================
DISCORD_EPOCH = 1420070400000

def discord_id_to_date(discord_id):
    try:
        timestamp = (int(discord_id) >> 22) + DISCORD_EPOCH
        return datetime.datetime.fromtimestamp(timestamp / 1000).strftime("%Y-%m-%d %H:%M:%S")
    except:
        return "ID invalide"

def discord_avatar_url(user_id, avatar_hash=None):
    if avatar_hash:
        return f"https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.png"
    return f"https://cdn.discordapp.com/embed/avatars/{int(user_id) % 5}.png"

def discord_invite_lookup(code):
    try:
        r = requests.get(f"https://discord.com/api/v9/invites/{code}?with_counts=true", timeout=5)
        return r.json()
    except:
        return "Erreur invite"

def discord_username_check(username):
    return bool(re.match(r"^[a-zA-Z0-9_.]{2,32}$", username))

# =======================
# OSINT GÉNÉRAL
# =======================
def geoip(ip):
    return requests.get(f"http://ip-api.com/json/{ip}").json()

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Aucun PTR"

def dns_lookup(domain):
    try:
        return [r.to_text() for r in dns.resolver.resolve(domain, 'A')]
    except:
        return "Erreur DNS"

def mx_lookup(domain):
    try:
        return [str(r.exchange) for r in dns.resolver.resolve(domain, 'MX')]
    except:
        return "Erreur MX"

def whois_lookup(domain):
    try:
        return whois.whois(domain)
    except:
        return "WHOIS error"

def ssl_info(domain):
    ctx = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            return ssock.getpeercert()

def http_headers(url):
    if not url.startswith("http"):
        url = "http://" + url
    r = requests.head(url, allow_redirects=True)
    return dict(r.headers)

def robots_txt(url):
    if not url.startswith("http"):
        url = "http://" + url
    base = re.match(r"(https?://[^/]+)", url)[0]
    return requests.get(base + "/robots.txt").text

def parse_domain(url):
    ext = tldextract.extract(url)
    return ext._asdict()

def exif_image(path):
    img = Image.open(path)
    return {TAGS.get(k): v for k, v in (img._getexif() or {}).items()}

def email_check(email):
    ok = bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))
    domain = email.split("@")[-1] if ok else None
    try:
        dns.resolver.resolve(domain, "MX")
        mx = True
    except:
        mx = False
    return {"format_ok": ok, "domain": domain, "mx": mx}

def page_meta(url):
    if not url.startswith("http"):
        url = "http://" + url
    soup = BeautifulSoup(requests.get(url).text, "html.parser")
    return {
        "title": soup.title.string if soup.title else None,
        "description": soup.find("meta", {"name": "description"})
    }

# =======================
# MENU
# =======================
def menu():
    banner()
    print(Fore.YELLOW + """
[1] Discord ID lookup (date)
[2] Discord Avatar URL
[3] Discord Invite lookup
[4] Discord username check
[5] IP GeoIP
[6] Reverse DNS
[7] DNS lookup
[8] MX lookup
[9] WHOIS domain
[10] SSL info
[11] HTTP headers
[12] robots.txt
[13] Domain parser
[14] Image EXIF
[15] Email check
[16] Page title/meta
[0] Quit
""")

# =======================
# MAIN
# =======================
while True:
    menu()
    c = input("Select > ")

    if c == "0":
        break
    elif c == "1":
        print(discord_id_to_date(input("Discord ID > ")))
    elif c == "2":
        print(discord_avatar_url(input("User ID > "), input("Avatar hash (optionnel) > ")))
    elif c == "3":
        print(json.dumps(discord_invite_lookup(input("Invite code > ")), indent=2))
    elif c == "4":
        print(discord_username_check(input("Username > ")))
    elif c == "5":
        print(geoip(input("IP > ")))
    elif c == "6":
        print(reverse_dns(input("IP > ")))
    elif c == "7":
        print(dns_lookup(input("Domain > ")))
    elif c == "8":
        print(mx_lookup(input("Domain > ")))
    elif c == "9":
        print(whois_lookup(input("Domain > ")))
    elif c == "10":
        print(ssl_info(input("Domain > ")))
    elif c == "11":
        print(http_headers(input("URL > ")))
    elif c == "12":
        print(robots_txt(input("URL > ")))
    elif c == "13":
        print(parse_domain(input("URL > ")))
    elif c == "14":
        print(exif_image(input("Image path > ")))
    elif c == "15":
        print(email_check(input("Email > ")))
    elif c == "16":
        print(page_meta(input("URL > ")))