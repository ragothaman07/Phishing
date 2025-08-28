# -*- coding: utf-8 -*-
"""
Feature Extraction for Phishing URL Detection
"""

from urllib.parse import urlparse
import ipaddress
import re
import urllib
import urllib.request
from datetime import datetime
from bs4 import BeautifulSoup
import requests
import whois

# -----------------------
#  Address Bar Features
# -----------------------

def havingIP(url: str) -> int:
    """Check if the URL contains an IP address instead of a domain."""
    try:
        ipaddress.ip_address(url)
        return 1
    except:
        return 0


def haveAtSign(url: str) -> int:
    """Check presence of '@' symbol in URL."""
    return 1 if "@" in url else 0


def getLength(url: str) -> int:
    """Check if URL length >= 54 characters."""
    return 1 if len(url) >= 54 else 0


def getDepth(url: str) -> int:
    """Calculate depth of the URL path (number of subpages)."""
    s = urlparse(url).path.split('/')
    depth = sum(1 for part in s if len(part) > 0)
    return depth


def redirection(url: str) -> int:
    """Check for '//' redirection in the URL path."""
    pos = url.rfind('//')
    if pos > 6:
        return 1
    return 0


def httpDomain(url: str) -> int:
    """Check if 'http' or 'https' is in the domain part."""
    domain = urlparse(url).netloc
    return 1 if 'https' in domain else 0


shortening_services = (
    r"bit\.ly|goo\.gl|shorte\.st|x\.co|ow\.ly|t\.co|tinyurl|is\.gd|cli\.gs|"
    r"tr\.im|j\.mp|u\.to|qr\.ae|po\.st|bc\.vc|cutt\.us|yourls\.org|"
    r"prettylinkpro\.com|v\.gd|link\.zip\.net"
)

def tinyURL(url: str) -> int:
    """Check if URL is shortened using popular shortening services."""
    return 1 if re.search(shortening_services, url) else 0


def prefixSuffix(url: str) -> int:
    """Check for '-' in the domain part of the URL."""
    return 1 if '-' in urlparse(url).netloc else 0


# -----------------------
#  Domain Based Features
# -----------------------

def web_traffic(url: str) -> int:
    """Check Alexa rank (web traffic)."""
    try:
        url = urllib.parse.quote(url)
        rank = BeautifulSoup(
            urllib.request.urlopen(
                "http://data.alexa.com/data?cli=10&dat=s&url=" + url
            ).read(),
            "xml"
        ).find("REACH")['RANK']
        rank = int(rank)
        return 1 if rank < 100000 else 0
    except:
        return 1


def domainAge(domain_name) -> int:
    """Check domain age (phishing if < 6 months)."""
    try:
        creation_date = domain_name.creation_date
        expiration_date = domain_name.expiration_date

        if isinstance(creation_date, str) or isinstance(expiration_date, str):
            creation_date = datetime.strptime(str(creation_date), '%Y-%m-%d')
            expiration_date = datetime.strptime(str(expiration_date), '%Y-%m-%d')

        if not creation_date or not expiration_date:
            return 1

        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        ageofdomain = abs((expiration_date - creation_date).days)
        return 1 if (ageofdomain / 30) < 6 else 0
    except:
        return 1


def domainEnd(domain_name) -> int:
    """Check remaining domain life (phishing if < 6 months)."""
    try:
        expiration_date = domain_name.expiration_date

        if isinstance(expiration_date, str):
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        if not expiration_date:
            return 1
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        today = datetime.now()
        end = abs((expiration_date - today).days)
        return 0 if (end / 30) < 6 else 1
    except:
        return 1


# -----------------------
#  HTML & JavaScript Features
# -----------------------

def iframe(response) -> int:
    """Check for iframe usage."""
    if response == "":
        return 1
    return 0 if re.findall(r"[<iframe>|<frameBorder>]", response.text) else 1


def mouseOver(response) -> int:
    """Check for mouse over status bar manipulation."""
    if response == "":
        return 1
    return 1 if re.findall("<script>.+onmouseover.+</script>", response.text) else 0


def rightClick(response) -> int:
    """Check if right-click is disabled via JS."""
    if response == "":
        return 1
    return 0 if re.findall(r"event.button ?== ?2", response.text) else 1


def forwarding(response) -> int:
    """Check number of redirections (phishing if >2)."""
    if response == "":
        return 1
    return 0 if len(response.history) <= 2 else 1


# -----------------------
#  Feature Extraction Wrapper
# -----------------------

def featureExtraction(url: str):
    """Extract all features for a given URL."""
    features = []

    # Address bar features
    features.append(havingIP(url))
    features.append(haveAtSign(url))
    features.append(getLength(url))
    features.append(getDepth(url))
    features.append(redirection(url))
    features.append(httpDomain(url))
    features.append(tinyURL(url))
    features.append(prefixSuffix(url))

    # Domain features
    dns = 0
    try:
        domain_name = whois.whois(urlparse(url).netloc)
    except:
        dns = 1
        domain_name = None

    features.append(dns)
    features.append(web_traffic(url))
    features.append(1 if dns == 1 else domainAge(domain_name))
    features.append(1 if dns == 1 else domainEnd(domain_name))

    # HTML & JavaScript features
    try:
        response = requests.get(url, timeout=5)
    except:
        response = ""

    features.append(iframe(response))
    features.append(mouseOver(response))
    features.append(rightClick(response))
    features.append(forwarding(response))

    return features


# Feature names (excluding label)
feature_names = [
    'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection',
    'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record',
    'Web_Traffic', 'Domain_Age', 'Domain_End',
    'iFrame', 'Mouse_Over', 'Right_Click', 'Web_Forwards'
]
