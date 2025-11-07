# scanner/scanner.py
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin
import validators
import time

XSS_PAYLOAD = "<script>alert('xss')</script>"
SQLI_PAYLOADS = ["' OR '1'='1", "' OR 1=1 -- ", "'; DROP TABLE users; --"]

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "sqlite3.OperationalError"
]

HEADERS = {"User-Agent": "BlacklatchScanner/1.0"}

def fetch(url, timeout=8):
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout, verify=False)
        return r
    except Exception as e:
        return None

def get_links(base_url, html):
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for a in soup.find_all("a", href=True):
        href = a['href']
        full = urljoin(base_url, href)
        if validators.url(full):
            links.add(full)
    return list(links)

def find_forms(html):
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        f = {"action": form.get("action"), "method": form.get("method", "get").lower(), "inputs": []}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            typ = inp.get("type", "text")
            if name:
                f["inputs"].append({"name": name, "type": typ})
        forms.append(f)
    return forms

def test_xss(url, form=None):
    evidence = None
    if form:
        # Prepare data
        data = {}
        for i in form['inputs']:
            data[i['name']] = XSS_PAYLOAD
        target = urljoin(url, form['action']) if form.get('action') else url
        try:
            if form['method'] == 'post':
                r = requests.post(target, data=data, headers=HEADERS, timeout=8, verify=False)
            else:
                r = requests.get(target, params=data, headers=HEADERS, timeout=8, verify=False)
            if XSS_PAYLOAD in r.text:
                evidence = {"type":"xss","target":target,"payload":XSS_PAYLOAD}
        except Exception:
            pass
    else:
        # test URL reflection
        test_url = url + "?q=" + XSS_PAYLOAD
        try:
            r = requests.get(test_url, headers=HEADERS, timeout=8, verify=False)
            if XSS_PAYLOAD in r.text:
                evidence = {"type":"xss","target":test_url,"payload":XSS_PAYLOAD}
        except Exception:
            pass
    return evidence

def test_sqli(url, param=None):
    for payload in SQLI_PAYLOADS:
        turl = url
        if param:
            turl = turl.replace(param, payload)
        else:
            turl = url + "?id=" + payload
        try:
            r = requests.get(turl, headers=HEADERS, timeout=8, verify=False)
            text = r.text.lower()
            for err in SQL_ERRORS:
                if err in text:
                    return {"type":"sqli","target":turl,"payload":payload,"evidence_snippet":text[:500]}
        except Exception:
            pass
    return None

def crawl_and_scan(start_url, max_pages=30):
    start_time = time.time()
    results = {"start_url": start_url, "scanned": 0, "findings": []}
    if not validators.url(start_url):
        return {"error":"invalid URL"}
    to_crawl = [start_url]
    crawled = set()
    while to_crawl and len(crawled) < max_pages:
        url = to_crawl.pop(0)
        if url in crawled:
            continue
        r = fetch(url)
        if not r:
            crawled.add(url)
            continue
        html = r.text
        crawled.add(url)
        results['scanned'] += 1

        # find forms
        forms = find_forms(html)
        for form in forms:
            x = test_xss(url, form=form)
            if x:
                results['findings'].append(x)
            s = test_sqli(url, param=None)
            if s:
                results['findings'].append(s)

        # test url params
        x2 = test_xss(url, form=None)
        if x2:
            results['findings'].append(x2)
        s2 = test_sqli(url)
        if s2:
            results['findings'].append(s2)

        # gather new links
        links = get_links(url, html)
        for l in links:
            if l not in crawled and l not in to_crawl and start_url in l:
                to_crawl.append(l)

    results['duration_sec'] = time.time() - start_time
    return results
