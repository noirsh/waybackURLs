import sys
import json
import requests
from urllib.parse import urlparse
from datetime import datetime
import os
from threading import Thread
from queue import Queue

def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--dates", action="store_true", help="show date of fetch in the first column")
    parser.add_argument("--no-subs", action="store_true", help="don't include subdomains of the target domain")
    parser.add_argument("--get-versions", action="store_true", help="list URLs for crawled versions of input URL(s)")
    parser.add_argument("domain", nargs="?", help="the domain to fetch URLs for")
    args = parser.parse_args()

    domains = []
    if args.domain:
        domains = [args.domain]
    else:
        domains = [line.strip() for line in sys.stdin]

    if args.get_versions:
        for domain in domains:
            versions = get_versions(domain)
            if versions:
                print("\n".join(versions))
        return

    fetch_fns = [get_wayback_urls, get_common_crawl_urls, get_virus_total_urls]

    for domain in domains:
        q = Queue()
        threads = []
        for fn in fetch_fns:
            t = Thread(target=lambda f=fn: fetch_urls(f, domain, args.no_subs, q))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        seen = set()
        while not q.empty():
            w = q.get()
            if w['url'] in seen:
                continue
            seen.add(w['url'])

            if args.dates:
                try:
                    d = datetime.strptime(w['date'], "%Y%m%d%H%M%S")
                    print(f"{d.isoformat()} {w['url']}")
                except ValueError:
                    print(f"failed to parse date [{w['date']}] for URL [{w['url']}]", file=sys.stderr)
            else:
                print(w['url'])

def fetch_urls(fn, domain, no_subs, q):
    try:
        resp = fn(domain, no_subs)
        for r in resp:
            if no_subs and is_subdomain(r['url'], domain):
                continue
            q.put(r)
    except Exception as e:
        print(f"Error fetching URLs: {e}", file=sys.stderr)

def get_wayback_urls(domain, no_subs):
    subs_wildcard = "*." if not no_subs else ""
    url = f"http://web.archive.org/cdx/search/cdx?url={subs_wildcard}{domain}/*&output=json&collapse=urlkey"
    response = requests.get(url)
    response.raise_for_status()
    wrapper = response.json()

    out = []
    skip = True
    for urls in wrapper:
        if skip:
            skip = False
            continue
        out.append({'date': urls[1], 'url': urls[2]})
    return out

def get_common_crawl_urls(domain, no_subs):
    subs_wildcard = "*." if not no_subs else ""
    url = f"http://index.commoncrawl.org/CC-MAIN-2018-22-index?url={subs_wildcard}{domain}/*&output=json"
    response = requests.get(url)
    response.raise_for_status()

    out = []
    for line in response.iter_lines():
        if line:
            wrapper = json.loads(line)
            out.append({'date': wrapper['timestamp'], 'url': wrapper['url']})
    return out

def get_virus_total_urls(domain, no_subs):
    out = []
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return out

    url = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key}&domain={domain}"
    response = requests.get(url)
    response.raise_for_status()
    wrapper = response.json()

    for u in wrapper.get('detected_urls', []):
        out.append({'url': u['url']})
    return out

def is_subdomain(raw_url, domain):
    try:
        u = urlparse(raw_url)
        return u.hostname != domain
    except:
        return False

def get_versions(u):
    out = []
    url = f"http://web.archive.org/cdx/search/cdx?url={u}&output=json"
    response = requests.get(url)
    response.raise_for_status()
    r = response.json()

    first = True
    seen = set()
    for s in r:
        if first:
            first = False
            continue
        if s[5] in seen:
            continue
        seen.add(s[5])
        out.append(f"https://web.archive.org/web/{s[1]}if_/{s[2]}")
    return out

if __name__ == "__main__":
    main()
