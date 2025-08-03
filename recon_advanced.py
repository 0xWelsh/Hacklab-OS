# Features:
# - WHOIS information lookup
# - Subdomain enumeration
# - Port scanning (with common ports or full scan)
# - Historical URL discovery via Wayback Machine
# - Technology detection
# - Comprehensive reporting

import socket
import requests
import whois
import concurrent.futures
from urllib.parse import urlparse
import dns.resolver
import time
from datetime import datetime
import argparse

# Configuration
MAX_THREADS = 50  # For concurrent port scanning
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 8080]
TIMEOUT = 2  # Socket timeout in seconds
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

def get_whois_info(domain):
    """Retrieve WHOIS information for a domain"""
    try:
        domain = domain.strip().lower()
        if not domain.startswith('http'):
            domain = 'http://' + domain
        parsed = urlparse(domain)
        domain = parsed.netloc or parsed.path.split('/')[0]
        
        print(f"[*] Querying WHOIS for: {domain}")
        w = whois.whois(domain)
        
        result = {
            'domain_name': w.domain_name,
            'registrar': w.registrar,
            'creation_date': w.creation_date,
            'expiration_date': w.expiration_date,
            'name_servers': w.name_servers,
            'emails': w.emails,
            'status': w.status
        }
        return result
    except Exception as e:
        return f"WHOIS lookup failed: {str(e)}"

def scan_port(domain, port):
    """Check if a single port is open"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            result = sock.connect_ex((domain, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                return (port, service)
        return None
    except Exception:
        return None

def scan_open_ports(domain, ports_to_scan=None):
    """Scan for open ports using multithreading"""
    if ports_to_scan is None:
        ports_to_scan = COMMON_PORTS
    
    print(f"[*] Scanning {len(ports_to_scan)} ports on {domain}")
    
    open_ports = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(scan_port, domain, port): port for port in ports_to_scan}
        
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            try:
                result = future.result()
                if result:
                    open_ports.append(result)
                    print(f"[+] Found open port: {result[0]} ({result[1]})")
            except Exception as e:
                print(f"[-] Error scanning port {port}: {str(e)}")
    
    return sorted(open_ports, key=lambda x: x[0])

def discover_historical_urls(domain):
    """Retrieve historical URLs from Wayback Machine"""
    print(f"[*] Checking Wayback Machine for: {domain}")
    
    try:
        url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=timestamp,original&collapse=urlkey&limit=100"
        response = requests.get(url, headers=HEADERS, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if len(data) > 1:
                results = []
                for entry in data[1:]:
                    timestamp = entry[0]
                    url = entry[1]
                    date = datetime.strptime(timestamp, "%Y%m%d%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
                    results.append((date, url))
                return results
        return []
    except Exception as e:
        print(f"[-] Wayback Machine query failed: {str(e)}")
        return []

def find_subdomains(domain, wordlist=None):
    """Discover subdomains using DNS enumeration"""
    print(f"[*] Searching for subdomains of: {domain}")
    
    if wordlist is None:
        # Basic list of common subdomains
        wordlist = ['www', 'mail', 'ftp', 'admin', 'webmail', 'server', 'ns1', 'ns2', 
                   'test', 'dev', 'staging', 'api', 'blog', 'shop', 'm', 'mobile']
    
    found_subdomains = []
    
    for sub in wordlist:
        subdomain = f"{sub}.{domain}"
        try:
            answers = dns.resolver.resolve(subdomain, 'A')
            for answer in answers:
                found_subdomains.append((subdomain, str(answer)))
                print(f"[+] Found subdomain: {subdomain} -> {answer}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            continue
        except Exception as e:
            print(f"[-] Error resolving {subdomain}: {str(e)}")
    
    return found_subdomains

def get_website_tech(url):
    """Identify technologies used by a website"""
    try:
        if not url.startswith('http'):
            url = 'http://' + url
        
        print(f"[*] Analyzing technologies for: {url}")
        headers = requests.get(url, headers=HEADERS, timeout=10).headers
        
        tech_info = {
            'server': headers.get('Server', ''),
            'x-powered-by': headers.get('X-Powered-By', ''),
            'x-aspnet-version': headers.get('X-AspNet-Version', '')
        }
        
        return tech_info
    except Exception as e:
        return f"Technology detection failed: {str(e)}"

def generate_report(domain, results):
    """Generate a simple text report"""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"recon_report_{domain}_{timestamp}.txt"
    
    with open(filename, 'w') as f:
        f.write(f"Reconnaissance Report for {domain}\n")
        f.write(f"Generated on: {timestamp}\n\n")
        
        for section, data in results.items():
            f.write(f"=== {section.upper()} ===\n")
            if isinstance(data, (list, tuple)):
                for item in data:
                    if isinstance(item, (list, tuple)):
                        f.write(f"- {' | '.join(map(str, item))}\n")
                    else:
                        f.write(f"- {item}\n")
            elif isinstance(data, dict):
                for key, value in data.items():
                    f.write(f"- {key}: {value}\n")
            else:
                f.write(f"{data}\n")
            f.write("\n")
    
    print(f"[+] Report saved to: {filename}")
    return filename

def main():
    parser = argparse.ArgumentParser(description="Enhanced Target Reconnaissance Tool")
    parser.add_argument("domain", help="Domain to investigate")
    parser.add_argument("--full-port-scan", action="store_true", 
                       help="Scan all 1024 ports instead of just common ones")
    parser.add_argument("--subdomain-wordlist", 
                       help="Path to custom subdomain wordlist file")
    args = parser.parse_args()
    
    target_domain = args.domain.lower().strip()
    if target_domain.startswith('http'):
        target_domain = urlparse(target_domain).netloc
    
    print(f"\n[=== Starting reconnaissance on {target_domain} ===]\n")
    
    start_time = time.time()
    
    # Load custom wordlist if provided
    wordlist = None
    if args.subdomain_wordlist:
        try:
            with open(args.subdomain_wordlist, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
            print(f"[*] Loaded {len(wordlist)} subdomains from wordlist")
        except Exception as e:
            print(f"[-] Error loading wordlist: {str(e)}")
            wordlist = None
    
    # Execute all checks
    results = {
        'whois_info': get_whois_info(target_domain),
        'subdomains': find_subdomains(target_domain, wordlist),
        'open_ports': scan_open_ports(target_domain, 
                                     range(1, 1025) if args.full_port_scan else COMMON_PORTS),
        'historical_urls': discover_historical_urls(target_domain),
        'technologies': get_website_tech(target_domain)
    }
    
    # Generate report
    report_file = generate_report(target_domain, results)
    
    elapsed_time = time.time() - start_time
    print(f"\n[=== Reconnaissance completed in {elapsed_time:.2f} seconds ===]")
    print(f"[=== Results saved to {report_file} ===]\n")

if __name__ == "__main__":
    main()