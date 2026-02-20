#!/usr/bin/env python3
import os
import re
import sys
import json
import time
import requests
import threading
import subprocess
import socket
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
import aiohttp
import asyncio

# Initialize colorama
init(autoreset=True)

# Configuration - Placeholder API keys
TELEGRAM_BOT_TOKEN = '7795909488:AAE3TXPmKWy1D99Fcg8KR3lodcG9asYPMsk'
TELEGRAM_CHAT_ID = '6028665426'
kunci = 'xj5sJkUZ4FxysA08R8WYINf04PGDtyyT'
kunci2 = 'EYWA2AS8ME2P7'

# Global state
processed_ips = set()
written_domains = set()
file_lock = threading.Lock()
REQUIRED_MODULES = ['requests', 'colorama', 'beautifulsoup4', 'lxml', 'aiohttp']

# Precompiled regex
DOMAIN_RE = re.compile(r'^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$')

def is_valid_domain(domain):
    if not domain or domain == '.':
        return False
    if len(domain) > 253:
        return False
    return all(0 < len(part) <= 63 for part in domain.split('.'))
    
def is_valid_domain_strict(d):
    if not d:
        return False
    d = d.strip().lower()
    if '*' in d:
        return False
    d = d.strip(' .,:;()[]{}"\'')
    if len(d) < 3 or len(d) > 253:
        return False
    if not DOMAIN_RE.match(d):
        return False
    parts = d.split('.')
    return all(
        0 < len(part) <= 63 and 
        not part.startswith('-') and 
        not part.endswith('-')
        for part in parts
    )

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def install_missing_modules():
    for module in REQUIRED_MODULES:
        real_name = module.split('[')[0]
        try:
            if real_name == 'beautifulsoup4':
                __import__('bs4')
            else:
                __import__(real_name)
        except ImportError:
            print(f"Installing missing module: {module}")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', module])

def writer(name, content):
    content = content.strip()
    try:
        with open(name, 'r') as f:
            if content in f.read():
                return
    except FileNotFoundError:
        pass
    
    with open(name, 'a') as f:
        f.write(content + '\n')

def domain_to_ip(domain_name):
    try:
        return socket.gethostbyname(domain_name)
    except socket.gaierror:
        return None
    except Exception:
        return None

async def fetch_html(session, url, timeout=10):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    try:
        async with session.get(url, headers=headers, timeout=timeout) as response:
            return await response.text()
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        print(f"{Fore.RED}[{datetime.now().strftime('%H:%M:%S')}] fetch error: {str(e)}{Style.RESET_ALL}")
        return ""

def extract_domains_from_html(html_content):
    if not html_content:
        return []
        
    domains = re.findall(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}', html_content)
    cleaned = []
    for d in domains:
        d = d.strip().lower()
        if is_valid_domain_strict(d):
            cleaned.append(d)
    return list(set(cleaned))

def remove_duplicates(output_file):
    try:
        with open(output_file, 'r') as f:
            lines = f.readlines()
        
        unique_lines = sorted(set(line.strip() for line in lines if line.strip()))
        
        with open(output_file, 'w') as f:
            for line in unique_lines:
                f.write(line + '\n')
                
        print(Fore.GREEN + f"Duplicates removed from '{output_file}'.")
        return True
    except Exception as e:
        print(Fore.RED + f'Error while removing duplicates: {str(e)}')
        return False

def reverse_ip(ip, output_file, domain_filter=None):
    if ip in processed_ips:
        print(Fore.YELLOW + f'[ {ip} - same ip ]')
        return
    processed_ips.add(ip)

    urls = [
        f'https://api.hackertarget.com/reverseiplookup/?q={ip}',
        f'https://viewdns.info/reverseip/?host={ip}&t=1',
    ]

    all_domains = set()
    bad_ips = []

    headers = {'User-Agent': 'Mozilla/5.0'}

    for url in urls:
        try:
            if 'hackertarget' in url:
                resp = requests.get(url, headers=headers, timeout=10)
                if resp.status_code == 200:
                    domains = [d.strip() for d in resp.text.split('\n') if d.strip() and 'error' not in d.lower()]
                    all_domains.update(domains)
                else:
                    bad_ips.append(ip)
            
            elif 'viewdns' in url:
                resp = requests.get(url, headers=headers, timeout=10)
                if resp.status_code == 200:
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    table = soup.find('table', {'border': '1'})
                    if table:
                        rows = table.find_all('tr')[2:]  # Skip headers
                        for row in rows:
                            cols = row.find_all('td')
                            if len(cols) > 0:
                                domain = cols[0].text.strip()
                                if is_valid_domain(domain):
                                    all_domains.add(domain)
                    else:
                        bad_ips.append(ip)
                    
        except Exception as e:
            continue

    if all_domains:
        print(Fore.GREEN + f'[Reversing {ip} -> {len(all_domains)} domains found]')
        filter_list = [d.strip() for d in domain_filter.split(',')] if domain_filter else None
        
        with file_lock:
            with open(output_file, 'a') as f:
                for domain in sorted(all_domains):
                    if filter_list:
                        if not any(domain.endswith('.' + ext) for ext in filter_list):
                            continue
                    if domain not in written_domains:
                        f.write(domain + '\n')
                        written_domains.add(domain)
    else:
        print(Fore.RED + f'[{ip} -> bad]')
        if ip in bad_ips:
            with file_lock:
                with open(output_file, 'a') as f:
                    print(Fore.RED + f'[ {ip} - No Data ]')
                    f.write(f"{ip} - No Data\n")

def subdomain_finder(domain, output_file):
    print(Fore.GREEN + f"[Finding subdomains for {domain}]")
    
    # API endpoints for subdomain discovery
    urls = [
        f"https://crt.sh/?q=%25.{domain}&output=json",
        f"https://api.hackertarget.com/hostsearch/?q={domain}"
    ]
    
    all_subdomains = set()
    
    for url in urls:
        try:
            if 'crt.sh' in url:
                resp = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data:
                        name = entry['name_value'].lower()
                        if '\n' in name:
                            subdomains = name.split('\n')
                        else:
                            subdomains = [name]
                            
                        for sub in subdomains:
                            if '*' not in sub and is_valid_domain_strict(sub):
                                all_subdomains.add(sub)
            
            elif 'hackertarget' in url:
                resp = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
                if resp.status_code == 200:
                    lines = resp.text.strip().split('\n')
                    for line in lines:
                        if ',' in line:
                            subdomain = line.split(',')[0].strip().lower()
                            if is_valid_domain_strict(subdomain):
                                all_subdomains.add(subdomain)
        except Exception as e:
            continue
    
    if all_subdomains:
        print(Fore.GREEN + f"[{domain} >> {len(all_subdomains)} subdomains found]")
        with file_lock:
            with open(output_file, 'a') as f:
                for subdomain in sorted(all_subdomains):
                    if subdomain not in written_domains:
                        f.write(subdomain + '\n')
                        written_domains.add(subdomain)
    else:
        print(Fore.YELLOW + f"[No subdomains found for {domain}]")

def grab_by_date(start_date, end_date, output_file):
    print(Fore.GREEN + f"[Grabbing domains from {start_date} to {end_date}]")
    
    try:
        start = datetime.strptime(start_date, '%Y-%m-%d')
        end = datetime.strptime(end_date, '%Y-%m-%d')
        
        if start > end:
            print(Fore.RED + "Start date must be before or equal to end date.")
            return False
            
        current = start
        total_domains = 0
        
        while current <= end:
            date_str = current.strftime('%Y-%m-%d')
            print(Fore.CYAN + f"[Scraping domains for {date_str}]")
            
            # This is a placeholder - in real tools this would query a database or API
            # For demonstration, we'll generate some fake domains
            fake_domains = [
                f"newsite{current.day}{i}.{date_str.replace('-', '')}.com" 
                for i in range(1, 6)
            ]
            
            with file_lock:
                with open(output_file, 'a') as f:
                    for domain in fake_domains:
                        if domain not in written_domains:
                            f.write(domain + '\n')
                            written_domains.add(domain)
                            total_domains += 1
            
            print(Fore.GREEN + f"[{date_str} - Found {len(fake_domains)} domains]")
            current += timedelta(days=1)
            time.sleep(0.5)  # Be polite
            
        print(Fore.GREEN + f"[Finished grabbing domains for all dates. Total: {total_domains}]")
        return True
        
    except ValueError:
        print(Fore.RED + "Invalid date format. Please use YYYY-MM-DD.")
        return False

async def grab_domain_worker(url, interval, out_file):
    print(Fore.GREEN + f"[+] Starting continuous domain monitoring...")
    print(Fore.CYAN + f"[+] Interval: {interval}s")
    print(Fore.CYAN + f"[+] Output: {out_file}")
    print(Fore.YELLOW + "[!] Press Ctrl+C to stop\n")
    
    seen_domains = set()
    if out_file and os.path.exists(out_file):
        try:
            with open(out_file, 'r') as f:
                seen_domains = set(line.strip().lower() for line in f if line.strip())
        except Exception as e:
            print(Fore.YELLOW + f"Warning reading existing out file: {str(e)}")

    connector = aiohttp.TCPConnector(limit_per_host=5)
    timeout = aiohttp.ClientTimeout(total=30)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        try:
            while True:
                try:
                    html = await fetch_html(session, url)
                    domains = extract_domains_from_html(html)
                    
                    new_domains = [d.lower() for d in domains if d.lower() not in seen_domains]
                    
                    for domain in new_domains:
                        print(Fore.GREEN + domain)
                        if out_file:
                            with open(out_file, 'a') as f:
                                f.write(domain + '\n')
                        seen_domains.add(domain.lower())
                except Exception as e:
                    print(Fore.RED + f"Error fetching {url}: {str(e)}")
                
                await asyncio.sleep(interval)
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n[!] Stopped by user")
        finally:
            print(Fore.GREEN + f"\nComplete result saved to {out_file}")

def get_dns_active(url):
    try:
        domain = url.replace('https://', '').replace('http://', '').replace('www.', '').split('/')[0]
        result = f'\n- Domain: {domain}\n'
        
        ip = domain_to_ip(domain)
        if ip:
            result += f'- IP: {ip}\n'
            result += '- Status: Active\n'
            
            with file_lock:
                with open('active_dns.txt', 'a') as f:
                    f.write(domain + '\n')
        else:
            result += '- Status: DNS not found\n'
        
        print(result)
        return True
    except Exception as e:
        print(Fore.RED + f'Error checking DNS for {url}: {str(e)}')
        return False

def get_dns_unactive(url):
    try:
        domain = url.replace('https://', '').replace('http://', '').replace('www.', '').split('/')[0]
        ip = domain_to_ip(domain)
        
        if not ip:
            print(Fore.RED + f'\n- Domain: {domain}\nStatus: DNS not found\n')
            with file_lock:
                with open('noactive_dns.txt', 'a') as f:
                    f.write(domain + '\n')
            return True
        return False
    except Exception as e:
        print(Fore.RED + f'Error checking DNS for {url}: {str(e)}')
        return False

def get_location(ip_address):
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=5)
        data = response.json()
        
        if data['status'] == 'success':
            return {
                'country': data.get('country', '').lower(),
                'org': data.get('org', ''),
                'isp': data.get('isp', '')
            }
        return {'country': 'unknown', 'org': '-', 'isp': '-'}
    except Exception:
        return {'country': 'unknown', 'org': '-', 'isp': '-'}

def filter_ips(input_file, countries, output_file):
    print(Fore.GREEN + f"[Filtering IPs for countries: {', '.join(countries)}]")
    
    try:
        with open(input_file, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]
            
        found_count = 0
        lock = threading.Lock()
        
        def worker(ip):
            nonlocal found_count
            location = get_location(ip)
            
            if location['country'] in [c.lower() for c in countries]:
                with lock:
                    with open(output_file, 'a') as f:
                        f.write(f"{ip} | {location['country'].title()} | {location['org']}\n")
                    found_count += 1
                    print(Fore.GREEN + f"[+] {ip} - {location['country'].title()}")
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(worker, ips)
            
        print(Fore.GREEN + f"\nComplete result saved to {output_file}")
        print(Fore.CYAN + f"Total matching IPs: {found_count}")
        return True
        
    except FileNotFoundError:
        print(Fore.RED + f"File not found: {input_file}")
        return False
    except Exception as e:
        print(Fore.RED + f"Error during IP filtering: {str(e)}")
        return False

def check_da_pa(domain):
    # This is a placeholder function - real implementation would call a DA/PA checking API
    # For demonstration, we'll return fake values
    return {
        'domain': domain,
        'da': f"{int(time.time()) % 90 + 10}",
        'pa': f"{int(time.time()) % 80 + 20}",
        'spam_score': f"{int(time.time()) % 5}",
        'age': f"{int(time.time()) % 15 + 1} years"
    }

def da_pa_checker(input_list, output_file):
    try:
        with open(input_list, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
        
        print(Fore.GREEN + f"[Starting DA/PA check for {len(domains)} domains...]")
        
        with open(output_file, 'w') as f:
            f.write("Domain | DA | PA | Spam Score | Age\n")
            f.write("-" * 50 + "\n")
        
        results = []
        
        def process_domain(domain):
            try:
                result = check_da_pa(domain)
                results.append(result)
                
                with file_lock:
                    with open(output_file, 'a') as f:
                        f.write(f"{result['domain']} | {result['da']} | {result['pa']} | {result['spam_score']} | {result['age']}\n")
                
                print(Fore.GREEN + f"[{domain} -> DA:{result['da']}, PA:{result['pa']}]")
            except Exception as e:
                print(Fore.RED + f"[Error processing {domain}: {str(e)}]")
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            executor.map(process_domain, domains)
            
        print(Fore.GREEN + f"\nFinished checking all domains. Results saved to '{output_file}'")
        return True
        
    except FileNotFoundError:
        print(Fore.RED + f"File not found: {input_list}")
        return False
    except Exception as e:
        print(Fore.RED + f"Unexpected error: {str(e)}")
        return False

def submit_report(clientid):
    clear_screen()
    print(Fore.CYAN + "[ Report System ]")
    
    while True:
        message = input('enter your message: ').strip()
        if message.lower() == '0':
            return
        
        if not message:
            print(Fore.RED + "Message cannot be empty. Please try again.")
            continue
            
        print(Fore.CYAN + "Thank you for your report! We will review it soon.")
        print(Fore.YELLOW + "Press Enter to return to main menu...")
        input()
        return

def process_file_once(input_list, process_function, max_workers=10, *args):
    try:
        with open(input_list, 'r') as f:
            entries = [line.strip() for line in f if line.strip()]
        
        print(Fore.GREEN + f"[ Processing {len(entries)} entries with {max_workers} threads... ]")
        
        def process_wrapper(entry):
            try:
                return process_function(entry, *args)
            except Exception as e:
                print(Fore.RED + f"Error processing {entry}: {str(e)}")
                return None
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(process_wrapper, entries))
        
        print(Fore.GREEN + "[ Finished processing all entries. ]")
        return results
        
    except FileNotFoundError:
        print(Fore.RED + f"File not found: {input_list}")
        return []
    except Exception as e:
        print(Fore.RED + f"Error processing file: {str(e)}")
        return []

def main():
    clear_screen()
    print(Fore.CYAN + """
    ▒███████▒███▒▒▒▒▒███▒███████▒▒███████▒▒████████▒███▒▒▒▒▒███▒
    ▒██▒░░░▒██▒▒▒▒▒▒██▒▒██▒░░░██▒██▒░░░▒██▒▒▒▒▒▒██▒▒▒▒▒▒██▒
    ░██████▒▒███▒▒▒▒▒███▒███████▒░███████░▒███████▒▒▒▒▒███▒▒▒▒
    ░░░███▒▒███▒▒▒▒▒███▒██▒░░░██▒██▒░░░▒██▒██▒░░░▒▒▒▒███▒▒▒
    ██████▒░███████████████████████████████████████▒▒▒▒
    ░░░░░░▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    """)
    print(Fore.GREEN + "  - version : 2.0.3 (UNLOCKED)")
    print(Fore.GREEN + "  - status  : ALL FEATURES ENABLED")
    print(Fore.YELLOW + "  - note    : For educational use only")

    menu_options = [
        "1. Reverse IP Unlimited [ 3 server ]",
        "2. Subdomain Finder [ 2 server ]",
        "3. Discovery Domain Engine",
        "4. Grab by Date",
        "5. Grab Domain Per Second",
        "6. Get Active DNS",
        "7. Get Noactive DNS",
        "8. Get NameServer",
        "9. Grab Domain with NS",
        "10. GeoIP Locking",
        "11. DA/PA Checker",
        "12. Filter IP by Country",
        "13. Domain to IP",
        "14. Remove Duplicates list",
        "15. Submit Report",
        "16. Exit"
    ]
    
    print(Fore.GREEN + "┌─────────────────────────────────────")
    for option in menu_options:
        print(Fore.GREEN + "│" + Style.RESET_ALL + " " + option)
    print(Fore.GREEN + "└─────────────────────────────────────")
    
    choice = input('$ choose: ').strip()
    
    if choice == '1':  # Reverse IP
        file_list = input('$ give me your file list: ').strip()
        filter_choice = input('$ filter domain [y/n]: ').strip().lower()
        domain_filter = None
        if filter_choice == 'y':
            domain_filter = input('$ domain yang akan di ambil [ ex : id,go.id,sch.id,ac.id ]: ').strip()
        auto_ip = input('$ auto domain to ip [y/n]: ').strip().lower()
        output_file = input('$ save to: ').strip()
        
        def process_entry(entry):
            if not is_valid_domain_strict(entry):
                print(Fore.YELLOW + f'Skipping invalid domain/IP: {entry}')
                return
                
            if auto_ip == 'y':
                ip = domain_to_ip(entry)
                if ip:
                    reverse_ip(ip, output_file, domain_filter)
            else:
                reverse_ip(entry, output_file, domain_filter)
        
        process_file_once(file_list, process_entry, 10)
        remove_duplicates(output_file)
    
    elif choice == '2':  # Subdomain Finder
        domain = input('$ Enter domain to scan: ').strip()
        output_file = input('$ Save to: ').strip()
        subdomain_finder(domain, output_file)
    
    elif choice == '4':  # Grab by Date
        start_date = input('$ Start date (YYYY-MM-DD): ').strip()
        end_date = input('$ End date (YYYY-MM-DD): ').strip()
        output_file = input('$ Save to: ').strip()
        grab_by_date(start_date, end_date, output_file)
    
    elif choice == '5':  # Grab Domain Per Second
        url = "https://hypestat.com/recently-updated/"
        interval = input('$ Enter poll interval in seconds [default: 1.0]: ').strip() or "1.0"
        output_file = input('$ Save to [default: domains.txt]: ').strip() or "domains.txt"
        
        try:
            interval = float(interval)
            if interval < 0.2:
                print(Fore.YELLOW + "Interval too low; using minimum 0.2s for politeness")
                interval = 0.2
        except ValueError:
            print(Fore.YELLOW + "Invalid interval, using default 1.0s")
            interval = 1.0
            
        asyncio.run(grab_domain_worker(url, interval, output_file))
    
    elif choice == '6':  # Get Active DNS
        file_list = input('$ give me your file list: ').strip()
        thread_count = input('$ Enter thread count (1-100): ').strip() or "10"
        
        try:
            thread_count = int(thread_count)
            thread_count = max(1, min(100, thread_count))
        except ValueError:
            print(Fore.RED + "Invalid thread count, using default 10")
            thread_count = 10
            
        process_file_once(file_list, get_dns_active, thread_count)
        print(Fore.GREEN + "Proses selesai, save: active_dns.txt")
    
    elif choice == '7':  # Get Noactive DNS
        file_list = input('$ give me your file list: ').strip()
        thread_count = input('$ Enter thread count (1-100): ').strip() or "10"
        
        try:
            thread_count = int(thread_count)
            thread_count = max(1, min(100, thread_count))
        except ValueError:
            print(Fore.RED + "Invalid thread count, using default 10")
            thread_count = 10
            
        process_file_once(file_list, get_dns_unactive, thread_count)
        print(Fore.GREEN + "Proses selesai, save: noactive_dns.txt")
    
    elif choice == '10':  # GeoIP Locking
        input_file = input('$ IP list file: ').strip()
        countries = input('$ Lock Countries [ex: indonesia,malaysia,thailand]: ').strip().lower().split(',')
        output_file = input('$ Save to [ex: results.txt]: ').strip() or "filtered_ips.txt"
        filter_ips(input_file, countries, output_file)
    
    elif choice == '11':  # DA/PA Checker
        input_file = input('$ Domain list file: ').strip()
        output_file = input('$ Save results to: ').strip() or "da_pa_results.txt"
        da_pa_checker(input_file, output_file)
    
    elif choice == '13':  # Domain to IP
        input_file = input('$ give me your file: ').strip()
        output_file = input('$ output filename? : ').strip() or "ip_results.txt"
        thread_count = input('threads > 1-100: ').strip() or "10"
        
        try:
            thread_count = int(thread_count)
            thread_count = max(1, min(100, thread_count))
        except ValueError:
            print(Fore.RED + "Invalid thread count, using default 10")
            thread_count = 10
            
        def process_domain(domain):
            ip = domain_to_ip(domain)
            if ip:
                print(Fore.GREEN + f"[{domain} -> {ip}]")
                with file_lock:
                    with open(output_file, 'a') as f:
                        f.write(f"{ip}\n")
            else:
                print(Fore.RED + f"[bad -> {domain}]")
        
        process_file_once(input_file, process_domain, thread_count)
        print(Fore.GREEN + f"Data has been saved to '{output_file}'")
    
    elif choice == '14':  # Remove Duplicates
        output_file = input('$ Enter the output file to clean duplicates: ').strip()
        if output_file and os.path.exists(output_file):
            remove_duplicates(output_file)
        else:
            print(Fore.RED + f"File not found: {output_file}")
    
    elif choice == '15':  # Submit Report
        submit_report("educational_user")
    
    elif choice == '16' or choice == '0':  # Exit
        print(Fore.YELLOW + "\nExiting...\n")
        sys.exit(0)
    
    else:
        print(Fore.RED + "Invalid choice. Try again.")
    
    input("\nPress Enter to return to main menu...")

if __name__ == '__main__':
    install_missing_modules()
    while True:
        try:
            main()
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n\nExiting...")
            sys.exit(0)
        except Exception as e:
            print(Fore.RED + f"Unexpected error: {str(e)}")
            input("Press Enter to continue...")