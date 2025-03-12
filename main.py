import os
import re
import requests
import threading
import random
from bs4 import BeautifulSoup
from queue import Queue
from fake_useragent import UserAgent

# Fetch fresh proxies from ProxyScrape
def get_proxies():
    proxy_url = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http"
    try:
        response = requests.get(proxy_url, timeout=5)
        proxies = response.text.strip().split("\n")
        return [proxy.strip() for proxy in proxies if proxy.strip()]
    except requests.exceptions.RequestException:
        return []

# Define patterns indicating insecure file uploads
vuln_patterns = [
    r"\$_FILES\['\w+'\]\['name'\]",  # Unrestricted filename usage
    r"move_uploaded_file\(\s*\$_FILES\['\w+'\]\['tmp_name'\]\s*,\s*\$target_path\s*\)",  # Insecure file move
    r"\$_FILES\['\w+'\]\['tmp_name'\]",  # Unchecked tmp_name usage
    r"\$target_path\s*=\s*\"uploads/\"",  # Hardcoded upload directory
    r"basename\(\s*\$_FILES\['\w+'\]\['name'\]\s*\)"  # Direct filename use without sanitization
]

# Thread-safe queue for storing search results
search_queue = Queue()
vulnerable_sites = []
lock = threading.Lock()

# Rotate User-Agents
ua = UserAgent()

def bing_search(query, num_results=10):
    """Use Bing to find websites with potential file upload vulnerabilities."""
    search_url = f"https://www.bing.com/search?q={query}&count={num_results}"
    headers = {"User-Agent": ua.random}

    try:
        response = requests.get(search_url, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        results = []
        for a in soup.select("li.b_algo a"):
            href = a.get("href")
            if href and "http" in href:
                results.append(href)
        
        return results[:num_results]
    
    except requests.exceptions.RequestException as e:
        print(f"Error fetching search results: {e}")
        return []

def scan_website(url, proxy_list):
    """Check if a website has an insecure file upload vulnerability using proxy rotation."""
    try:
        # Pick a random proxy
        proxy = random.choice(proxy_list) if proxy_list else None
        proxies = {"http": f"http://{proxy}", "https": f"https://{proxy}"} if proxy else None
        headers = {"User-Agent": ua.random}

        response = requests.get(url, headers=headers, proxies=proxies, timeout=5)
        
        if response.status_code == 200:
            html_content = response.text
            for pattern in vuln_patterns:
                if re.search(pattern, html_content):
                    with lock:
                        vulnerable_sites.append(url)
                        print(f"[+] Vulnerable: {url}")
                    return
        print(f"[-] Not vulnerable: {url}")
    except requests.exceptions.RequestException:
        print(f"[!] Failed to scan: {url}")

def worker(proxy_list):
    """Thread worker for scanning websites."""
    while not search_queue.empty():
        url = search_queue.get()
        scan_website(url, proxy_list)
        search_queue.task_done()

def find_vulnerable_sites():
    """Search Bing for potential targets and scan them using multi-threading."""
    print("Fetching fresh proxies...\n")
    proxy_list = get_proxies()
    
    print("Searching for potential file upload vulnerabilities...\n")
    search_results = bing_search("inurl:'upload.php' OR inurl:'upload_file.php' OR inurl:'file_upload.php'", num_results=20)
    for result in search_results:
        search_queue.put(result)

    # Create worker threads
    num_threads = 10
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=worker, args=(proxy_list,))
        thread.start()
        threads.append(thread)

    # Wait for threads to complete
    search_queue.join()
    
    # Save results
    if vulnerable_sites:
        with open("vulnerable_sites.txt", "w") as f:
            for site in vulnerable_sites:
                f.write(site + "\n")
        print("\n[!] Vulnerable sites saved to vulnerable_sites.txt")

if __name__ == "__main__":
    find_vulnerable_sites()
