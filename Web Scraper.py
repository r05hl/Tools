import requests
import re
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def art():
  blue_color_code = "\033[34m"  # ANSI escape code for blue text
  reset_color_code = "\033[0m"  # ANSI escape code to reset text color
  ascii_art = """
    ____                           ___      
    / __/__________ ____  __ ______/ _ \__ __
   _\ \/ __/ __/ _ `/ _ \/ // /___/ ___/ // /
  /___/\__/_/  \_,_/ .__/\_, /   /_/   \_, / 
                  /_/   /___/         /___/ 
        """
  print(blue_color_code + ascii_art + reset_color_code)

def scrape_website(url):
    headers = {"User-Agent": "Mozilla/5.0"}

    def safe_get(u, method="GET", **kwargs):
        try:
            if method == "OPTIONS":
                return requests.options(u, headers=headers, timeout=5, **kwargs)
            return requests.get(u, headers=headers, timeout=5, **kwargs)
        except requests.RequestException:
            return None

    response = safe_get(url)
    if not response or response.status_code != 200:
        print(f"Failed to access {url}")
        return

    soup = BeautifulSoup(response.text, "html.parser")

    # Extract JavaScript files
    scripts = [urljoin(url, script["src"]) for script in soup.find_all("script", src=True)]

    # Extract emails
    emails = set(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", response.text))

    # SQL error detection
    sql_errors = ["You have an error in your SQL syntax", "SQLSTATE", "Warning: mysql_fetch"]
    sql_vuln = any(error in response.text for error in sql_errors)

    # robots.txt
    robots_url = urljoin(url, "robots.txt")
    robots_response = safe_get(robots_url)
    sensitive_dirs = []
    if robots_response and robots_response.status_code == 200:
        for line in robots_response.text.splitlines():
            if line.lower().startswith("disallow"):
                sensitive_dirs.append(line)

    # API key detection
    api_keys = []
    for script_url in scripts:
        js_response = safe_get(script_url)
        if js_response and js_response.status_code == 200:
            found_keys = re.findall(r"(AIza[0-9A-Za-z-_]{35}|sk_live_[0-9a-zA-Z]{24}|AKIA[0-9A-Z]{16}|eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+)", js_response.text)
            api_keys.extend(found_keys)

    # .git detection (check for HEAD content)
    git_head_url = urljoin(url, ".git/HEAD")
    git_head_response = safe_get(git_head_url)
    git_exposed = False
    if git_head_response and git_head_response.status_code == 200:
        if "ref:" in git_head_response.text and "refs" in git_head_response.text:
            git_exposed = True

    # .env detection (check for APP_KEY, DB_ etc.)
    env_url = urljoin(url, ".env")
    env_response = safe_get(env_url)
    env_exposed = False
    if env_response and env_response.status_code == 200:
        if any(keyword in env_response.text for keyword in ["APP_KEY", "DB_", "MAIL_", "API_KEY", "SECRET"]):
            env_exposed = True

    # .htaccess detection
    htaccess_url = urljoin(url, ".htaccess")
    htaccess_response = safe_get(htaccess_url)
    htaccess_exposed = False
    if htaccess_response and htaccess_response.status_code == 200:
        if "RewriteEngine" in htaccess_response.text or "Order allow,deny" in htaccess_response.text:
            htaccess_exposed = True

    # CORS Misconfiguration
    cors_misconfig = False
    options_response = safe_get(url, method="OPTIONS")
    if options_response and "Access-Control-Allow-Origin" in options_response.headers:
        if options_response.headers["Access-Control-Allow-Origin"] == "*":
            cors_misconfig = True

    # Admin Pages
    common_admin_pages = ["/admin", "/admin/login", "/wp-admin", "/cpanel", "/login"]
    found_admin_pages = []
    for page in common_admin_pages:
        admin_url = urljoin(url, page)
        admin_response = safe_get(admin_url)
        if admin_response and admin_response.status_code == 200:
            found_admin_pages.append(admin_url)

    # XSS Testing
    xss_payload = "<script>alert('XSS')</script>"
    xss_vuln = False
    test_params = ["q", "search", "id", "query"]
    for param in test_params:
        test_url = f"{url}?{param}={xss_payload}"
        test_response = safe_get(test_url)
        if test_response and xss_payload in test_response.text:
            xss_vuln = True
            break

        # **Subdomain Discovery**
    subdomains = ["www", "api", "admin", "mail", "blog", "shop", "dev", "test"]
    base_domain = urlparse(url).netloc
    found_subdomains = []

    for sub in subdomains:
        sub_url = f"https://{sub}.{base_domain}"
        try:
            sub_response = requests.get(sub_url, headers=headers, timeout=3)
            if sub_response.status_code == 200:
                found_subdomains.append(sub_url)
        except:
            continue
        time.sleep(0.5)  # Rate-limiting to prevent blocking

    # **Sensitive Files Check**
    sensitive_files = [".DS_Store", "backup.zip", "db.sql", "config.bak", "admin.bak", "dump.sql", "site_backup.tar.gz"]
    found_sensitive_files = []
    for file in sensitive_files:
        sensitive_url = urljoin(url, file)
        try:
            sensitive_response = requests.get(sensitive_url, headers=headers, timeout=5)
            if sensitive_response.status_code == 200 and len(sensitive_response.content) > 100:
                found_sensitive_files.append(sensitive_url)
        except:
            continue
    common_admin_pages = ["/admin", "/admin/login", "/wp-admin", "/cpanel", "/login"]
    found_admin_pages = [urljoin(url, page) for page in common_admin_pages if requests.get(urljoin(url, page), headers=headers).status_code == 200]
    
    # **Fuzzing for hidden/juicy pages**
    fuzz_pages = [
        "/backup", "/hidden", "/private", "/old", "/test", "/dev", "/staging",
        "/config", "/db", "/database", "/dump", "/debug", "/server-status",
        "/admin123", "/login-old", "/admin-old", "/dashboard", "/console", "/portal"
    ]
    found_fuzz_pages = []
    
    for fuzz_page in fuzz_pages:
        fuzz_url = urljoin(url, fuzz_page)
        try:
            fuzz_response = requests.get(fuzz_url, headers=headers, timeout=5)
            if fuzz_response.status_code in [200, 403]:  # 200 OK or 403 Forbidden
                found_fuzz_pages.append(fuzz_url)
        except:
            continue
        time.sleep(0.5)  # Sleep to avoid hammering server
    
      # **Results (add this in print section)**

    print(f"\n===== Scan Results for {url} =====")
    print(f"📧 Exposed Emails: {emails}" if emails else "✅ No emails found.")
    print(f"⚠️ SQL Injection Possible!" if sql_vuln else "✅ No SQL errors detected.")
    print(f"🔑 Exposed API Keys: {api_keys}" if api_keys else "✅ No API keys found.")
    print(f"🛑 Open .git directory detected!" if git_exposed else "✅ .git directory is secured.")
    print(f"⚠️ Exposed .env file found!" if env_exposed else "✅ .env file is secured.")
    print(f"⚠️ Exposed .htaccess file found!" if htaccess_exposed else "✅ .htaccess file is secured.")
    print(f"🌍 CORS Misconfiguration detected!" if cors_misconfig else "✅ CORS is properly configured.")
    print(f"🚪 Admin Pages Found: {found_admin_pages}" if found_admin_pages else "✅ No admin pages detected.")
    print(f"🔥 XSS Vulnerability Found!" if xss_vuln else "✅ No XSS detected.")
    print(f"🔎 Subdomains Found: {found_subdomains}" if found_subdomains else "✅ No accessible subdomains detected.")
    print(f"🚪 Admin Pages Found: {found_admin_pages}" if found_admin_pages else "✅ No admin pages detected.")
    print(f"🕵️‍♂️ Fuzzed Hidden Pages Found: {found_fuzz_pages}" if found_fuzz_pages else "✅ No hidden pages found.")
    print(f"📂 Sensitive Files Found: {found_sensitive_files}" if found_sensitive_files else "✅ No sensitive files detected.")

if __name__ == "__main__":
    art()
    target_url = input("Enter url: ").strip()
    scrape_website(target_url)
