# hellFuzzer

A high-performance web directory and file fuzzer designed for penetration testers and security researchers.

## What is hellFuzzer?

hellFuzzer is a Python-based tool that systematically discovers hidden directories and files on web servers. Built from the ground up for speed and real-world pentesting scenarios, it delivers professional-grade performance with an intuitive interface.

v1.1: Intelligent Content Detection - Automatically highlights interesting findings like config files, backups, admin panels, and credentials with visual markers and confidence levels.

v1.2: Enterprise Features - Multiple authentication methods, smart recursion, and professional reporting with Pwndoc JSON export.

New in v1.2.1: Advanced Operations - Multiple targets scanning, anti-rate limiting delays, and enhanced Windows compatibility.

New in v1.3: SPA Mode - Extract routes from JavaScript files, inline scripts, fetch() and XHR calls. Proxy support (HTTP/SOCKS5) and custom status-code filters.

**New in v1.4: Smart Filtering - Auto-filter duplicate responses and error pages with configurable aggressiveness. Word mining extracts hidden endpoints from HTML/JS content. Auto-recursion intelligently discovers directory structures.**

## Why I Built This

While there are great fuzzers out there, I wanted something that:
- **Handles modern web applications** with session-based authentication
- **Provides clear, color-coded results** in dirsearch-like format for quick analysis  
- **Works efficiently with large wordlists** through optimized threading and connection pooling
- **Offers flexible filtering** to focus on relevant findings
- **Intelligently highlights critical findings** to reduce analysis time
- **Integrates smoothly** into my pentesting workflow
- **Supports professional reporting** with JSON export for tools like Pwndoc
- **Scans multiple targets** efficiently without manual intervention
- **Avoids rate limiting** with configurable delays between requests
- **Works seamlessly across platforms** including Windows with proper color support
- **Extracts hidden routes from SPAs** by parsing JavaScript, fetch() and XHR calls
- **Supports HTTP/SOCKS5 proxies** for routing through Burp or other tools
- **Allows custom status-code filters** to define what counts as a "hit"
- **Automatically filters noise** by detecting duplicate responses and common error pages
- **Discovers hidden endpoints** through intelligent word mining from HTML/JS content
- **Automatically explores directory structures** with smart recursion
- **Provides adjustable filtering** to balance between findings and noise reduction

## Key Features

- **Multi-threaded performance** - Scan thousands of paths in seconds, not minutes (600+ req/sec)
- **Smart content detection** - Automatically flags interesting findings (configs, backups, admin panels, credentials)
- **Confidence-based highlighting** - Visual indicators (🔥/⚡) for high/medium confidence findings
- **Session support** - Test authenticated areas with cookies
- **Response filtering** - Ignore status codes (403, 404, etc.) to reduce noise
- **Extension support** - Automatically try multiple file extensions (php, html, txt, asp, jsp, etc.)
- **SSL flexibility** - Work with both HTTP and HTTPS, with optional certificate verification
- **Customizable timeouts** - Adapt to slow networks or applications
- **Real-time progress** - Live progress bar with requests/second metrics
- **Professional output** - Clean, color-coded results with timestamps and formatted sizes
- **Multiple authentication methods** - Basic Auth, JWT, OAuth2, and custom headers
- **Smart recursion** - Automatically discover new paths by following links in HTML responses
- **Professional reporting** - Summary table and Pwndoc JSON export for enterprise integration
- **Multiple targets scanning** - Process multiple URLs from a file in single execution
- **Anti-rate limiting** - Configurable delays between requests to avoid detection
- **Cross-platform compatibility** - Full color support on Windows, Linux, and macOS
- **SPA route extraction** - Discover hidden endpoints in Single Page Applications
- **Proxy support** - Route traffic through HTTP or SOCKS5 proxies (Burp, ZAP, etc.)
- **Custom status-code filters** - Define which codes count as valid hits (e.g. 200,301-302,401)
- **Auto-filter intelligence** - Automatically detect and filter duplicate responses and error pages
- **Configurable filtering** - Adjust filter aggressiveness from low to high (1-5 levels)
- **Word mining** - Extract hidden endpoints and parameters from HTML/JS responses
- **Auto-recursion** - Automatically discover and fuzz inside directories
- **Scope locking** - Restrict scanning to specific domains for focused testing
- **CI-friendly output** - Clean mode for pipelines and automated processes

## Installation

git clone https://github.com/akil3s79/hellFuzzer.git

cd hellfuzzer

pip3 install -r requirements.txt

## Usage Examples
- **Basic Scan: python3 hellFuzzer.py http://target.com common.txt** -
- **High-Speed Scan with Multiple Threads: python3 hellFuzzer.py https://webapp.com wordlist.txt -t 50**
- **Authenticated Scan with Cookies: python3 hellFuzzer.py https://webapp.com admin_paths.txt -c "sessionid=abc123; csrftoken=xyz"**
- **Scan with File Extensions: python3 hellFuzzer.py http://target.com common.txt -x php html txt**
- **High-Speed Scan: python3 hellFuzzer.py http://192.168.1.100 big_wordlist.txt -t 30**
- **SSL validation: python3 hellFuzzer.py https://company.com common.txt --ssl-verify**
- **Ignore Specific Status Codes: python3 hellFuzzer.py http://target.com wordlist.txt --ignore-status 403 404**
- **Slow Network Target: python3 hellFuzzer.py http://slow.server common.txt --timeout 10**
- **Complete Example: python3 hellFuzzer.py https://testapp.com raft-medium-words.txt -t 30 -x php html --ignore-status 403 --timeout 3 --auth-basic admin:pass --depth 1 --format json**
- **Basic Authentication: python3 hellFuzzer.py https://admin.target.com common.txt --auth-basic user:password**
- **Recursive Discovery: python3 hellFuzzer.py http://target.com common.txt --depth 2**
- **JSON Export: python3 hellFuzzer.py http://target.com common.txt --format json**
- **Multiple Targets Scan: python3 hellFuzzer.py -f targets.txt common.txt**
- **Anti-Rate Limiting: python3 hellFuzzer.py http://target.com common.txt --delay 0.1**
- **Multiple Targets with Delay: python3 hellFuzzer.py -f targets.txt common.txt --delay 0.2 -t 20**
- **SPA Route Discovery: python3 hellFuzzer.py https://spa.com common.txt --spa -x js**
- **Proxy through Burp: python3 hellFuzzer.py https://target.com common.txt --proxy http://127.0.0.1:8080**
- **Custom Status Filters: python3 hellFuzzer.py https://target.com common.txt --ok-codes 200,301-302,401 --hide-codes 404,500**
- **Smart Auto-filtering: python3 hellFuzzer.py https://target.com common.txt --auto-filter --filter-aggressiveness 3**
- **Word Mining: python3 hellFuzzer.py https://target.com common.txt --word-mine**
- **Auto-recursion: python3 hellFuzzer.py https://target.com common.txt --auto-recurse**
- **Scope-Locked Scan: python3 hellFuzzer.py https://target.com common.txt --scope-lock target.com**
- **CI Pipeline: python3 hellFuzzer.py https://target.com common.txt --ci --format json**

## Intelligent Content Detection: 
hellFuzzer automatically detects and highlights interesting content:
- **[16:43:16] 200 -  377B  - /images/** 
- **[16:43:17] 200 -  1.2KB - /config.php 🔥 [CONFIG]** 
- **[16:43:18] 301 -  245B  - /admin -&gt; /login.php ⚡ [ADMIN]** 
- **[16:43:19] 200 -  45KB  - /backup.zip 🔥 [BACKUP]** 
- **[16:43:20] 403 -  1.1KB - /.env 🔥 [CONFIG]** 
- **[RECURSION] Depth 1: Added 14 paths from index.php** 
- **[SPA] New JS routes added: 23** 
- **[WORD-MINE] Added 306 words from: /index.php** 
- **[AUTO-RECURSE] Added 14 paths inside directory: /admin** 
- **[AUTO-FILTER] 4733 responses filtered** 

## Markers:
- **🔥 - High confidence (specific patterns like .env, .bak, config.php)** 
- **⚡ - Medium confidence (generic patterns like admin, backup, password)** 

Categories: BACKUP, CONFIG, ADMIN, CREDENTIALS, DATABASE, LOG, GIT

## Output Format:
hellFuzzer uses a clean, professional output format:
- **[16:43:16] 200 - 377B - /images/** 
- **[16:43:17] 301 - 245B - /admin -&gt; /login.php** 
- **[16:43:18] 403 - 1.2KB - /backup/** 

## New: Summary Table
-----------------------------------------------------------
SCAN SUMMARY
-----------------------------------------------------------
Total Requests: 4613
Total Time: 28.69s
Requests/sec: 160.8

Status Codes:
200: 6
301: 6

Interesting Finds:
ADMIN: 2

Word mining: 608 words discovered
Auto-recursion: 142 paths discovered
Auto-filter: 4733 responses filtered
-----------------------------------------------------------

## JSON Export - Pwndoc-compatible format for professional reporting

hellFuzzer generates professional JSON reports compatible with Pwndoc for enterprise penetration testing workflows:

**Features:**
- **Structured Findings** - Each discovered path with status code, size, and metadata
- **Severity Classification** - Automatic categorization based on path patterns and status codes
- **Scan Metadata** - Complete scan information (target, wordlist, threads, timestamp)
- **Pwndoc Integration** - Direct import into Pwndoc for report generation

**Usage:**
- **Basic Export: python3 hellFuzzer.py http://target.com common.txt --format json**
- **With Authentication: python3 hellFuzzer.py https://admin.target.com common.txt --auth-basic user:pass --format json**
- **Multiple Targets: python3 hellFuzzer.py -f targets.txt common.txt --format json**

**Output File:** `hellfuzzer_scan_target_YYYYMMDD_HHMMSS.json`

**JSON Structure:**
```json
{
  "name": "hellFuzzer Scan - http://target.com",
  "scope": ["http://target.com"],
  "createdAt": "2024-01-15T12:30:45",
  "startDate": "2024-01-15T12:25:30",
  "endDate": "2024-01-15T12:30:45",
  "findings": [
    {
      "name": "Discovered /admin",
      "description": "Path /admin returned status 301 - Categorized as ADMIN (MEDIUM)",
      "severity": "medium",
      "references": ["http://target.com/admin"],
      "status": "open"
    }
  ]
}
## Wordlists
hellFuzzer works with any standard wordlist format. Some recommended wordlists:
- **dirb/common.txt** - 
- **dirbuster/directory-list-*.txt** - 
- **SecLists/Discovery/Web-Content/** - 

## Performance Tips:
- **Use 20-50 threads for optimal performance on most targets** -
- **Set timeout to 2-3 seconds for internal networks, 5-8 for external** -
- **Ignore 403/404 status codes to reduce output noise** -
- **Use targeted wordlists rather than huge generic ones** -
- **Enable SSL verification only when testing production environments** -
- **Use recursion (--depth) for comprehensive discovery but expect longer scan times**-
- **Use --delay 0.1-0.5 for targets with rate limiting protection**
- **Combine multiple targets with -f for efficient large-scale scanning**
- **Enable SPA mode (--spa) for modern JavaScript-heavy applications**
- **Route through Burp (--proxy) for manual inspection and logging**
- **Use --auto-filter to reduce noise from duplicate responses and error pages**
- **Adjust --filter-aggressiveness (1-5) to balance between findings and noise reduction**
- **Enable --word-mine to discover hidden endpoints from HTML/JS content**
- **Use --auto-recurse for automatic directory structure discovery**
- **Apply --scope-lock for focused testing on specific domains**
- **Use --ci for clean output in automated pipelines and JSON export**

## Legal Notice
This tool is intended for:
- **Authorized penetration testing** 
- **Security research**
- **Educational purposes**

## Only use hellFuzzer on systems you own or have explicit permission to test.

## Contributing
Found a bug? Have a feature request? Feel free to open an issue or pull request!

## You can buy me a coffe if you want!
<a href="https://www.buymeacoffee.com/akil3s1979" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="27" width="104"></a>

## Puedes invitarme a un café si quieres!
<a href="https://www.buymeacoffee.com/akil3s1979" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="27" width="104"></a>