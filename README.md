# hellFuzzer

A high-performance web directory and file fuzzer designed for penetration testers and security researchers.

## What is hellFuzzer?

hellFuzzer is a Python-based tool that systematically discovers hidden directories and files on web servers. Built from the ground up for speed and real-world pentesting scenarios, it delivers professional-grade performance with an intuitive interface.

**New in v1.1: Intelligent Content Detection** - Automatically highlights interesting findings like config files, backups, admin panels, and credentials with visual markers and confidence levels.

## Why I Built This

While there are great fuzzers out there, I wanted something that:
- **Handles modern web applications** with session-based authentication
- **Provides clear, color-coded results** in dirsearch-like format for quick analysis  
- **Works efficiently with large wordlists** through optimized threading and connection pooling
- **Offers flexible filtering** to focus on relevant findings
- **Intelligently highlights critical findings** to reduce analysis time
- **Integrates smoothly** into my pentesting workflow

## Key Features

- **Multi-threaded performance** - Scan thousands of paths in seconds, not minutes (150+ req/sec)
- **Smart content detection** - Automatically flags interesting findings (configs, backups, admin panels, credentials)
- **Confidence-based highlighting** - Visual indicators (🔥/⚡) for high/medium confidence findings
- **Session support** - Test authenticated areas with cookies
- **Response filtering** - Ignore status codes (403, 404, etc.) to reduce noise
- **Extension support** - Automatically try multiple file extensions (php, html, txt, asp, jsp, etc.)
- **SSL flexibility** - Work with both HTTP and HTTPS, with optional certificate verification
- **Customizable timeouts** - Adapt to slow networks or applications
- **Real-time progress** - Live progress bar with requests/second metrics
- **Professional output** - Clean, color-coded results with timestamps and formatted sizes

## Installation

git clone https://github.com/akil3s79/hellFuzzer.git
cd hellfuzzer
pip3 install -r requirements.txt


## Usage Examples
- **Basic Scan: python3 hellFuzzer.py http://target.com common.txt** -
- **High-Speed Scan with Multiple Threads: python3 hellFuzzer.py https://webapp.com wordlist.txt -t 50** -
- **Authenticated Scan with Cookies: python3 hellFuzzer.py https://webapp.com admin_paths.txt -c "sessionid=abc123; csrftoken=xyz"** -
- **Scan with File Extensions: python3 hellFuzzer.py http://target.com common.txt -x php html txt** -
- **High-Speed Scan: python3 hellFuzzer.py http://192.168.1.100 big_wordlist.txt -t 30** - 
- **SSL validation: python3 hellFuzzer.py https://company.com common.txt --ssl-verify** -
- **Ignore Specific Status Codes: python3 hellFuzzer.py http://target.com wordlist.txt --ignore-status 403 404** -
-  **Slow Network Target: python3 hellFuzzer.py http://slow.server common.txt --timeout 10** -
-  **Complete Example: python3 hellFuzzer.py https://testapp.com raft-medium-words.txt -t 30 -x php html --ignore-status 403 --timeout 3**-

## Intelligent Content Detection: 
hellFuzzer automatically detects and highlights interesting content:
- **[16:43:16] 200 -  377B  - /images/** -
- **[16:43:17] 200 -  1.2KB - /config.php 🔥 [CONFIG]** -
- **[16:43:18] 301 -  245B  - /admin -> /login.php ⚡ [ADMIN]** -
- **[16:43:19] 200 -  45KB  - /backup.zip 🔥 [BACKUP]** -
- **[16:43:20] 403 -  1.1KB - /.env 🔥 [CONFIG]** -

## Makers:
- **🔥 - High confidence (specific patterns like .env, .bak, config.php)** -
- **⚡ - Medium confidence (generic patterns like admin, backup, password)** -

Categories: BACKUP, CONFIG, ADMIN, CREDENTIALS, DATABASE, LOG, GIT

## Output Format:
hellFuzzer uses a clean, professional output format:
- **[16:43:16] 200 - 377B - /images/** -
- **[16:43:17] 301 - 245B - /admin -> /login.php** -
- **[16:43:18] 403 - 1.2KB - /backup/** -

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

## Legal Notice
This tool is intended for:
- **Authorized penetration testing** - 
- **Security research** - 
- **Educational purposes** - 

## Only use hellFuzzer on systems you own or have explicit permission to test.

## Contributing
Found a bug? Have a feature request? Feel free to open an issue or pull request!

## Puedes invitarme a un café si quieres!
<a href="https://www.buymeacoffee.com/akil3s1979" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="27" width="104"></a>

## You can buy me a coffe if you want!
<a href="https://www.buymeacoffee.com/akil3s1979" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="27" width="104"></a>
