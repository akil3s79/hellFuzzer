# hellFuzzer 🔥

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

- **⚡ Multi-threaded performance** - Scan thousands of paths in seconds, not minutes (150+ req/sec)
- **🎯 Smart content detection** - Automatically flags interesting findings (configs, backups, admin panels, credentials)
- **🔍 Confidence-based highlighting** - Visual indicators (🔥/⚡) for high/medium confidence findings
- **🔐 Session support** - Test authenticated areas with cookies
- **🎯 Response filtering** - Ignore status codes (403, 404, etc.) to reduce noise
- **📁 Extension support** - Automatically try multiple file extensions (php, html, txt)
- **🔒 SSL flexibility** - Work with both HTTP and HTTPS, with optional certificate verification
- **⏱️ Customizable timeouts** - Adapt to slow networks or applications
- **📊 Real-time progress** - Live progress bar with requests/second metrics
- **🎨 Professional output** - Clean, color-coded results with timestamps and formatted sizes

## Installation

git clone https://github.com/akil3s79/hellFuzzer.git
cd hellfuzzer
pip3 install -r requirements.txt


## Usage Examples
- **Basic Scan: python3 hellFuzzer.py http://target.com common.txt** - 
- **Authenticated Scan with Cookies: python3 hellFuzzer.py https://webapp.com admin_paths.txt -c "sessionid=abc123; csrftoken=xyz"** - 
- **High-Speed Scan: python3 hellFuzzer.py http://192.168.1.100 big_wordlist.txt -t 30** - 
- **SSL validation: python3 hellFuzzer.py https://company.com common.txt --ssl-verify** - 

## Wordlists
hellFuzzer works with any standard wordlist format. Some recommended wordlists:
- **dirb/common.txt** - 
- **dirbuster/directory-list-*.txt** - 
- **SecLists/Discovery/Web-Content/** - 

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
