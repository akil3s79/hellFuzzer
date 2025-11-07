# hellFuzzer 🔥

A high-performance web directory and file fuzzer designed for penetration testers and security researchers.

## What is hellFuzzer?

hellFuzzer is a Python-based tool that systematically discovers hidden directories and files on web servers. It's built for speed, flexibility, and real-world pentesting scenarios.

## Why I Built This

While there are great fuzzers out there, I wanted something that:
- Handles modern web applications with session-based authentication
- Provides clear, color-coded results for quick analysis  
- Works efficiently with large wordlists through smart threading
- Integrates smoothly into my pentesting workflow

## Key Features

- **Multi-threaded performance** - Scan thousands of paths in minutes
- **Session support** - Test authenticated areas with cookies
- **Smart response filtering** - Focus on interesting responses (200, 403, redirects)
- **SSL flexibility** - Work with both HTTP and HTTPS, with optional certificate verification
- **Customizable timeouts** - Adapt to slow networks or applications

## Installation

```bash
git clone https://github.com/rogaramo/hellfuzzer.git
cd hellfuzzer
pip3 install -r requirements.txt

Usage Examples
Basic Scan: python3 hellFuzzer.py http://target.com common.txt
Authenticated Scan with Cookies: python3 hellFuzzer.py https://webapp.com admin_paths.txt -c "sessionid=abc123; csrftoken=xyz"
High-Speed Scan: python3 hellFuzzer.py http://192.168.1.100 big_wordlist.txt -t 30
SSL validation: python3 hellFuzzer.py https://company.com common.txt --ssl-verify

Wordlists
hellFuzzer works with any standard wordlist format. Some recommended wordlists:
dirb/common.txt
dirbuster/directory-list-*.txt
SecLists/Discovery/Web-Content/

Legal Notice
This tool is intended for:
Authorized penetration testing
Security research
Educational purposes

Only use hellFuzzer on systems you own or have explicit permission to test.

Contributing
Found a bug? Have a feature request? Feel free to open an issue or pull request!
