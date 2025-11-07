#!/usr/bin/env python3
"""
hellFuzzer - Directory and file fuzzer for web pentesting  
Author: rogaramo (Rober)
"""

import requests
import sys
import threading
import time
import os
import queue
from datetime import datetime
from argparse import ArgumentParser
from urllib3.exceptions import InsecureRequestWarning
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

# Suprimir warnings de SSL no verificados
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Lock para prints ordenados entre hilos
print_lock = threading.Lock()

# Detectar si es TTY para usar colores
USE_COLORS = sys.stdout.isatty()

class Colors:
    """Manejo de colores con detección de TTY"""
    RED = '\033[91m' if USE_COLORS else ''
    GREEN = '\033[92m' if USE_COLORS else ''
    YELLOW = '\033[93m' if USE_COLORS else ''
    BLUE = '\033[94m' if USE_COLORS else ''
    CYAN = '\033[96m' if USE_COLORS else ''
    MAGENTA = '\033[95m' if USE_COLORS else ''
    END = '\033[0m' if USE_COLORS else ''

def show_banner():
    """Muestra el banner del tool"""
    print(f"""{Colors.MAGENTA}
    ╔══════════════════════════════════════════════════╗
    ║                    hellFuzzer                    ║
    ║               Web Directory Fuzzer               ║
    ║                   HTTP method: GET               ║
    ╚══════════════════════════════════════════════════╝{Colors.END}
    """)

def validate_url(url):
    """
    Valida y normaliza la URL objetivo
    """
    if not url.startswith(('http://', 'https://')):
        print(f"{Colors.RED}[ERROR] La URL debe incluir protocolo (http:// o https://){Colors.END}")
        print(f"[INFO] Ejemplo: http://ejemplo.com o https://192.168.1.100")
        return False
    return True

def load_wordlist(wordlist_path):
    """
    Carga el archivo de wordlist y devuelve lista de palabras
    """
    if not os.path.isfile(wordlist_path):
        print(f"{Colors.RED}[ERROR] No encuentro la wordlist: {wordlist_path}{Colors.END}")
        return None
    
    try:
        with open(wordlist_path, 'r', encoding='latin-1') as file:
            words = [line.strip() for line in file if line.strip()]
            if not words:
                print(f"{Colors.RED}[ERROR] La wordlist está vacía{Colors.END}")
                return None
            return words
    except Exception as e:
        print(f"{Colors.RED}[ERROR] Leyendo wordlist: {e}{Colors.END}")
        return None

def parse_cookies(cookie_string):
    """
    Convierte string de cookies en dict para requests
    Ej: 'session=abc123; user=admin' -> {'session': 'abc123', 'user': 'admin'}
    """
    if not cookie_string:
        return {}
    
    cookies = {}
    for cookie in cookie_string.split(';'):
        cookie = cookie.strip()
        if '=' in cookie:
            key, value = cookie.split('=', 1)
            cookies[key] = value
    return cookies

def generate_all_targets(words, extensions=None):
    """
    Genera TODAS las combinaciones de palabras + extensiones ANTES de empezar
    """
    all_targets = []
    
    for word in words:
        all_targets.append(word)  # La palabra sin extensión
        if extensions:
            for ext in extensions:
                all_targets.append(f"{word}.{ext}")
    
    return all_targets

def format_size(size):
    """Formatea el tamaño en bytes a formato legible"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.0f}{unit}" if unit == 'B' else f"{size:.1f}{unit}"
        size /= 1024.0
    return f"{size:.1f}TB"

def format_time():
    """Devuelve la hora actual en formato [HH:MM:SS]"""
    return datetime.now().strftime("[%H:%M:%S]")

def check_endpoint(target_url, word, session, timeout=2, ignore_codes=None):
    """
    Comprueba un endpoint y muestra resultado si es interesante
    """
    if ignore_codes is None:
        ignore_codes = []
    
    url = f"{target_url.rstrip('/')}/{word}"
    
    try:
        response = session.get(url, timeout=timeout, allow_redirects=False)
        status = response.status_code
        
        # Si está en la lista de ignorados, no mostrar
        if status in ignore_codes:
            return
        
        # Formatear la salida como dirsearch
        timestamp = format_time()
        size = format_size(len(response.content))
        path = f"/{word}"
        
        with print_lock:
            if status == 200:
                print(f"{timestamp} {Colors.GREEN}200{Colors.END} - {size:>6} - {path}")
            elif status == 403:
                print(f"{timestamp} {Colors.YELLOW}403{Colors.END} - {size:>6} - {path}")
            elif status in [301, 302]:
                print(f"{timestamp} {Colors.BLUE}{status}{Colors.END} - {size:>6} - {path} -> {response.headers.get('Location', '')}")
            elif status == 401:
                print(f"{timestamp} {Colors.CYAN}401{Colors.END} - {size:>6} - {path}")
            else:
                print(f"{timestamp} {status} - {size:>6} - {path}")
            
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.TooManyRedirects):
        # Silenciar errores comunes
        pass
    except Exception:
        # Silenciar otros errores
        pass

def create_session(verify_ssl=False, retries=1):
    """
    Crea una sesión HTTP con configuración optimizada para fuzzing
    """
    session = requests.Session()
    
    # Configurar retries
    retry_strategy = Retry(
        total=retries,
        backoff_factor=0.1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=100, pool_maxsize=100)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # Headers por defecto
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
    })
    
    session.verify = verify_ssl
    return session

def worker(target_url, target_queue, cookies, verify_ssl, timeout, ignore_codes):
    """
    Función ejecutada por cada hilo - CON SESIÓN COMPARTIDA OPTIMIZADA
    """
    # Cada hilo tiene su propia sesión para mejor rendimiento
    session = create_session(verify_ssl)
    if cookies:
        session.cookies.update(cookies)
    
    while True:
        try:
            target = target_queue.get_nowait()
            check_endpoint(target_url, target, session, timeout, ignore_codes)
            target_queue.task_done()
        except queue.Empty:
            break

def signal_handler(sig, frame):
    """Maneja Ctrl+C para una salida elegante"""
    print(f"\n{Colors.RED}[!] Interrupción recibida. Cerrando hilos...{Colors.END}")
    sys.exit(0)

def main():
    show_banner()
    
    parser = ArgumentParser(description='hellFuzzer - Web directory fuzzer for pentesting')
    parser.add_argument('url', help='Target URL (e.g., http://example.com or https://target.com)')
    parser.add_argument('wordlist', help='Path to wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=30, 
                       help='Number of threads (default: 30)')
    parser.add_argument('-c', '--cookies', help='Session cookies (e.g., "session=abc123; user=admin")')
    parser.add_argument('--timeout', type=int, default=2, 
                       help='Request timeout in seconds (default: 2)')
    parser.add_argument('--ssl-verify', action='store_true',
                       help='Verify SSL certificates (disabled by default)')
    parser.add_argument('-x', '--extensions', nargs='+', 
                       help='File extensions to try (e.g., php html txt)')
    parser.add_argument('--ignore-status', type=int, nargs='+', default=[],
                       help='Status codes to ignore (e.g., 403 404)')
    
    args = parser.parse_args()
    
    # Validar URL
    if not validate_url(args.url):
        sys.exit(1)
    
    # Configurar manejo de Ctrl+C
    try:
        import signal
        signal.signal(signal.SIGINT, signal_handler)
    except ImportError:
        pass
    
    # Parsear cookies si se proporcionan
    cookies_dict = parse_cookies(args.cookies) if args.cookies else {}
    
    # Cargar wordlist
    print(f"{Colors.CYAN}[*] Loading wordlist: {args.wordlist}{Colors.END}")
    words = load_wordlist(args.wordlist)
    if not words:
        sys.exit(1)
        
    # Generar TODOS los targets
    all_targets = generate_all_targets(words, args.extensions)
    
    # Mostrar configuración
    print(f"{Colors.CYAN}[*] Target: {args.url}{Colors.END}")
    print(f"{Colors.CYAN}[*] Threads: {args.threads}{Colors.END}")
    print(f"{Colors.CYAN}[*] Timeout: {args.timeout}s{Colors.END}")
    print(f"{Colors.CYAN}[*] Wordlist: {len(words)} base words{Colors.END}")
    
    if args.extensions:
        print(f"{Colors.CYAN}[*] Extensions: {', '.join(args.extensions)}{Colors.END}")
    
    if args.ignore_status:
        print(f"{Colors.CYAN}[*] Ignoring status: {', '.join(map(str, args.ignore_status))}{Colors.END}")
    
    print(f"{Colors.CYAN}[*] Total requests: {len(all_targets)}{Colors.END}")
    print(f"{Colors.CYAN}[*] Starting...{Colors.END}")
    print("-" * 60)
    
    start_time = time.time()
    requests_completed = 0
    
    try:
        # Crear cola y añadir TODOS los targets individuales
        target_queue = queue.Queue()
        for target in all_targets:
            target_queue.put(target)
        
        # Crear y lanzar hilos
        threads = []
        for _ in range(args.threads):
            thread = threading.Thread(
                target=worker, 
                args=(args.url, target_queue, cookies_dict, args.ssl_verify, args.timeout, args.ignore_status)
            )
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Mostrar progreso
        initial_size = target_queue.qsize()
        last_update = time.time()
        
        while any(thread.is_alive() for thread in threads):
            remaining = target_queue.qsize()
            completed = initial_size - remaining
            
            # Actualizar progreso cada 0.5 segundos
            if time.time() - last_update > 0.5:
                progress = (completed / initial_size) * 100
                rps = completed / (time.time() - start_time) if (time.time() - start_time) > 0 else 0
                print(f"\r{Colors.CYAN}[*] Progress: {completed}/{initial_size} ({progress:.1f}%) | {rps:.1f} req/sec{Colors.END}", 
                      end="", flush=True)
                last_update = time.time()
            
            time.sleep(0.1)
        
        print()  # Nueva línea después del progress
        
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Scan interrupted by user{Colors.END}")
    
    total_time = time.time() - start_time
    print("-" * 60)
    print(f"{Colors.CYAN}[*] Scan completed in {total_time:.2f} seconds{Colors.END}")
    
    if total_time > 0:
        rps = len(all_targets) / total_time
        print(f"{Colors.CYAN}[*] Average: {rps:.1f} requests/second{Colors.END}")
        
        if rps < 50:
            print(f"{Colors.YELLOW}[!] Performance warning: Low requests per second{Colors.END}")
            print(f"{Colors.YELLOW}[!] Consider reducing timeout or threads if target is rate limiting{Colors.END}")

if __name__ == "__main__":
    main()
