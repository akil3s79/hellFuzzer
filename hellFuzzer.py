#!/usr/bin/env python3
"""
hellFuzzer - Directory and file fuzzer for web pentesting  
Author: akil3s (Rober)
"""

import requests
import sys
import threading
import time
import os
import queue
import re
import json
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
    ORANGE = '\033[33m' if USE_COLORS else ''
    END = '\033[0m' if USE_COLORS else ''
class AuthManager:
    """Gestor de autenticaciones para hellFuzzer"""
    
    def __init__(self, args):
        self.auth_config = self._parse_auth_args(args)
        self.session = requests.Session()
        self._setup_authentication()
    
    def _parse_auth_args(self, args):
        """Convierte argumentos en configuración de auth"""
        config = {}
        
        if args.auth_basic:
            config['type'] = 'basic'
            config['credentials'] = args.auth_basic
        elif args.auth_jwt:
            config['type'] = 'jwt' 
            config['token'] = args.auth_jwt
        elif args.auth_oauth2:
            config['type'] = 'oauth2'
            config['token'] = args.auth_oauth2
        elif args.auth_header:
            config['type'] = 'custom'
            config['header'] = args.auth_header
            
        return config
    
    def _setup_authentication(self):
        """Configura la sesión con la autenticación seleccionada"""
        if not self.auth_config:
            return
            
        auth_type = self.auth_config.get('type')
        
        if auth_type == 'basic':
            user, pwd = self.auth_config['credentials'].split(':', 1)
            self.session.auth = (user, pwd)
            print(f"{Colors.CYAN}[AUTH] Basic Auth configurada para usuario: {user}{Colors.END}")
            
        elif auth_type in ['jwt', 'oauth2']:
            token = self.auth_config['token']
            self.session.headers.update({'Authorization': f'Bearer {token}'})
            print(f"{Colors.CYAN}[AUTH] {auth_type.upper()} Bearer Token configurado{Colors.END}")
            
        elif auth_type == 'custom':
            header_parts = self.auth_config['header'].split(':', 1)
            if len(header_parts) == 2:
                key, value = header_parts
                self.session.headers.update({key.strip(): value.strip()})
                print(f"{Colors.CYAN}[AUTH] Header personalizado: {key}{Colors.END}")
    
    def get_session(self):
        """Devuelve la sesión autenticada"""
        return self.session
    
    def test_auth(self, test_url, timeout=5):
        """Prueba si la autenticación funciona"""
        try:
            response = self.session.get(test_url, timeout=timeout, verify=False)
            if response.status_code == 401:
                return False, f"{Colors.RED}❌ Autenticación FALLIDA - Sigue devolviendo 401{Colors.END}"
            return True, f"{Colors.GREEN}✅ Autenticación EXITOSA - Sesión establecida{Colors.END}"
        except Exception as e:
            return False, f"{Colors.YELLOW}⚠️ Error probando auth: {e}{Colors.END}"

class RecursionManager:
    """Gestor de recursividad para descubrir contenido oculto"""
    
    def __init__(self, max_depth=0):
        self.max_depth = max_depth
        self.visited_urls = set()
        self.lock = threading.Lock()
    
    def should_process(self, url, current_depth):
        """Decide si procesar una URL basado en profundidad y visitados - MEJORADO"""
        if current_depth > self.max_depth:
            return False
        
        # Normalizar URL para evitar duplicados
        normalized_url = url.lower().split('?')[0]  # Ignorar query parameters
        normalized_url = normalized_url.rstrip('/')
        
        with self.lock:
            if normalized_url in self.visited_urls:
                return False
            self.visited_urls.add(normalized_url)
        
        return True
    
def extract_links_from_html(self, html_content, base_url):
    """Extrae links de HTML para añadir a la cola - MEJORADO"""
    links = set()
    
    # Patrones mejorados para encontrar URLs
    patterns = [
        r'href=[\'"]([^\'"]*?)[\'"]',
        r'src=[\'"]([^\'"]*?)[\'"]',  
        r'action=[\'"]([^\'"]*?)[\'"]',
        r'url\([\'"]?([^\'")]*)[\'"]?\)'
    ]
    
    # Extensiones que NO queremos seguir (archivos estáticos, etc.)
    skip_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js', 
                      '.ico', '.svg', '.woff', '.ttf', '.pdf', '.zip']
    
    for pattern in patterns:
        found_links = re.findall(pattern, html_content, re.IGNORECASE)
        for link in found_links:
            # Saltar enlaces no interesantes
            if any(link.endswith(ext) for ext in skip_extensions):
                continue
            if link.startswith(('javascript:', 'mailto:', 'tel:', '#', '//')):
                continue
                
            # Normalizar URL
            if link.startswith(('http://', 'https://')):
                if base_url in link:
                    links.add(link)
            elif link.startswith('/'):
                links.add(f"{base_url.rstrip('/')}{link}")
            elif not link.startswith(('#', 'javascript:', 'mailto:')):
                links.add(f"{base_url.rstrip('/')}/{link}")
    
    return links
    
def process_discovered_links(self, new_links, target_queue, current_depth):
        """Añade links descubiertos a la cola para procesar"""
        added_count = 0
        for link in new_links:
            # Extraer solo la parte del path de la URL completa
            if link.startswith(('http://', 'https://')):
                # Si es URL completa, extraer el path
                from urllib.parse import urlparse
                parsed = urlparse(link)
                path = parsed.path
            else:
                path = link
            
            # Quitar la barra inicial si existe
            if path.startswith('/'):
                path = path[1:]
            
            if path and self.should_process(path, current_depth + 1):
                target_queue.put(RecursiveLink(path, current_depth + 1))
                added_count += 1
        
        return added_count

class RecursiveLink:
    """Representa un link descubierto durante la recursividad"""
    def __init__(self, path, depth):
        self.path = path
        self.depth = depth
    
    def __str__(self):
        return self.path

# Patrones de contenido interesante
INTERESTING_PATTERNS = {
    'backup': [
        r'backup', r'back_up', r'bak', r'\.bak$', r'\.old$', r'\.save$',
        r'backup\.zip', r'backup\.tar', r'backup\.sql', r'database\.bak'
    ],
    'config': [
        r'config', r'configuration', r'\.env', r'env\.', r'settings', 
        r'configuration', r'config\.php', r'config\.json', r'config\.xml',
        r'web\.config', r'\.htaccess', r'htpasswd'
    ],
    'admin': [
        r'admin', r'administrator', r'dashboard', r'panel', r'control',
        r'manager', r'login', r'log_in', r'signin', r'root', r'superuser'
    ],
    'credentials': [
        r'password', r'credential', r'secret', r'key', r'token', 
        r'passwd', r'pwd', r'id_rsa', r'id_dsa', r'\.pem$',
        r'oauth', r'jwt', r'api[_-]?key'
    ],
    'database': [
        r'database', r'db', r'mysql', r'postgres', r'sqlite',
        r'\.sql$', r'dump', r'schema', r'migration'
    ],
    'log': [
        r'log', r'debug', r'error', r'trace', r'audit',
        r'\.log$', r'logging', r'history'
    ],
    'git': [
        r'\.git', r'gitignore', r'gitkeep', r'gitlab'
    ]
}

def show_banner():
    """Muestra el banner del tool"""
    print(f"""{Colors.MAGENTA}
    ╔══════════════════════════════════════════════════╗
    ║                    hellFuzzer                    ║
    ║               Web Directory Fuzzer               ║
    ║                   HTTP method: GET               ║
    ╚══════════════════════════════════════════════════╝{Colors.END}
    """)

def is_interesting_path(path):
    """
    Detecta si una ruta es interesante basado en patrones
    Returns: (es_interesante, categoria, confianza)
    """
    path_lower = path.lower()
    
    for category, patterns in INTERESTING_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, path_lower, re.IGNORECASE):
                # Calcular confianza basada en lo específico del patrón
                confidence = "HIGH" if pattern.startswith(r'\.') or r'\.' in pattern else "MEDIUM"
                return True, category.upper(), confidence
    
    return False, None, None

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

def check_endpoint(target_url, word, session, timeout=2, ignore_codes=None, 
                   recursion_manager=None, current_depth=0, target_queue=None, 
                   stats=None, pwndoc_findings=None): 
    
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
        
        # Verificar si es interesante
        is_interesting, category, confidence = is_interesting_path(word)
        
        # Formatear la salida como dirsearch
        timestamp = format_time()
        size = format_size(len(response.content))
        path = f"/{word}"
        
        with print_lock:
            # COLORES ESPECIALES PARA CONTENIDO INTERESANTE
            if is_interesting:
                if confidence == "HIGH":
                    color = Colors.ORANGE
                    marker = "🔥"
                else:
                    color = Colors.YELLOW  
                    marker = "⚡"
                
                print(f"{timestamp} {Colors.GREEN if status == 200 else Colors.BLUE}{status}{Colors.END} - {size:>6} - {path} {color}{marker} [{category}]{Colors.END}")
            
            elif status == 200:
                print(f"{timestamp} {Colors.GREEN}200{Colors.END} - {size:>6} - {path}")
            elif status == 403:
                print(f"{timestamp} {Colors.YELLOW}403{Colors.END} - {size:>6} - {path}")
            elif status in [301, 302]:
                print(f"{timestamp} {Colors.BLUE}{status}{Colors.END} - {size:>6} - {path} -> {response.headers.get('Location', '')}")
            elif status == 401:
                print(f"{timestamp} {Colors.CYAN}401{Colors.END} - {size:>6} - {path}")
            else:
                print(f"{timestamp} {status} - {size:>6} - {path}")
        # ACTUALIZAR ESTADÍSTICAS
        if stats:
            stats['total_requests'] += 1
            stats['status_codes'][status] = stats['status_codes'].get(status, 0) + 1
            
            if is_interesting:
                stats['interesting_finds'][category] = stats['interesting_finds'].get(category, 0) + 1
        # PROCESAR RECURSIVIDAD SI ESTÁ ACTIVA
        if recursion_manager and recursion_manager.max_depth > 0:
            if status in [200, 301, 302] and 'text/html' in response.headers.get('content-type', ''):
                # Extraer links del HTML
                new_links = recursion_manager.extract_links_from_html(response.text, target_url)
        
                if new_links and target_queue:
                    # Añadir links a la cola
                    added_count = recursion_manager.process_discovered_links(
                        new_links, target_queue, current_depth
                    )
                    if added_count > 0:
                        print(f"{Colors.CYAN}[RECURSION] Depth {current_depth+1}: Added {added_count} paths from {word}{Colors.END}")

        # NUEVO: GUARDAR PARA JSON PWDOC 
        if pwndoc_findings is not None and status not in ignore_codes:
            
            finding = {
                'url': f"{target_url.rstrip('/')}/{word}",
                'path': f"/{word}",
                'status': status,
                'size': len(response.content),
                'timestamp': datetime.now().isoformat()
            }
            
            # Añadir categoría si es interesante
            if is_interesting:
                finding['category'] = category
                finding['confidence'] = confidence
                finding['marker'] = "🔥" if confidence == "HIGH" else "⚡"
            
            # Añadir a la lista de hallazgos
            pwndoc_findings['findings'].append(finding)

    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.TooManyRedirects):
        # Silenciar errores comunes
        pass
    except Exception:
        # Silenciar otros errores
        pass

def export_pwndoc_json(pwndoc_findings, output_file=None):
    """Exporta resultados en formato Pwndoc JSON"""  
    # Formatear para Pwndoc
    pwndoc_output = {
        'name': f"hellFuzzer Scan - {pwndoc_findings['scan_info']['target']}",
        'scope': [pwndoc_findings['scan_info']['target']],
        'createdAt': datetime.now().isoformat(),
        'startDate': pwndoc_findings['scan_info']['timestamp'],
        'endDate': datetime.now().isoformat(),
        'findings': []
    }
    
    # Convertir hallazgos a formato Pwndoc
    for finding in pwndoc_findings['findings']:
        # Determinar severidad basada en categoría y status
        severity = "info"
        if finding.get('category') in ['ADMIN', 'CREDENTIALS', 'CONFIG']:
            severity = "medium" if finding['status'] in [200, 301, 302] else "info"
        
        pwndoc_finding = {
            'name': f"Discovered {finding['path']}",
            'description': f"Path {finding['path']} returned status {finding['status']}",
            'severity': severity,
            'references': [finding['url']],
            'status': "open"
        }
        
        # Añadir evidencias si es interesante
        if finding.get('category'):
            pwndoc_finding['description'] += f" - Categorized as {finding['category']} ({finding.get('confidence', 'UNKNOWN')})"
        
        pwndoc_output['findings'].append(pwndoc_finding)
    
    # Guardar archivo
    if not output_file:
        output_file = f"hellfuzzer_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    with open(output_file, 'w') as f:
        json.dump(pwndoc_output, f, indent=2)
    
    print(f"{Colors.GREEN}[JSON] Results exported to {output_file}{Colors.END}")
    return output_file
def show_summary(stats, total_time):
    """Muestra tabla resumen de estadísticas"""
    print(f"\n{Colors.MAGENTA}{'='*60}{Colors.END}")
    print(f"{Colors.MAGENTA}                  SCAN SUMMARY{Colors.END}")
    print(f"{Colors.MAGENTA}{'='*60}{Colors.END}")
    
    # Estadísticas básicas
    print(f"{Colors.CYAN}Total Requests:{Colors.END} {stats['total_requests']}")
    print(f"{Colors.CYAN}Total Time:{Colors.END} {total_time:.2f}s")
    print(f"{Colors.CYAN}Requests/sec:{Colors.END} {stats['total_requests']/total_time:.1f}")
    
    # Códigos de estado
    print(f"\n{Colors.CYAN}Status Codes:{Colors.END}")
    for code, count in sorted(stats['status_codes'].items()):
        color = Colors.GREEN if code == 200 else Colors.YELLOW if code in [301, 302] else Colors.BLUE
        print(f"  {color}{code}: {count}{Colors.END}")
    
    # Hallazgos interesantes
    if stats['interesting_finds']:
        print(f"\n{Colors.CYAN}Interesting Finds:{Colors.END}")
        for category, count in sorted(stats['interesting_finds'].items()):
            print(f"  {Colors.ORANGE}{category}: {count}{Colors.END}")
    
    # Recursividad
    if stats.get('recursion_discovered', 0) > 0:
        print(f"\n{Colors.CYAN}Recursion Discovered:{Colors.END} {stats['recursion_discovered']} paths")
    
    print(f"{Colors.MAGENTA}{'='*60}{Colors.END}")

def worker(target_url, target_queue, session, timeout, ignore_codes, recursion_manager=None, stats=None, pwndoc_findings=None):
    """
    Función ejecutada por cada hilo - CON SESIÓN AUTENTICADA Y RECURSIVIDAD
    """
    while True:
        try:
            target = target_queue.get_nowait()
            
            # Determinar profundidad actual si es recursivo
            current_depth = 0
            if recursion_manager and hasattr(target, 'depth'):
                current_depth = target.depth
                target_word = target.path
            else:
                target_word = target
            
            # Pasar target_queue a check_endpoint
            check_endpoint(target_url, target_word, session, timeout, ignore_codes, 
                          recursion_manager, current_depth, target_queue, stats, pwndoc_findings)  # Añadir pwndoc_findings 
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
    parser.add_argument('--show-interesting', action='store_true', default=True,
                       help='Highlight interesting findings (enabled by default)')
    # Contadores para estadísticas
    stats = {
        'total_requests': 0,
        'status_codes': {},
        'interesting_finds': {},
        'recursion_discovered': 0,
        'start_time': time.time()
    }

     # NUEVAS OPCIONES DE AUTENTICACIÓN
    parser.add_argument('--auth-basic', help='Basic Authentication: usuario:password')
    parser.add_argument('--auth-jwt', help='JWT Token for Bearer authentication')
    parser.add_argument('--auth-oauth2', help='OAuth2 Token for Bearer authentication') 
    parser.add_argument('--auth-header', help='Custom auth header (e.g., "X-API-Key: value")')
    
    # NUEVAS OPCIONES FUTURAS (para la siguiente fase)
    parser.add_argument('--depth', type=int, default=0, help='Recursion depth (0=no recursion)')
    parser.add_argument('--format', choices=['default', 'json'], default='default', help='Output format')
    args = parser.parse_args()
    
    # Validar URL
    if not validate_url(args.url):
        sys.exit(1)
    
    # CONFIGURAR AUTENTICACIÓN
    auth_manager = AuthManager(args)
    session = auth_manager.get_session()
    # NUEVO: ESTRUCTURA PARA JSON PWDOC
    pwndoc_findings = {
        'scan_info': {
            'tool': 'hellFuzzer',
            'version': '1.2',
            'target': args.url,
            'timestamp': datetime.now().isoformat(),
            'wordlist': args.wordlist,
            'threads': args.threads
        },
        'findings': []
    }
    # NUEVO: CONFIGURAR RECURSIVIDAD
    recursion_manager = RecursionManager(max_depth=args.depth)
    
    # Probar autenticación si se configuró
    if any([args.auth_basic, args.auth_jwt, args.auth_oauth2, args.auth_header]):
        auth_ok, auth_msg = auth_manager.test_auth(args.url)
        print(auth_msg)
        if not auth_ok and "401" in auth_msg:
            print(f"{Colors.YELLOW}Revisa las credenciales/token{Colors.END}")
    # Probar autenticación si se configuró
    if any([args.auth_basic, args.auth_jwt, args.auth_oauth2, args.auth_header]):
        auth_ok, auth_msg = auth_manager.test_auth(args.url)
        print(auth_msg)
        if not auth_ok and "401" in auth_msg:
            print(f"{Colors.YELLOW}Revisa las credenciales/token{Colors.END}")
            
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
    
    print(f"{Colors.CYAN}[*] Interesting content detection: ENABLED{Colors.END}")
    print(f"{Colors.CYAN}[*] Total requests: {len(all_targets)}{Colors.END}")
    print(f"{Colors.CYAN}[*] Starting...{Colors.END}")
    print("-" * 60)
    
    start_time = time.time()
    
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
                args=(args.url, target_queue, session, args.timeout, args.ignore_status, recursion_manager, stats, pwndoc_findings)  # 🆕 Añadir pwndoc_findings
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
        # NUEVO: MOSTRAR SUMMARY TABLE
    stats['total_requests'] = len(all_targets)  # Usar el total real en lugar del contador
    show_summary(stats, total_time)
        #  NUEVO: EXPORTAR JSON PWDOC SI SE SOLICITA
    if args.format == 'json':
        output_file = export_pwndoc_json(pwndoc_findings)
        print(f"{Colors.GREEN}[*] Pwndoc JSON exported to: {output_file}{Colors.END}")

    if total_time > 0:
        rps = len(all_targets) / total_time
        print(f"{Colors.CYAN}[*] Average: {rps:.1f} requests/second{Colors.END}")
        
        if rps < 50:
            print(f"{Colors.YELLOW}[!] Performance warning: Low requests per second{Colors.END}")
            print(f"{Colors.YELLOW}[!] Consider reducing timeout or threads if target is rate limiting{Colors.END}")

if __name__ == "__main__":
    main()
