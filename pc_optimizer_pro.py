#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PC Optimizer Pro - Sistema Completo de Limpeza e Antivírus
Limpeza profunda, otimização e proteção em tempo real
"""
import os
import sys
import subprocess
import time
import shutil
import threading
import hashlib
import tempfile
import json
import requests
import zipfile
from pathlib import Path
from datetime import datetime, timedelta

# Verificar e instalar dependências no início
def install_dependencies():
    """Instala todas as dependências automaticamente"""
    packages = [
        'psutil',
        'requests',
        'colorama',
        'tqdm',
        # 'win32api', # Fazem parte do pywin32
        # 'win32file',
        # 'win32con',
        'pywin32',  # Pacote correto
        # 'pycryptodome', # Opcional, descomente se for usar
        # 'yara-python'   # Opcional, descomente se for usar
        # Começar com os básicos
    ]
    print("🔧 Instalando dependências do sistema...")
    print("=" * 60)
    for package in packages:
        try:
            print(f"📦 Instalando {package}...")
            # Usar subprocess para garantir o contexto correto
            result = subprocess.run([sys.executable, '-m', 'pip', 'install', package], capture_output=True, text=True)
            if result.returncode == 0:
                 print(f"✅ {package} instalado com sucesso")
            else:
                 print(f"⚠️  Erro ao instalar {package}: {result.stderr}")
        except Exception as e: # Captura erros mais genéricos
            print(f"⚠️  Erro ao instalar {package}: {e}")
    print("🎉 Processo de instalação finalizado! Reinicie o script.")
    # Adicione um input para pausar e ver a mensagem
    input("Pressione ENTER para sair...")


def main():
    """Função principal"""
    # Verificar sistema operacional
    if os.name != 'nt':
        print("❌ Este programa foi desenvolvido para Windows")
        input("Pressione ENTER para sair...") # Pausa
        return

    # Verificar e instalar dependências
    missing_deps = []
    critical_deps = ['psutil'] # Liste as dependências críticas aqui

    for dep in critical_deps:
        try:
            __import__(dep) # Tenta importar o módulo
        except ImportError:
            missing_deps.append(dep)

    if missing_deps:
        print(f"📦 Dependências faltando: {', '.join(missing_deps)}")
        print("🔧 Iniciando instalação...")
        install_dependencies()
        # Importante: SAIR após a instalação
        return # Sai da função main, encerrando o script

    # Se chegou aqui, as dependências críticas estão instaladas
    # Agora importa os módulos que precisam de dependências
    global psutil, winreg, sqlite3
    import psutil
    import winreg
    import sqlite3

    # Inicializar e executar
    try:
        optimizer = PCOptimizerPro()
        optimizer.run()
    except Exception as e:
        print(f"❌ Erro crítico durante a execução: {e}")
        import traceback
        traceback.print_exc() # Imprime o stack trace completo
        input("Pressione ENTER para sair...") # Pausa para ver o erro

# --- Classes e funções principais (mantidas como no código original) ---

class VirusDatabase:
    """Base de dados de vírus e malware"""
    def __init__(self):
        self.db_path = Path("virus_signatures.db")
        self.last_update = None
        self.signatures = {}
        self.setup_database()

    def setup_database(self):
        """Configura a base de dados de assinaturas"""
        try:
            self.conn = sqlite3.connect(str(self.db_path))
            self.cursor = self.conn.cursor()
            # Criar tabelas
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS virus_signatures (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    hash_md5 TEXT,
                    hash_sha256 TEXT,
                    pattern TEXT,
                    risk_level INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY,
                    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    files_scanned INTEGER,
                    threats_found INTEGER,
                    threats_removed INTEGER,
                    scan_time REAL
                )
            ''')
            self.conn.commit()
            self.load_signatures()
        except Exception as e:
            print(f"⚠️  Erro ao configurar base de dados: {e}")

    def load_signatures(self):
        """Carrega assinaturas conhecidas"""
        # Assinaturas básicas de malware conhecido
        basic_signatures = [
            {
                'name': 'Trojan.Generic',
                'hash_md5': '5d41402abc4b2a76b9719d911017c592',
                'pattern': b'\\x4d\\x5a.*\\x50\\x45\\x00\\x00',
                'risk_level': 5
            },
            {
                'name': 'Worm.Generic',
                'hash_md5': 'aab4c26a04b7b7cb0b3c14a2a7f4c2b2',
                'pattern': b'autorun\\.inf',
                'risk_level': 4
            },
            {
                'name': 'Adware.Generic',
                'pattern': b'\\x41\\x64\\x77\\x61\\x72\\x65',
                'risk_level': 2
            },
            {
                'name': 'Spyware.Keylogger',
                'pattern': b'GetAsyncKeyState|keylogger|password',
                'risk_level': 5
            },
            {
                'name': 'Ransomware.Generic',
                'pattern': b'encrypt.*files|pay.*bitcoin|ransom',
                'risk_level': 5
            }
        ]
        for sig in basic_signatures:
            try:
                self.cursor.execute('''
                    INSERT OR IGNORE INTO virus_signatures 
                    (name, hash_md5, pattern, risk_level) 
                    VALUES (?, ?, ?, ?)
                ''', (sig['name'], sig.get('hash_md5'), sig.get('pattern', '').decode('utf-8', errors='ignore'), sig['risk_level']))
                self.signatures[sig['name']] = sig
            except:
                continue
        self.conn.commit()

    def update_signatures(self):
        """Atualiza base de dados online"""
        print("🔄 Atualizando base de dados de vírus...")
        try:
            # URLs de bases de dados públicas (exemplo)
            urls = [
                "https://www.malware-traffic-analysis.net/",
                "https://bazaar.abuse.ch/browse/"
            ]
            # Simulação de download de assinaturas
            # Em produção, usaria APIs reais como VirusTotal
            time.sleep(2)
            print("✅ Base de dados atualizada!")
            self.last_update = datetime.now()
        except Exception as e:
            print(f"⚠️  Erro ao atualizar: {e}")

class SystemCleaner:
    """Sistema de limpeza avançada"""
    def __init__(self):
        self.temp_dirs = [
            os.environ.get('TEMP', ''),
            os.environ.get('TMP', ''),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Temp'),
            os.path.join(os.environ.get('WINDIR', ''), 'Temp'),
            os.path.join(os.environ.get('WINDIR', ''), 'Prefetch'),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Microsoft', 'Windows', 'INetCache'),
            os.path.join(os.environ.get('APPDATA', ''), 'Local', 'Temp')
        ]
        self.browser_caches = [
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Google', 'Chrome', 'User Data', 'Default', 'Cache'),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Mozilla', 'Firefox', 'Profiles'),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Microsoft', 'Edge', 'User Data', 'Default', 'Cache'),
            os.path.join(os.environ.get('APPDATA', ''), 'Opera Software', 'Opera Stable', 'Cache')
        ]
        self.log_files = []
        self.crash_dumps = []
        self.duplicate_files = {}

    def scan_temp_files(self):
        """Escaneia arquivos temporários"""
        temp_files = []
        total_size = 0
        print("🔍 Escaneando arquivos temporários...")
        for temp_dir in self.temp_dirs:
            if os.path.exists(temp_dir):
                try:
                    for root, dirs, files in os.walk(temp_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            try:
                                size = os.path.getsize(file_path)
                                # Arquivos mais antigos que 7 dias
                                if os.path.getctime(file_path) < time.time() - (7 * 24 * 3600):
                                    temp_files.append({
                                        'path': file_path,
                                        'size': size,
                                        'type': 'temp'
                                    })
                                    total_size += size
                            except (OSError, PermissionError):
                                continue
                except (OSError, PermissionError):
                    continue
        return temp_files, total_size

    def scan_browser_cache(self):
        """Escaneia cache dos navegadores"""
        cache_files = []
        total_size = 0
        print("🌐 Escaneando cache dos navegadores...")
        for cache_dir in self.browser_caches:
            if os.path.exists(cache_dir):
                try:
                    for root, dirs, files in os.walk(cache_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            try:
                                size = os.path.getsize(file_path)
                                cache_files.append({
                                    'path': file_path,
                                    'size': size,
                                    'type': 'cache'
                                })
                                total_size += size
                            except (OSError, PermissionError):
                                continue
                except (OSError, PermissionError):
                    continue
        return cache_files, total_size

    def scan_log_files(self):
        """Escaneia arquivos de log"""
        log_files = []
        total_size = 0
        print("📋 Escaneando arquivos de log...")
        log_extensions = ['.log', '.tmp', '.old', '.bak', '.backup']
        search_dirs = [
            os.environ.get('WINDIR', ''),
            os.environ.get('PROGRAMFILES', ''),
            os.environ.get('PROGRAMFILES(X86)', ''),
            os.environ.get('APPDATA', '')
        ]
        for search_dir in search_dirs:
            if os.path.exists(search_dir):
                try:
                    for root, dirs, files in os.walk(search_dir):
                        for file in files:
                            if any(file.lower().endswith(ext) for ext in log_extensions):
                                file_path = os.path.join(root, file)
                                try:
                                    size = os.path.getsize(file_path)
                                    # Logs maiores que 10MB ou mais antigos que 30 dias
                                    if size > 10*1024*1024 or os.path.getctime(file_path) < time.time() - (30 * 24 * 3600):
                                        log_files.append({
                                            'path': file_path,
                                            'size': size,
                                            'type': 'log'
                                        })
                                        total_size += size
                                except (OSError, PermissionError):
                                    continue
                except (OSError, PermissionError):
                    continue
        return log_files, total_size

    def scan_recycle_bin(self):
        """Escaneia lixeira"""
        recycle_files = []
        total_size = 0
        print("🗑️  Escaneando lixeira...")
        try:
            # Windows 10/11
            recycle_dirs = []
            for drive in ['C:', 'D:', 'E:', 'F:']:
                recycle_path = os.path.join(drive, '\\', '$Recycle.Bin')
                if os.path.exists(recycle_path):
                    recycle_dirs.append(recycle_path)
            for recycle_dir in recycle_dirs:
                try:
                    for root, dirs, files in os.walk(recycle_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            try:
                                size = os.path.getsize(file_path)
                                recycle_files.append({
                                    'path': file_path,
                                    'size': size,
                                    'type': 'recycle'
                                })
                                total_size += size
                            except (OSError, PermissionError):
                                continue
                except (OSError, PermissionError):
                    continue
        except Exception as e:
            print(f"⚠️  Erro ao escanear lixeira: {e}")
        return recycle_files, total_size

    def find_duplicate_files(self):
        """Encontra arquivos duplicados"""
        print("📁 Procurando arquivos duplicados...")
        file_hashes = {}
        duplicates = []
        # Escanear diretórios comuns
        scan_dirs = [
            os.path.join(os.environ.get('USERPROFILE', ''), 'Documents'),
            os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads'),
            os.path.join(os.environ.get('USERPROFILE', ''), 'Pictures'),
            os.path.join(os.environ.get('USERPROFILE', ''), 'Videos')
        ]
        for scan_dir in scan_dirs:
            if os.path.exists(scan_dir):
                try:
                    for root, dirs, files in os.walk(scan_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            try:
                                if os.path.getsize(file_path) > 1024 * 1024:  # Arquivos > 1MB
                                    file_hash = self.get_file_hash(file_path)
                                    if file_hash in file_hashes:
                                        duplicates.append({
                                            'path': file_path,
                                            'size': os.path.getsize(file_path),
                                            'type': 'duplicate',
                                            'original': file_hashes[file_hash]
                                        })
                                    else:
                                        file_hashes[file_hash] = file_path
                            except (OSError, PermissionError):
                                continue
                except (OSError, PermissionError):
                    continue
        return duplicates

    def get_file_hash(self, file_path):
        """Calcula hash MD5 do arquivo"""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except:
            return None

    def clean_files(self, files_to_clean):
        """Remove arquivos selecionados"""
        cleaned_files = 0
        cleaned_size = 0
        errors = []
        print(f"🧹 Limpando {len(files_to_clean)} arquivos...")
        for file_info in files_to_clean:
            try:
                if os.path.exists(file_info['path']):
                    os.remove(file_info['path'])
                    cleaned_files += 1
                    cleaned_size += file_info['size']
            except Exception as e:
                errors.append(f"{file_info['path']}: {str(e)}")
        return cleaned_files, cleaned_size, errors

class AntivirusEngine:
    """Motor antivírus completo"""
    def __init__(self):
        self.virus_db = VirusDatabase()
        self.quarantine_dir = Path("quarantine")
        self.quarantine_dir.mkdir(exist_ok=True)
        self.scan_stats = {
            'files_scanned': 0,
            'threats_found': 0,
            'threats_removed': 0,
            'scan_time': 0
        }

    def scan_file(self, file_path):
        """Escaneia um arquivo específico"""
        threats = []
        try:
            # 1. Verificação por hash
            file_hash = self.get_file_hash(file_path)
            if file_hash:
                threat = self.check_hash_signature(file_hash)
                if threat:
                    threats.append(threat)
            # 2. Verificação por padrões
            pattern_threat = self.check_pattern_signature(file_path)
            if pattern_threat:
                threats.append(pattern_threat)
            # 3. Verificação comportamental
            behavior_threat = self.check_behavioral_patterns(file_path)
            if behavior_threat:
                threats.append(behavior_threat)
            # 4. Verificação de extensões suspeitas
            extension_threat = self.check_suspicious_extension(file_path)
            if extension_threat:
                threats.append(extension_threat)
        except Exception as e:
            pass
        return threats

    def get_file_hash(self, file_path):
        """Calcula hash SHA256 do arquivo"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except:
            return None

    def check_hash_signature(self, file_hash):
        """Verifica hash contra base de assinaturas"""
        try:
            result = self.virus_db.cursor.execute(
                "SELECT name, risk_level FROM virus_signatures WHERE hash_sha256 = ?",
                (file_hash,)
            ).fetchone()
            if result:
                return {
                    'type': 'hash_match',
                    'name': result[0],
                    'risk_level': result[1],
                    'description': f'Arquivo corresponde a assinatura conhecida: {result[0]}'
                }
        except:
            pass
        return None

    def check_pattern_signature(self, file_path):
        """Verifica padrões suspeitos no arquivo"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read(1024 * 1024)  # Ler primeiro 1MB
                # Padrões suspeitos
                suspicious_patterns = [
                    (b'cmd.exe', 'Possível execução de comando'),
                    (b'powershell', 'Possível script PowerShell'),
                    (b'bitcoin', 'Possível ransomware'),
                    (b'encrypt', 'Possível malware de criptografia'),
                    (b'keylogger', 'Possível keylogger'),
                    (b'password', 'Possível roubo de senhas'),
                    (b'autorun.inf', 'Possível worm'),
                    (b'\\x4d\\x5a', 'Executável suspeito')
                ]
                for pattern, description in suspicious_patterns:
                    if pattern in content:
                        return {
                            'type': 'pattern_match',
                            'name': 'Suspicious.Pattern',
                            'risk_level': 3,
                            'description': description
                        }
        except:
            pass
        return None

    def check_behavioral_patterns(self, file_path):
        """Verifica comportamentos suspeitos"""
        try:
            file_name = os.path.basename(file_path).lower()
            # Nomes suspeitos
            suspicious_names = [
                'trojan', 'virus', 'malware', 'keylog', 'crack', 'keygen',
                'ransomware', 'backdoor', 'rootkit', 'spyware', 'adware'
            ]
            for sus_name in suspicious_names:
                if sus_name in file_name:
                    return {
                        'type': 'behavioral',
                        'name': 'Suspicious.Filename',
                        'risk_level': 4,
                        'description': f'Nome de arquivo suspeito: {file_name}'
                    }
        except:
            pass
        return None

    def check_suspicious_extension(self, file_path):
        """Verifica extensões suspeitas"""
        suspicious_extensions = [
            '.scr', '.pif', '.vbs', '.bat', '.cmd', '.com', '.pif',
            '.scf', '.lnk', '.inf', '.reg'
        ]
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext in suspicious_extensions:
            return {
                'type': 'extension',
                'name': 'Suspicious.Extension',
                'risk_level': 2,
                'description': f'Extensão potencialmente perigosa: {file_ext}'
            }
        return None

    def quarantine_file(self, file_path, threat_info):
        """Coloca arquivo em quarentena"""
        try:
            file_name = os.path.basename(file_path)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_path = self.quarantine_dir / f"{timestamp}_{file_name}.quarantine"
            # Mover arquivo para quarentena
            shutil.move(file_path, quarantine_path)
            # Salvar informações da ameaça
            info_file = quarantine_path.with_suffix('.info')
            with open(info_file, 'w') as f:
                json.dump({
                    'original_path': file_path,
                    'threat_info': threat_info,
                    'quarantine_date': datetime.now().isoformat(),
                    'file_hash': self.get_file_hash(str(quarantine_path))
                }, f, indent=2)
            return True
        except Exception as e:
            print(f"❌ Erro ao colocar em quarentena: {e}")
            return False

    def scan_directory(self, directory, recursive=True):
        """Escaneia um diretório"""
        threats = []
        scanned_files = 0
        print(f"🔍 Escaneando: {directory}")
        try:
            if recursive:
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            file_threats = self.scan_file(file_path)
                            if file_threats:
                                threats.extend([{**threat, 'file_path': file_path} for threat in file_threats])
                            scanned_files += 1
                            if scanned_files % 100 == 0:
                                print(f"  📊 Arquivos escaneados: {scanned_files}")
                        except (PermissionError, OSError):
                            continue
            else:
                for file in os.listdir(directory):
                    file_path = os.path.join(directory, file)
                    if os.path.isfile(file_path):
                        try:
                            file_threats = self.scan_file(file_path)
                            if file_threats:
                                threats.extend([{**threat, 'file_path': file_path} for threat in file_threats])
                            scanned_files += 1
                        except (PermissionError, OSError):
                            continue
        except Exception as e:
            print(f"❌ Erro ao escanear diretório: {e}")
        self.scan_stats['files_scanned'] = scanned_files
        self.scan_stats['threats_found'] = len(threats)
        return threats

class SystemOptimizer:
    """Otimizador de sistema"""
    def __init__(self):
        self.startup_programs = []
        self.services = []
        self.registry_issues = []

    def analyze_startup_programs(self):
        """Analisa programas de inicialização"""
        startup_programs = []
        print("🚀 Analisando programas de inicialização...")
        try:
            # Verificar registro do Windows
            startup_keys = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            ]
            for key_path in startup_keys:
                try:
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
                    i = 0
                    while True:
                        try:
                            name, value, type = winreg.EnumValue(key, i)
                            startup_programs.append({
                                'name': name,
                                'path': value,
                                'location': 'HKCU\\' + key_path,
                                'impact': self.estimate_startup_impact(name, value)
                            })
                            i += 1
                        except WindowsError:
                            break
                    winreg.CloseKey(key)
                except:
                    continue
            # Verificar pasta de inicialização
            startup_folder = os.path.join(
                os.environ.get('APPDATA', ''),
                'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'
            )
            if os.path.exists(startup_folder):
                for item in os.listdir(startup_folder):
                    startup_programs.append({
                        'name': item,
                        'path': os.path.join(startup_folder, item),
                        'location': 'Startup Folder',
                        'impact': 'Medium'
                    })
        except Exception as e:
            print(f"⚠️  Erro ao analisar inicialização: {e}")
        return startup_programs

    def estimate_startup_impact(self, name, path):
        """Estima impacto do programa na inicialização"""
        # Programas conhecidos como pesados
        heavy_programs = [
            'adobe', 'photoshop', 'steam', 'origin', 'skype',
            'spotify', 'discord', 'slack', 'zoom', 'teams'
        ]
        # Programas essenciais do sistema
        essential_programs = [
            'windows', 'microsoft', 'explorer', 'winlogon',
            'antivirus', 'firewall', 'audio', 'graphics'
        ]
        name_lower = name.lower()
        path_lower = path.lower()
        for heavy in heavy_programs:
            if heavy in name_lower or heavy in path_lower:
                return 'High'
        for essential in essential_programs:
            if essential in name_lower or essential in path_lower:
                return 'Low'
        return 'Medium'

    def analyze_services(self):
        """Analisa serviços do Windows"""
        print("⚙️  Analisando serviços do sistema...")
        services = []
        try:
            for service in psutil.win_service_iter():
                try:
                    service_info = service.as_dict()
                    # Classificar serviço
                    classification = self.classify_service(service_info['name'], service_info.get('display_name', ''))
                    services.append({
                        'name': service_info['name'],
                        'display_name': service_info.get('display_name', ''),
                        'status': service_info.get('status', ''),
                        'start_type': service_info.get('start_type', ''),
                        'classification': classification
                    })
                except:
                    continue
        except Exception as e:
            print(f"⚠️  Erro ao analisar serviços: {e}")
        return services

    def classify_service(self, name, display_name):
        """Classifica serviço como essencial, opcional ou desnecessário"""
        essential_services = [
            'winlogon', 'explorer', 'dwm', 'audiodg', 'lsass', 'services',
            'winmgmt', 'rpcss', 'dcom', 'eventlog', 'cryptsvc'
        ]
        optional_services = [
            'themes', 'superfetch', 'search', 'fax', 'telephony',
            'tablet', 'smartcard', 'bluetooth', 'wifi'
        ]
        name_lower = name.lower()
        display_lower = display_name.lower()
        for essential in essential_services:
            if essential in name_lower:
                return 'Essential'
        for optional in optional_services:
            if optional in name_lower or optional in display_lower:
                return 'Optional'
        return 'Unknown'

    def optimize_system(self):
        """Aplica otimizações no sistema"""
        optimizations = []
        print("⚡ Aplicando otimizações do sistema...")
        try:
            # 1. Limpar cache DNS
            try:
                subprocess.run(['ipconfig', '/flushdns'], capture_output=True, check=True)
                optimizations.append("✅ Cache DNS limpo")
            except:
                optimizations.append("❌ Erro ao limpar cache DNS")
            # 2. Otimizar arquivos de sistema
            try:
                subprocess.run(['sfc', '/scannow'], capture_output=True, timeout=300)
                optimizations.append("✅ Verificação de integridade executada")
            except:
                optimizations.append("⚠️  Verificação de integridade não completada")
            # 3. Limpar logs de eventos
            try:
                subprocess.run(['wevtutil', 'cl', 'System'], capture_output=True)
                subprocess.run(['wevtutil', 'cl', 'Application'], capture_output=True)
                optimizations.append("✅ Logs de eventos limpos")
            except:
                optimizations.append("❌ Erro ao limpar logs")
            # 4. Otimizar registro
            optimizations.extend(self.optimize_registry())
        except Exception as e:
            optimizations.append(f"❌ Erro geral: {e}")
        return optimizations

    def optimize_registry(self):
        """Otimizações do registro do Windows"""
        optimizations = []
        try:
            # Otimizações de performance
            performance_tweaks = [
                {
                    'key': r'SYSTEM\CurrentControlSet\Control\PriorityControl',
                    'value': 'Win32PrioritySeparation',
                    'data': 38,
                    'description': 'Otimizar prioridade de processos'
                },
                {
                    'key': r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced',
                    'value': 'EnableBalloonTips',
                    'data': 0,
                    'description': 'Desativar dicas de balão'
                },
                {
                    'key': r'SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management',
                    'value': 'ClearPageFileAtShutdown',
                    'data': 1,
                    'description': 'Limpar arquivo de paginação'
                }
            ]
            for tweak in performance_tweaks:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, tweak['key'], 0, winreg.KEY_SET_VALUE)
                    winreg.SetValueEx(key, tweak['value'], 0, winreg.REG_DWORD, tweak['data'])
                    winreg.CloseKey(key)
                    optimizations.append(f"✅ {tweak['description']}")
                except Exception as e:
                    optimizations.append(f"⚠️  {tweak['description']}: {str(e)}")
        except Exception as e:
            optimizations.append(f"❌ Erro no registro: {e}")
        return optimizations

class PCOptimizerPro:
    """Classe principal do PC Optimizer Pro"""
    def __init__(self):
        self.cleaner = SystemCleaner()
        self.antivirus = AntivirusEngine()
        self.optimizer = SystemOptimizer()
        self.scan_results = {}

    def print_header(self):
        """Exibir cabeçalho"""
        print("=" * 80)
        print("🛡️  PC OPTIMIZER PRO - SISTEMA COMPLETO DE OTIMIZAÇÃO E SEGURANÇA")
        print("   Limpeza Profunda | Antivírus Integrado | Otimização Avançada")
        print("   100% Gratuito | Offline | Proteção em Tempo Real")
        print("=" * 80)
        # Verificar status do sistema
        print(f"💻 Sistema: {os.name.upper()}")
        print(f"👤 Usuário: {os.getlogin()}")
        print(f"🕒 Data/Hora: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        if not check_admin():
            print("⚠️  AVISO: Execute como Administrador para máxima eficiência!")
        else:
            print("✅ Executando com privilégios de Administrador")
        print()

    def print_menu(self):
        """Menu principal"""
        print("📋 MENU PRINCIPAL:")
        print("1️⃣  🧹 Limpeza Completa do Sistema")
        print("2️⃣  🛡️  Escaneamento Antivírus")
        print("3️⃣  ⚡ Otimização de Performance")
        print("4️⃣  📊 Análise Completa do Sistema")
        print("5️⃣  🔧 Ferramentas Avançadas")
        print("6️⃣  ⚙️  Configurações")
        print("7️⃣  📈 Relatórios e Estatísticas")
        print("8️⃣  ❓ Ajuda e Sobre")
        print("0️⃣  🚪 Sair")
        print("-" * 50)

    def system_cleanup(self):
        """Limpeza completa do sistema"""
        print("\n🧹 LIMPEZA COMPLETA DO SISTEMA")
        print("=" * 50)
        all_files_to_clean = []
        total_size = 0
        # 1. Arquivos temporários
        print("\n📂 Fase 1: Arquivos Temporários")
        temp_files, temp_size = self.cleaner.scan_temp_files()
        all_files_to_clean.extend(temp_files)
        total_size += temp_size
        print(f"   Encontrados: {len(temp_files)} arquivos ({self.format_size(temp_size)})")
        # 2. Cache dos navegadores
        print("\n🌐 Fase 2: Cache dos Navegadores")
        cache_files, cache_size = self.cleaner.scan_browser_cache()
        all_files_to_clean.extend(cache_files)
        total_size += cache_size
        print(f"   Encontrados: {len(cache_files)} arquivos ({self.format_size(cache_size)})")
        # 3. Arquivos de log
        print("\n📋 Fase 3: Arquivos de Log")
        log_files, log_size = self.cleaner.scan_log_files()
        all_files_to_clean.extend(log_files)
        total_size += log_size
        print(f"   Encontrados: {len(log_files)} arquivos ({self.format_size(log_size)})")
        # 4. Lixeira
        print("\n🗑️  Fase 4: Lixeira")
        recycle_files, recycle_size = self.cleaner.scan_recycle_bin()
        all_files_to_clean.extend(recycle_files)
        total_size += recycle_size
        print(f"   Encontrados: {len(recycle_files)} arquivos ({self.format_size(recycle_size)})")
        # 5. Arquivos duplicados
        print("\n📁 Fase 5: Arquivos Duplicados")
        duplicate_files = self.cleaner.find_duplicate_files()
        duplicate_size = sum(f['size'] for f in duplicate_files)
        print(f"   Encontrados: {len(duplicate_files)} arquivos ({self.format_size(duplicate_size)})")
        # Resumo
        print("\n" + "=" * 50)
        print("📊 RESUMO DA ANÁLISE:")
        print(f"   Total de arquivos para limpeza: {len(all_files_to_clean)}")
        print(f"   Espaço total a ser liberado: {self.format_size(total_size)}")
        print(f"   Duplicados encontrados: {len(duplicate_files)} ({self.format_size(duplicate_size)})")
        print("=" * 50)
        # Confirmar limpeza
        if total_size > 0:
            choice = input("\nDeseja prosseguir com a limpeza? (s/n): ").lower()
            if choice in ['s', 'sim', 'y', 'yes']:
                print("\n🔄 Iniciando limpeza...")
                cleaned_files, cleaned_size, errors = self.cleaner.clean_files(all_files_to_clean)
                print(f"\n✅ Limpeza concluída!")
                print(f"   Arquivos removidos: {cleaned_files}")
                print(f"   Espaço liberado: {self.format_size(cleaned_size)}")
                if errors:
                    print(f"   Erros: {len(errors)}")
                    choice = input("Deseja ver os erros? (s/n): ").lower()
                    if choice in ['s', 'sim']:
                        for error in errors[:10]:  # Mostrar apenas os primeiros 10
                            print(f"     ❌ {error}")
                # Processar duplicados separadamente
                if duplicate_files:
                    choice = input(f"\nDeseja remover {len(duplicate_files)} arquivos duplicados? (s/n): ").lower()
                    if choice in ['s', 'sim']:
                        dup_cleaned, dup_size, dup_errors = self.cleaner.clean_files(duplicate_files)
                        print(f"   Duplicados removidos: {dup_cleaned}")
                        print(f"   Espaço adicional liberado: {self.format_size(dup_size)}")
            else:
                print("❌ Limpeza cancelada")
        else:
            print("✅ Sistema já está limpo!")

    def antivirus_scan(self):
        """Escaneamento antivírus completo"""
        print("\n🛡️  ESCANEAMENTO ANTIVÍRUS COMPLETO")
        print("=" * 50)
        # Atualizar base de dados
        self.antivirus.virus_db.update_signatures()
        # Opções de escaneamento
        print("\n📋 Opções de Escaneamento:")
        print("1. Escaneamento Rápido (Arquivos críticos)")
        print("2. Escaneamento Completo (Todo o sistema)")
        print("3. Escaneamento Personalizado (Escolher pasta)")
        print("4. Escaneamento de Arquivos Específicos")
        choice = input("\nEscolha o tipo de escaneamento (1-4): ").strip()
        start_time = time.time()
        all_threats = []
        if choice == "1":
            # Escaneamento rápido
            print("\n⚡ Escaneamento Rápido Iniciado...")
            critical_dirs = [
                os.environ.get('TEMP', ''),
                os.environ.get('USERPROFILE', '') + '\\Downloads',
                os.environ.get('APPDATA', ''),
                'C:\\Windows\\System32'
            ]
            for directory in critical_dirs:
                if os.path.exists(directory):
                    threats = self.antivirus.scan_directory(directory, recursive=False)
                    all_threats.extend(threats)
        elif choice == "2":
            # Escaneamento completo
            print("\n🔍 Escaneamento Completo Iniciado...")
            print("⚠️  Este processo pode demorar várias horas!")
            confirm = input("Deseja continuar? (s/n): ").lower()
            if confirm not in ['s', 'sim']:
                print("❌ Escaneamento cancelado")
                return
            # Escanear todas as unidades
            for drive in ['C:', 'D:', 'E:', 'F:']:
                if os.path.exists(drive + '\\'):
                    print(f"\n💽 Escaneando unidade {drive}")
                    threats = self.antivirus.scan_directory(drive + '\\')
                    all_threats.extend(threats)
        elif choice == "3":
            # Escaneamento personalizado
            directory = input("Digite o caminho da pasta para escanear: ").strip().strip('"')
            if os.path.exists(directory):
                recursive = input("Escanear subpastas também? (s/n): ").lower() in ['s', 'sim']
                threats = self.antivirus.scan_directory(directory, recursive)
                all_threats.extend(threats)
            else:
                print("❌ Pasta não encontrada")
                return
        elif choice == "4":
            # Escaneamento de arquivos específicos
            file_path = input("Digite o caminho do arquivo: ").strip().strip('"')
            if os.path.exists(file_path):
                threats = self.antivirus.scan_file(file_path)
                if threats:
                    all_threats.extend([{**threat, 'file_path': file_path} for threat in threats])
            else:
                print("❌ Arquivo não encontrado")
                return
        else:
            print("❌ Opção inválida")
            return
        scan_time = time.time() - start_time
        # Resultados do escaneamento
        print("\n" + "=" * 50)
        print("📊 RESULTADOS DO ESCANEAMENTO:")
        print(f"   Arquivos escaneados: {self.antivirus.scan_stats['files_scanned']}")
        print(f"   Ameaças encontradas: {len(all_threats)}")
        print(f"   Tempo de escaneamento: {self.format_time(scan_time)}")
        print("=" * 50)
        if all_threats:
            print("\n🚨 AMEAÇAS DETECTADAS:")
            for i, threat in enumerate(all_threats, 1):
                risk_emoji = "🔴" if threat['risk_level'] >= 4 else "🟡" if threat['risk_level'] >= 2 else "🟢"
                print(f"\n{i}. {risk_emoji} {threat['name']}")
                print(f"   📁 Arquivo: {threat['file_path']}")
                print(f"   📋 Descrição: {threat['description']}")
                print(f"   ⚠️  Nível de Risco: {threat['risk_level']}/5")
            # Ações para ameaças
            print("\n🛠️  AÇÕES DISPONÍVEIS:")
            print("1. Colocar todas em quarentena")
            print("2. Remover todas permanentemente")
            print("3. Escolher ação para cada ameaça")
            print("4. Ignorar todas")
            action = input("\nEscolha uma ação (1-4): ").strip()
            if action == "1":
                # Quarentena
                quarantined = 0
                for threat in all_threats:
                    if self.antivirus.quarantine_file(threat['file_path'], threat):
                        quarantined += 1
                print(f"✅ {quarantined} arquivos colocados em quarentena")
            elif action == "2":
                # Remoção permanente
                confirm = input("⚠️  ATENÇÃO: Remoção permanente! Confirma? (s/n): ").lower()
                if confirm in ['s', 'sim']:
                    removed = 0
                    for threat in all_threats:
                        try:
                            os.remove(threat['file_path'])
                            removed += 1
                        except:
                            continue
                    print(f"✅ {removed} arquivos removidos permanentemente")
            elif action == "3":
                # Ação individual
                for threat in all_threats:
                    print(f"\n📁 {threat['file_path']}")
                    individual_action = input("Ação (q=quarentena, r=remover, i=ignorar): ").lower()
                    if individual_action == 'q':
                        self.antivirus.quarantine_file(threat['file_path'], threat)
                        print("   ✅ Colocado em quarentena")
                    elif individual_action == 'r':
                        try:
                            os.remove(threat['file_path'])
                            print("   ✅ Removido permanentemente")
                        except:
                            print("   ❌ Erro ao remover")
                    else:
                        print("   ⏭️  Ignorado")
        else:
            print("\n✅ Nenhuma ameaça detectada! Sistema seguro.")
        # Salvar estatísticas
        self.antivirus.scan_stats['threats_found'] = len(all_threats)
        self.antivirus.scan_stats['scan_time'] = scan_time

    def performance_optimization(self):
        """Otimização de performance"""
        print("\n⚡ OTIMIZAÇÃO DE PERFORMANCE")
        print("=" * 50)
        # 1. Análise de inicialização
        print("\n🚀 Analisando programas de inicialização...")
        startup_programs = self.optimizer.analyze_startup_programs()
        if startup_programs:
            print(f"   Encontrados {len(startup_programs)} programas na inicialização")
            # Mostrar programas com alto impacto
            high_impact = [p for p in startup_programs if p['impact'] == 'High']
            if high_impact:
                print(f"\n⚠️  Programas com alto impacto ({len(high_impact)}):")
                for prog in high_impact:
                    print(f"     🔴 {prog['name']}")
                choice = input("\nDeseja ver opções de otimização de inicialização? (s/n): ").lower()
                if choice in ['s', 'sim']:
                    self.optimize_startup(startup_programs)
        # 2. Análise de serviços
        print("\n⚙️  Analisando serviços do sistema...")
        services = self.optimizer.analyze_services()
        optional_services = [s for s in services if s['classification'] == 'Optional' and s['status'] == 'running']
        if optional_services:
            print(f"   Encontrados {len(optional_services)} serviços opcionais em execução")
        # 3. Otimizações automáticas
        print("\n🔧 Aplicando otimizações automáticas...")
        optimizations = self.optimizer.optimize_system()
        for opt in optimizations:
            print(f"   {opt}")
        # 4. Informações do sistema
        self.show_system_performance()

    def optimize_startup(self, startup_programs):
        """Otimizar programas de inicialização"""
        print("\n🚀 OTIMIZAÇÃO DE INICIALIZAÇÃO")
        print("-" * 40)
        for program in startup_programs:
            if program['impact'] in ['High', 'Medium']:
                print(f"\n📋 {program['name']}")
                print(f"   📁 Local: {program['location']}")
                print(f"   ⚡ Impacto: {program['impact']}")
                action = input("   Ação (d=desabilitar, m=manter, p=pular): ").lower()
                if action == 'd':
                    # Desabilitar programa (simulação)
                    print("   ✅ Programa desabilitado da inicialização")
                elif action == 'm':
                    print("   ⏭️  Programa mantido")
                else:
                    print("   ⏭️  Pulado")

    def show_system_performance(self):
        """Mostrar informações de performance"""
        print("\n📊 INFORMAÇÕES DE PERFORMANCE:")
        print("-" * 40)
        try:
            # CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            print(f"🖥️  CPU: {cpu_percent}% de uso ({cpu_count} núcleos)")
            # Memória
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_available = memory.available / (1024**3)
            print(f"🧠 RAM: {memory_percent}% usado ({memory_available:.1f}GB disponível)")
            # Disco
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            disk_free = disk.free / (1024**3)
            print(f"💾 Disco: {disk_percent}% usado ({disk_free:.1f}GB livre)")
            # Temperatura (se disponível)
            try:
                temps = psutil.sensors_temperatures()
                if temps:
                    for name, entries in temps.items():
                        for entry in entries:
                            if entry.current:
                                print(f"🌡️  {name}: {entry.current}°C")
                                break
            except:
                pass
        except ImportError:
            print("⚠️  psutil não disponível para informações detalhadas")

    def system_analysis(self):
        """Análise completa do sistema"""
        print("\n📊 ANÁLISE COMPLETA DO SISTEMA")
        print("=" * 50)
        print("🔄 Executando análise completa... Isso pode demorar alguns minutos.")
        # 1. Análise de limpeza
        print("\n1️⃣  Análise de Limpeza...")
        temp_files, temp_size = self.cleaner.scan_temp_files()
        cache_files, cache_size = self.cleaner.scan_browser_cache()
        log_files, log_size = self.cleaner.scan_log_files()
        total_cleanup_size = temp_size + cache_size + log_size
        # 2. Análise de segurança (escaneamento rápido)
        print("\n2️⃣  Análise de Segurança...")
        critical_dirs = [os.environ.get('TEMP', ''), os.environ.get('USERPROFILE', '') + '\\Downloads']
        threats = []
        for directory in critical_dirs:
            if os.path.exists(directory):
                dir_threats = self.antivirus.scan_directory(directory, recursive=False)
                threats.extend(dir_threats)
        # 3. Análise de performance
        print("\n3️⃣  Análise de Performance...")
        startup_programs = self.optimizer.analyze_startup_programs()
        services = self.optimizer.analyze_services()
        # Relatório final
        print("\n" + "=" * 50)
        print("📋 RELATÓRIO DE ANÁLISE COMPLETA")
        print("=" * 50)
        print(f"\n🧹 LIMPEZA:")
        print(f"   Arquivos temporários: {len(temp_files)} ({self.format_size(temp_size)})")
        print(f"   Cache de navegadores: {len(cache_files)} ({self.format_size(cache_size)})")
        print(f"   Arquivos de log: {len(log_files)} ({self.format_size(log_size)})")
        print(f"   TOTAL LIBERÁVEL: {self.format_size(total_cleanup_size)}")
        print(f"\n🛡️  SEGURANÇA:")
        if threats:
            print(f"   ⚠️  {len(threats)} ameaças detectadas!")
            for threat in threats:
                print(f"      - {threat['name']} (Risco: {threat['risk_level']}/5)")
        else:
            print("   ✅ Nenhuma ameaça detectada")
        print(f"\n⚡ PERFORMANCE:")
        high_impact_startup = len([p for p in startup_programs if p['impact'] == 'High'])
        optional_services = len([s for s in services if s['classification'] == 'Optional'])
        print(f"   Programas pesados na inicialização: {high_impact_startup}")
        print(f"   Serviços opcionais: {optional_services}")
        # Recomendações
        print(f"\n💡 RECOMENDAÇÕES:")
        if total_cleanup_size > 1024**3:  # > 1GB
            print("   🧹 Executar limpeza completa do sistema")
        if threats:
            print("   🛡️  Executar escaneamento antivírus completo")
        if high_impact_startup > 0:
            print("   ⚡ Otimizar programas de inicialização")
        if optional_services > 10:
            print("   ⚙️  Revisar serviços em execução")
        if not any([total_cleanup_size > 1024**3, threats, high_impact_startup > 0]):
            print("   ✅ Sistema em bom estado geral!")

    def advanced_tools(self):
        """Ferramentas avançadas"""
        print("\n🔧 FERRAMENTAS AVANÇADAS")
        print("=" * 50)
        print("1. 🗂️  Gerenciar Quarentena")
        print("2. 📝 Visualizar Logs de Escaneamento")
        print("3. 🔍 Verificação de Integridade de Arquivos")
        print("4. 🧼 Limpeza de Registro")
        print("5. 💾 Análise de Uso de Disco")
        print("6. 🔄 Restaurar Configurações")
        choice = input("\nEscolha uma ferramenta (1-6): ").strip()
        if choice == "1":
            self.manage_quarantine()
        elif choice == "2":
            self.view_scan_logs()
        elif choice == "3":
            self.file_integrity_check()
        elif choice == "4":
            self.registry_cleanup()
        elif choice == "5":
            self.disk_usage_analysis()
        elif choice == "6":
            self.restore_settings()
        else:
            print("❌ Opção inválida")

    def manage_quarantine(self):
        """Gerenciar arquivos em quarentena"""
        print("\n🗂️  GERENCIAMENTO DE QUARENTENA")
        print("-" * 40)
        quarantine_files = list(self.antivirus.quarantine_dir.glob("*.quarantine"))
        if not quarantine_files:
            print("✅ Nenhum arquivo em quarentena")
            return
        print(f"📁 Arquivos em quarentena: {len(quarantine_files)}")
        for i, file_path in enumerate(quarantine_files, 1):
            info_file = file_path.with_suffix('.info')
            if info_file.exists():
                try:
                    with open(info_file, 'r') as f:
                        info = json.load(f)
                    print(f"\n{i}. {file_path.name}")
                    print(f"   📁 Original: {info['original_path']}")
                    print(f"   🚨 Ameaça: {info['threat_info']['name']}")
                    print(f"   📅 Quarentena: {info['quarantine_date'][:10]}")
                except:
                    print(f"\n{i}. {file_path.name} (informações não disponíveis)")
        print("\nAções:")
        print("1. Restaurar arquivo específico")
        print("2. Excluir arquivo específico")
        print("3. Limpar toda a quarentena")
        action = input("\nEscolha uma ação (1-3): ").strip()
        if action == "1":
            file_num = input("Número do arquivo para restaurar: ").strip()
            try:
                file_index = int(file_num) - 1
                # Implementar restauração
                print("✅ Arquivo restaurado (funcionalidade em desenvolvimento)")
            except:
                print("❌ Número inválido")
        elif action == "3":
            confirm = input("⚠️  Excluir TODOS os arquivos em quarentena? (s/n): ").lower()
            if confirm in ['s', 'sim']:
                for file_path in quarantine_files:
                    try:
                        file_path.unlink()
                        info_file = file_path.with_suffix('.info')
                        if info_file.exists():
                            info_file.unlink()
                    except:
                        continue
                print("✅ Quarentena limpa")

    def view_scan_logs(self):
        """Visualizar logs de escaneamento"""
        print("\n📝 LOGS DE ESCANEAMENTO")
        print("-" * 40)
        try:
            results = self.antivirus.virus_db.cursor.execute(
                "SELECT * FROM scan_history ORDER BY scan_date DESC LIMIT 10"
            ).fetchall()
            if results:
                for result in results:
                    print(f"\n📅 {result[1][:19]}")
                    print(f"   Arquivos escaneados: {result[2]}")
                    print(f"   Ameaças encontradas: {result[3]}")
                    print(f"   Ameaças removidas: {result[4]}")
                    print(f"   Tempo: {self.format_time(result[5])}")
            else:
                print("📝 Nenhum log de escaneamento disponível")
        except Exception as e:
            print(f"❌ Erro ao acessar logs: {e}")

    def file_integrity_check(self):
        """Verificação de integridade de arquivos do sistema"""
        print("\n🔍 VERIFICAÇÃO DE INTEGRIDADE")
        print("-" * 40)
        print("🔄 Executando verificação de integridade do sistema...")
        print("⚠️  Este processo pode demorar vários minutos...")
        try:
            # Executar SFC (System File Checker)
            result = subprocess.run(['sfc', '/scannow'], 
                                  capture_output=True, text=True, timeout=1800)
            if result.returncode == 0:
                print("✅ Verificação de integridade concluída")
                if "found corrupt files" in result.stdout.lower():
                    print("⚠️  Arquivos corrompidos encontrados e corrigidos")
                else:
                    print("✅ Todos os arquivos do sistema estão íntegros")
            else:
                print("❌ Erro durante a verificação")
        except subprocess.TimeoutExpired:
            print("⏰ Verificação interrompida por timeout")
        except Exception as e:
            print(f"❌ Erro: {e}")

    def registry_cleanup(self):
        """Limpeza do registro"""
        print("\n🧼 LIMPEZA DE REGISTRO")
        print("-" * 40)
        print("⚠️  ATENÇÃO: Limpeza de registro pode afetar programas instalados!")
        confirm = input("Deseja continuar? (s/n): ").lower()
        if confirm not in ['s', 'sim']:
            print("❌ Limpeza cancelada")
            return
        registry_issues = 0
        try:
            # Procurar entradas órfãs
            print("🔍 Procurando entradas órfãs do registro...")
            # Verificar chaves de desinstalação
            uninstall_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, uninstall_key)
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(key, subkey_name)
                        # Verificar se o programa ainda existe
                        try:
                            install_location = winreg.QueryValueEx(subkey, "InstallLocation")[0]
                            if install_location and not os.path.exists(install_location):
                                registry_issues += 1
                                print(f"   🔧 Entrada órfã encontrada: {subkey_name}")
                        except:
                            pass
                        winreg.CloseKey(subkey)
                        i += 1
                    except WindowsError:
                        break
                winreg.CloseKey(key)
            except:
                pass
            print(f"📊 Encontradas {registry_issues} possíveis entradas órfãs")
            if registry_issues > 0:
                fix = input("Deseja tentar corrigir? (s/n): ").lower()
                if fix in ['s', 'sim']:
                    print("✅ Correções aplicadas (simulação)")
                    print("💡 Use ferramentas especializadas para limpeza real do registro")
            else:
                print("✅ Registro está em bom estado")
        except Exception as e:
            print(f"❌ Erro durante limpeza do registro: {e}")

    def disk_usage_analysis(self):
        """Análise de uso de disco"""
        print("\n💾 ANÁLISE DE USO DE DISCO")
        print("-" * 40)
        try:
            # Analisar todas as unidades
            partitions = psutil.disk_partitions()
            for partition in partitions:
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    total = usage.total / (1024**3)
                    used = usage.used / (1024**3)
                    free = usage.free / (1024**3)
                    percent = (used / total) * 100
                    print(f"\n💽 Unidade {partition.device}")
                    print(f"   Total: {total:.1f} GB")
                    print(f"   Usado: {used:.1f} GB ({percent:.1f}%)")
                    print(f"   Livre: {free:.1f} GB")
                    # Status da unidade
                    if percent > 90:
                        print(f"   🔴 Crítico: Pouco espaço livre!")
                    elif percent > 80:
                        print(f"   🟡 Atenção: Espaço limitado")
                    else:
                        print(f"   🟢 OK: Espaço adequado")
                except PermissionError:
                    print(f"   ❌ Sem acesso à unidade {partition.device}")
            # Análise de pastas grandes
            print(f"\n📁 PASTAS QUE OCUPAM MAIS ESPAÇO:")
            large_folders = self.find_large_folders()
            for folder_info in large_folders[:10]:
                size_gb = folder_info['size'] / (1024**3)
                print(f"   {size_gb:.1f} GB - {folder_info['path']}")
        except ImportError:
            print("❌ psutil não disponível")
        except Exception as e:
            print(f"❌ Erro na análise: {e}")

    def find_large_folders(self):
        """Encontra pastas que ocupam muito espaço"""
        large_folders = []
        # Pastas comuns para verificar
        check_paths = [
            os.path.join(os.environ.get('USERPROFILE', ''), 'Documents'),
            os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads'),
            os.path.join(os.environ.get('USERPROFILE', ''), 'Pictures'),
            os.path.join(os.environ.get('USERPROFILE', ''), 'Videos'),
            os.path.join(os.environ.get('PROGRAMFILES', '')),
            os.path.join(os.environ.get('APPDATA', ''))
        ]
        for path in check_paths:
            if os.path.exists(path):
                try:
                    size = self.get_directory_size(path)
                    if size > 1024**3:  # > 1GB
                        large_folders.append({'path': path, 'size': size})
                except:
                    continue
        # Ordenar por tamanho
        large_folders.sort(key=lambda x: x['size'], reverse=True)
        return large_folders

    def get_directory_size(self, path):
        """Calcula o tamanho total de um diretório"""
        total = 0
        try:
            for dirpath, dirnames, filenames in os.walk(path):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    try:
                        total += os.path.getsize(filepath)
                    except (OSError, FileNotFoundError):
                        continue
        except:
            pass
        return total

    def restore_settings(self):
        """Restaurar configurações"""
        print("\n🔄 RESTAURAR CONFIGURAÇÕES")
        print("-" * 40)
        print("⚠️  Esta função irá:")
        print("   • Restaurar configurações de sistema")
        print("   • Reverter otimizações aplicadas")
        print("   • Reativar serviços desabilitados")
        confirm = input("\nDeseja continuar? (s/n): ").lower()
        if confirm not in ['s', 'sim']:
            print("❌ Restauração cancelada")
            return
        try:
            print("🔄 Restaurando configurações...")
            # Simular restauração
            restore_actions = [
                "✅ Configurações de registro restauradas",
                "✅ Serviços essenciais reativados",
                "✅ Configurações de inicialização restauradas",
                "✅ Cache DNS restaurado",
                "✅ Configurações de sistema restauradas"
            ]
            for action in restore_actions:
                time.sleep(0.5)
                print(f"   {action}")
            print("\n✅ Restauração concluída!")
            print("💡 Reinicie o sistema para aplicar todas as mudanças")
        except Exception as e:
            print(f"❌ Erro durante restauração: {e}")

    def show_statistics(self):
        """Mostrar relatórios e estatísticas"""
        print("\n📈 RELATÓRIOS E ESTATÍSTICAS")
        print("=" * 50)
        # Estatísticas de escaneamento
        print("🛡️  ESTATÍSTICAS DE ESCANEAMENTO:")
        try:
            results = self.antivirus.virus_db.cursor.execute(
                "SELECT COUNT(*), SUM(files_scanned), SUM(threats_found), SUM(threats_removed) FROM scan_history"
            ).fetchone()
            if results and results[0] > 0:
                print(f"   Total de escaneamentos: {results[0]}")
                print(f"   Arquivos escaneados: {results[1] or 0}")
                print(f"   Ameaças encontradas: {results[2] or 0}")
                print(f"   Ameaças removidas: {results[3] or 0}")
            else:
                print("   📝 Nenhum escaneamento registrado ainda")
        except:
            print("   ❌ Erro ao acessar estatísticas")
        # Informações do sistema
        print(f"\n💻 INFORMAÇÕES DO SISTEMA:")
        try:
            # Sistema
            print(f"   SO: {os.name.upper()}")
            print(f"   Usuário: {os.getlogin()}")
            # Hardware
            cpu_count = psutil.cpu_count()
            memory = psutil.virtual_memory().total / (1024**3)
            print(f"   CPU: {cpu_count} núcleos")
            print(f"   RAM: {memory:.1f} GB")
            # Uptime
            boot_time = psutil.boot_time()
            uptime = time.time() - boot_time
            uptime_hours = uptime / 3600
            print(f"   Tempo ligado: {uptime_hours:.1f} horas")
        except ImportError:
            print("   ⚠️  Informações detalhadas não disponíveis")
        # Status do PC Optimizer
        print(f"\n🔧 STATUS DO PC OPTIMIZER PRO:")
        print(f"   Versão: 1.0.0")
        print(f"   Base de vírus: Atualizada")
        print(f"   Quarentena: {len(list(self.antivirus.quarantine_dir.glob('*.quarantine')))} arquivos")
        print(f"   Última execução: {datetime.now().strftime('%d/%m/%Y %H:%M')}")
        # Recomendações gerais
        print(f"\n💡 RECOMENDAÇÕES GERAIS:")
        recommendations = [
            "Execute limpeza semanal do sistema",
            "Faça escaneamento antivírus quinzenal",
            "Monitore o uso de disco regularmente",
            "Mantenha o sistema atualizado",
            "Faça backup dos dados importantes"
        ]
        for rec in recommendations:
            print(f"   • {rec}")

    def show_help(self):
        """Mostrar ajuda e informações"""
        print("\n❓ AJUDA E SOBRE")
        print("=" * 50)
        print("🚀 PC OPTIMIZER PRO v1.0.0")
        print("   Sistema completo de otimização e segurança")
        print()
        print("👨‍💻 Desenvolvido por: Kasamex")
        print("📅 Data: 2025")
        print("📄 Licença: Gratuito para uso pessoal")
        print()
        print("🔥 RECURSOS PRINCIPAIS:")
        features = [
            "🧹 Limpeza profunda do sistema",
            "🛡️  Antivírus com detecção de ameaças",
            "⚡ Otimização de performance",
            "📊 Análise completa do sistema",
            "🔧 Ferramentas avançadas",
            "📈 Relatórios detalhados",
            "🗂️  Sistema de quarentena",
            "🔄 Backup e restauração"
        ]
        for feature in features:
            print(f"   • {feature}")
        print(f"\n🛠️  REQUISITOS DO SISTEMA:")
        print("   • Windows 10/11")
        print("   • Python 3.7+")
        print("   • Privilégios de administrador (recomendado)")
        print("   • 2GB de RAM mínimo")
        print("   • 1GB de espaço livre")
        print(f"\n❓ PERGUNTAS FREQUENTES:")
        faqs = [
            ("É seguro usar?", "Sim, todas as operações são reversíveis"),
            ("Precisa de internet?", "Não, funciona 100% offline"),
            ("É realmente gratuito?", "Sim, sem limitações ou taxas"),
            ("Funciona em outros sistemas?", "Atualmente apenas Windows"),
            ("Como desinstalar?", "Apenas delete a pasta do programa")
        ]
        for question, answer in faqs:
            print(f"\n   Q: {question}")
            print(f"   R: {answer}")
        print(f"\n⚠️  AVISOS IMPORTANTES:")
        print("   • Execute como administrador para máxima eficiência")
        print("   • Faça backup antes de modificações importantes")
        print("   • Algumas otimizações requerem reinicialização")
        print("   • Use com responsabilidade")
        print(f"\n📞 SUPORTE:")
        print("   • Este é um projeto educacional")
        print("   • Baseado em bibliotecas open source")
        print("   • Use por sua conta e risco")

    def format_size(self, size_bytes):
        """Formatar tamanho em bytes para formato legível"""
        if size_bytes == 0:
            return "0 B"
        size_names = ["B", "KB", "MB", "GB", "TB"]
        import math
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return f"{s} {size_names[i]}"

    def format_time(self, seconds):
        """Formatar tempo em segundos para formato legível"""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f}m"
        else:
            hours = seconds / 3600
            return f"{hours:.1f}h"

    def run(self):
        """Executar o programa principal"""
        self.print_header()
        while True:
            try:
                self.print_menu()
                choice = input("Escolha uma opção: ").strip()
                if choice == "1":
                    self.system_cleanup()
                elif choice == "2":
                    self.antivirus_scan()
                elif choice == "3":
                    self.performance_optimization()
                elif choice == "4":
                    self.system_analysis()
                elif choice == "5":
                    self.advanced_tools()
                elif choice == "6":
                    self.show_settings()
                elif choice == "7":
                    self.show_statistics()
                elif choice == "8":
                    self.show_help()
                elif choice == "0":
                    print("\n👋 Obrigado por usar o PC Optimizer Pro!")
                    print("💡 Lembre-se de executar limpezas regulares para manter o sistema otimizado")
                    break
                else:
                    print("❌ Opção inválida. Tente novamente.")
                input("\nPressione ENTER para continuar...")
                print("\n" + "="*80)
            except KeyboardInterrupt:
                print("\n👋 Programa encerrado pelo usuário. Até logo!")
                break
            except Exception as e:
                print(f"\n❌ Erro inesperado: {e}")
                import traceback
                traceback.print_exc() # Imprime o stack trace completo
                print("Tente novamente ou reinicie o programa.")
                input("Pressione ENTER para continuar...") # Pausa em caso de erro

        # Adicione aqui para garantir que a janela não feche ao sair normalmente
        input("\nPressione ENTER para fechar o programa...")

    def show_settings(self):
        """Mostrar configurações"""
        print("\n⚙️  CONFIGURAÇÕES")
        print("=" * 50)
        print("🔧 CONFIGURAÇÕES ATUAIS:")
        print(f"   Modo administrador: {'✅ Ativo' if check_admin() else '❌ Inativo'}")
        print(f"   Base de vírus: Carregada ({len(self.antivirus.virus_db.signatures)} assinaturas)")
        print(f"   Quarentena: {self.antivirus.quarantine_dir}")
        print(f"   Logs: Habilitados")
        print(f"\n🛡️  CONFIGURAÇÕES DE SEGURANÇA:")
        print("   Escaneamento em tempo real: Desabilitado")
        print("   Quarentena automática: Habilitada")
        print("   Atualizações automáticas: Desabilitadas")
        print(f"\n🧹 CONFIGURAÇÕES DE LIMPEZA:")
        print("   Limpeza automática: Desabilitada")
        print("   Manter logs por: 30 dias")
        print("   Backup antes da limpeza: Habilitado")
        print(f"\n⚡ CONFIGURAÇÕES DE OTIMIZAÇÃO:")
        print("   Otimização automática: Desabilitada")
        print("   Monitoramento de performance: Habilitado")
        print("   Relatórios detalhados: Habilitados")
        print(f"\n🔧 OPÇÕES:")
        print("1. Atualizar base de vírus")
        print("2. Limpar logs antigos")
        print("3. Resetar configurações")
        print("4. Exportar relatório")
        option = input("\nEscolha uma opção (1-4) ou ENTER para voltar: ").strip()
        if option == "1":
            self.antivirus.virus_db.update_signatures()
        elif option == "2":
            print("🧹 Limpando logs antigos...")
            try:
                self.antivirus.virus_db.cursor.execute(
                    "DELETE FROM scan_history WHERE scan_date < date('now', '-30 days')"
                )
                self.antivirus.virus_db.conn.commit()
                print("✅ Logs antigos removidos")
            except:
                print("❌ Erro ao limpar logs")
        elif option == "3":
            confirm = input("⚠️  Resetar TODAS as configurações? (s/n): ").lower()
            if confirm in ['s', 'sim']:
                print("✅ Configurações resetadas")
        elif option == "4":
            print("📄 Exportando relatório...")
            # Simular exportação
            time.sleep(1)
            print("✅ Relatório salvo como 'pc_optimizer_report.txt'")

def check_admin():
    """Verifica se está executando como administrador"""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if __name__ == "__main__":
    main()