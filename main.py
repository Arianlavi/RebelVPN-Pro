import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, ttk
import asyncio
import aiohttp
import json
import base64
import urllib.parse
import urllib.request
import subprocess
import os
import sys
import ctypes
import time
import socket
import logging
import winreg
import hashlib
import re
import random
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ================================
# Configuration & Constants
# ================================
APP_NAME = "RebelVPN Pro"
APP_VERSION = "1.2"
COLOR_BG = "#0F0F1B"
COLOR_SIDEBAR = "#0A0A14"
COLOR_CARD = "#1A1C25"
COLOR_ACCENT = "#5E72E4"
COLOR_CONNECT_BTN = "#2DCE89"
COLOR_DISCONNECT_BTN = "#F5365C"
COLOR_WARNING = "#FB6340"
COLOR_TEXT_MAIN = "#E3E3E3"
COLOR_TEXT_DIM = "#8898AA"

# Proxy ports
SOCKS_PORT = 10808
HTTP_PORT = 10809

# Decryption keys for MahsaNG configs
CORE_KEY = bytes.fromhex("66343330343830303134383235646462")
CORE_IV = bytes.fromhex("58766331774F7278733737496C6A304E")

# URLs and files
CONFIG_FETCH_URL = "https://raw.githubusercontent.com/GFW-knocker/MahsaNG/master/mahsa_EMS_accounts.json"
SAVED_CONFIGS_FILE = Path("saved_configs.json")
XRAY_EXE = Path("xray.exe")
SINGBOX_EXE = Path("sing-box.exe")
CONFIG_JSON = Path("config.json")
SINGBOX_CONFIG_JSON = Path("singbox_config.json")

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("app.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(APP_NAME)

# Setup UI
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# ================================
# Requirements Check
# ================================
def check_requirements():
    """Check all requirements before starting"""
    missing = []
    
    # Check core files
    for exe in [XRAY_EXE, SINGBOX_EXE]:
        if not exe.exists():
            missing.append(f"Core file: {exe.name}")
    
    # Check Python packages
    try:
        import Crypto
    except ImportError:
        missing.append("pycryptodome (pip install pycryptodome)")
    
    try:
        import aiohttp
    except ImportError:
        missing.append("aiohttp (pip install aiohttp)")
    
    try:
        from aiohttp_socks import ProxyConnector
    except ImportError:
        missing.append("aiohttp-socks (pip install aiohttp-socks)")
    
    # psutil is optional for traffic monitoring
    try:
        import psutil
    except ImportError:
        logger.warning("psutil not found, traffic monitoring will use simulated values")
    
    if missing:
        error_msg = "Missing requirements:\n" + "\n".join(f"• {item}" for item in missing)
        messagebox.showerror("❌ Missing Requirements", error_msg)
        sys.exit(1)

# ================================
# Utilities
# ================================
def is_admin() -> bool:
    """Check if running as administrator"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def check_cores() -> None:
    """Check if core executables exist"""
    missing = []
    for exe in [XRAY_EXE, SINGBOX_EXE]:
        if not exe.exists():
            missing.append(exe.name)
    
    if missing:
        messagebox.showerror(
            "❌ Missing Core Files",
            f"Required files not found:\n" + "\n".join(missing)
        )
        sys.exit(1)

def clean_json_syntax(json_str: str) -> str:
    """Fix common JSON syntax errors"""
    try:
        json_str = re.sub(r'//.*', '', json_str)
        json_str = re.sub(r'#.*', '', json_str)
        json_str = re.sub(r',(\s*[\]}])', r'\1', json_str)
        return json_str
    except:
        return json_str

def download_singbox_config(url: str) -> Optional[Dict[str, Any]]:
    """
    Download Sing-Box config from URL with improved Google Drive support
    """
    try:
        logger.info(f"Downloading Sing-Box config from: {url}")
        
        # Handle Google Drive links - convert to direct download
        if "drive.google.com" in url:
            file_id_match = re.search(r'(?:/d/|/file/d/|id=)([^/&?]+)', url)
            if file_id_match:
                file_id = file_id_match.group(1)
                url = f"https://drive.google.com/uc?export=download&id={file_id}"
                logger.info(f"Converted Google Drive URL to direct download: {url}")
            else:
                logger.error("Could not extract file ID from Google Drive URL")
                return None
        
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json,text/plain,*/*',
            }
        )
        
        with urllib.request.urlopen(req, timeout=30) as response:
            data = response.read().decode('utf-8')
        
        # Clean and parse JSON
        cleaned = clean_json_syntax(data)
        try:
            config = json.loads(cleaned)
            logger.info("Successfully downloaded and parsed Sing-Box config")
            return config
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON format after cleaning: {e}")
            # Try to parse as base64 encoded
            try:
                decoded = base64.b64decode(data).decode('utf-8', errors='ignore')
                cleaned_decoded = clean_json_syntax(decoded)
                config = json.loads(cleaned_decoded)
                logger.info("Successfully decoded base64 and parsed Sing-Box config")
                return config
            except:
                logger.error("Failed to parse as JSON or base64")
                return None
        
    except urllib.error.HTTPError as e:
        logger.error(f"HTTP error downloading config: {e.code} - {e.reason}")
        if e.code == 404:
            logger.error("File not found - check if the URL is correct and file exists")
        return None
    except urllib.error.URLError as e:
        logger.error(f"Network error downloading config: {e.reason}")
        return None
    except Exception as e:
        logger.error(f"Failed to download Sing-Box config: {e}", exc_info=True)
        return None

# ================================
# Config Parser & Decryptor
# ================================
class ConfigDecryptor:
    @staticmethod
    def decrypt_payload(data: str) -> Optional[str]:
        """Decrypt MahsaNG config payload"""
        try:
            raw = base64.b64decode(data)
            cipher = AES.new(CORE_KEY, AES.MODE_CBC, CORE_IV)
            decrypted = unpad(cipher.decrypt(raw), AES.block_size)
            result = decrypted.decode('utf-8')
            logger.info(f"Successfully decrypted {len(result)} characters")
            return result
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return None

class ConfigParser:
    @staticmethod
    def safe_decode(s: str) -> str:
        """Safely decode base64 string"""
        if not s:
            return ""
        
        s = s.strip().replace('-', '+').replace('_', '/')
        padding = '=' * (-len(s) % 4)
        try:
            return base64.b64decode(s + padding).decode('utf-8', errors='ignore')
        except:
            return ""

    @staticmethod
    def parse(link: str) -> Optional[Dict[str, Any]]:
        """Parse any type of config link"""
        link = link.strip()
        if not link or link.startswith('#'):
            return None

        # Handle JSON arrays/objects that contain URLs
        if link.startswith('{"'):
            try:
                parsed_json = json.loads(link)
                if 'url' in parsed_json:
                    return ConfigParser.parse(parsed_json['url'])
                return ConfigParser._parse_json(link)
            except:
                pass

        if link.startswith("{") and link.endswith("}"):
            return ConfigParser._parse_json(link)

        if link.startswith("sing-box://import-remote-profile"):
            return ConfigParser._parse_singbox_import(link)

        if link.startswith("mvless://"):
            link = link.replace("mvless://", "vless://", 1)

        try:
            if link.startswith("vmess://"):
                return ConfigParser._parse_vmess(link)
            elif link.startswith("vless://"):
                return ConfigParser._parse_vless(link)
            elif link.startswith("trojan://"):
                return ConfigParser._parse_trojan(link)
            elif link.startswith("ss://"):
                return ConfigParser._parse_ss(link)
            elif link.startswith("sb://"):
                return ConfigParser._parse_sb(link)
            else:
                logger.warning(f"Unsupported link type: {link[:30]}...")
                return None
        except Exception as e:
            logger.error(f"Parse error: {e}")
            return None

    @staticmethod
    def _parse_vmess(link: str) -> Optional[Dict[str, Any]]:
        try:
            decoded = ConfigParser.safe_decode(link[8:])
            if not decoded:
                return None
            
            d = json.loads(decoded)
            return {
                'type': 'vmess',
                'uuid': d.get('id', ''),
                'addr': d.get('add', ''),
                'port': int(d.get('port', 443)),
                'remark': d.get('ps', 'VMess'),
                'net': d.get('net', 'tcp'),
                'host': d.get('host', ''),
                'path': d.get('path', ''),
                'tls': d.get('tls', ''),
                'sni': d.get('sni', ''),
                'fp': d.get('fp', ''),
                'raw': link,
                'delay': "?",
                'valid': True
            }
        except Exception as e:
            logger.error(f"VMess parse error: {e}")
            return None

    @staticmethod
    def _parse_vless(link: str) -> Optional[Dict[str, Any]]:
        try:
            parts = link[8:].split('#', 1)
            remark = urllib.parse.unquote(parts[1]) if len(parts) > 1 else "VLess"
            
            main = parts[0]
            query = {}
            if '?' in main:
                main, query_str = main.split('?', 1)
                query = urllib.parse.parse_qs(query_str)
            
            uuid, server = main.split('@', 1)
            addr, port = server.rsplit(':', 1)
            
            return {
                'type': 'vless',
                'uuid': uuid,
                'addr': addr,
                'port': int(port),
                'remark': remark,
                'net': query.get('type', ['tcp'])[0],
                'tls': query.get('security', [''])[0],
                'sni': query.get('sni', [''])[0],
                'flow': query.get('flow', [''])[0],
                'fp': query.get('fp', [''])[0],
                'pbk': query.get('pbk', [''])[0],
                'sid': query.get('sid', [''])[0],
                'host': query.get('host', [''])[0],
                'path': query.get('path', [''])[0],
                'raw': link,
                'delay': "?",
                'valid': True
            }
        except Exception as e:
            logger.error(f"VLess parse error: {e}")
            return None

    @staticmethod
    def _parse_trojan(link: str) -> Optional[Dict[str, Any]]:
        try:
            parts = link[9:].split('#', 1)
            remark = urllib.parse.unquote(parts[1]) if len(parts) > 1 else "Trojan"
            
            main = parts[0]
            query = {}
            if '?' in main:
                main, query_str = main.split('?', 1)
                query = urllib.parse.parse_qs(query_str)
            
            pwd, server = main.split('@', 1)
            addr, port = server.rsplit(':', 1)
            
            return {
                'type': 'trojan',
                'uuid': pwd,
                'addr': addr,
                'port': int(port),
                'remark': remark,
                'net': query.get('type', ['tcp'])[0],
                'tls': 'tls',
                'sni': query.get('sni', [''])[0],
                'fp': query.get('fp', [''])[0],
                'raw': link,
                'delay': "?",
                'valid': True
            }
        except Exception as e:
            logger.error(f"Trojan parse error: {e}")
            return None

    @staticmethod
    def _parse_ss(link: str) -> Optional[Dict[str, Any]]:
        try:
            parts = link[5:].split('#', 1)
            remark = urllib.parse.unquote(parts[1]) if len(parts) > 1 else "SS"
            
            info = parts[0]
            if '@' in info:
                up, server = info.split('@', 1)
                if ':' in up:
                    method, pwd = up.split(':', 1)
                else:
                    decoded = ConfigParser.safe_decode(up)
                    method, pwd = decoded.split(':', 1)
                
                addr, port = server.rsplit(':', 1)
            else:
                decoded = ConfigParser.safe_decode(info)
                up, server = decoded.split('@', 1)
                method, pwd = up.split(':', 1)
                addr, port = server.rsplit(':', 1)
            
            return {
                'type': 'shadowsocks',
                'uuid': pwd,
                'method': method,
                'addr': addr,
                'port': int(port),
                'remark': remark,
                'net': 'tcp',
                'tls': '',
                'raw': link,
                'delay': "?",
                'valid': True
            }
        except Exception as e:
            logger.error(f"SS parse error: {e}")
            return None

    @staticmethod
    def _parse_sb(link: str) -> Optional[Dict[str, Any]]:
        try:
            parts = link[5:].split('#', 1)
            remark = urllib.parse.unquote(parts[1]) if len(parts) > 1 else "Sing-Box"
            
            cfg = json.loads(ConfigParser.safe_decode(parts[0]))
            return {
                'type': 'singbox',
                'remark': remark,
                'config': cfg,
                'raw': link,
                'delay': "-",
                'valid': True
            }
        except Exception as e:
            logger.error(f"Sing-Box parse error: {e}")
            return None

    @staticmethod
    def _parse_json(raw_json: str) -> Optional[Dict[str, Any]]:
        try:
            cleaned = clean_json_syntax(raw_json)
            js = json.loads(cleaned)
            
            if "outbounds" in js:
                tag = "Imported"
                for out in js["outbounds"]:
                    if out.get("tag") not in [None, "direct", "block", "bypass"]:
                        tag = out.get("tag", tag)
                        break
                
                return {
                    'type': 'singbox',
                    'remark': tag,
                    'config': js,
                    'raw': f"sb_json_{hash(raw_json)}",
                    'delay': "-",
                    'valid': True
                }
            else:
                logger.error("Unknown JSON format - no outbounds found")
                return None
        except Exception as e:
            logger.error(f"JSON parse error: {e}")
            return None

    @staticmethod
    def _parse_singbox_import(link: str) -> Optional[Dict[str, Any]]:
        """Parse sing-box://import-remote-profile links - FIXED for Google Drive"""
        try:
            parsed = urllib.parse.urlparse(link)
            params = urllib.parse.parse_qs(parsed.query)
            
            url = params.get('url', [None])[0]
            if not url:
                logger.error("No URL found in sing-box:// link")
                return None
            
            # Decode URL (handle double encoding)
            url = urllib.parse.unquote(url)
            if '%' in url:
                url = urllib.parse.unquote(url)
            
            # Convert Google Drive URL if present
            if "drive.google.com" in url and "export=download" not in url:
                file_id_match = re.search(r'(?:/d/|/file/d/|id=)([^/&?]+)', url)
                if file_id_match:
                    file_id = file_id_match.group(1)
                    url = f"https://drive.google.com/uc?export=download&id={file_id}"
                    logger.info(f"Converted Google Drive URL in sing-box link: {url}")
            
            return {
                'type': 'singbox_subscription',
                'remark': urllib.parse.unquote(parsed.fragment) if parsed.fragment else "📦 Sing-Box Config",
                'url': url,
                'raw': link,
                'delay': "-",
                'valid': True,
                'needs_resolve': True
            }
        except Exception as e:
            logger.error(f"Sing-Box import parse error: {e}")
            return None

# ================================
# Delay Checker
# ================================
class DelayChecker:
    @staticmethod
    def check(cfg: Dict[str, Any]) -> str:
        """Check latency with improved method"""
        if cfg.get('type') in ['singbox', 'singbox_subscription'] or cfg.get('needs_resolve'):
            return "-"
        
        addr = cfg.get('addr')
        port = cfg.get('port')
        
        if not addr or not port:
            return "Invalid"
        
        if addr in ['127.0.0.1', 'localhost']:
            return "-"
        
        try:
            ip = addr
            try:
                ip = socket.gethostbyname(addr)
            except socket.gaierror:
                return "DNS Error"
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                start = time.time()
                result = s.connect_ex((ip, port))
                
                if result != 0:
                    return "Offline"
            
            latency = int((time.time() - start) * 1000)
            return f"{latency}ms" if latency < 3000 else "High"
            
        except socket.timeout:
            return "Timeout"
        except Exception as e:
            logger.debug(f"Ping failed for {addr}:{port}: {e}")
            return "Error"

# ================================
# Core Managers
# ================================
class XrayManager:
    def __init__(self):
        self.process: Optional[subprocess.Popen] = None

    def generate_config(self, cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Generate Xray config"""
        
        stream = {
            "network": cfg.get('net', 'tcp'),
            "security": cfg.get('tls', 'none')
        }
        
        if cfg.get('tls') == 'reality':
            stream['security'] = 'reality'
            stream['realitySettings'] = {
                "show": False,
                "fingerprint": cfg.get('fp') or "chrome",
                "serverName": cfg.get('sni') or cfg.get('addr'),
                "publicKey": cfg.get('pbk', ''),
                "shortId": cfg.get('sid', ''),
                "spiderX": ""
            }
        elif cfg.get('tls') == 'tls':
            stream['tlsSettings'] = {
                "allowInsecure": False,
                "serverName": cfg.get('sni') or cfg.get('addr'),
                "fingerprint": cfg.get('fp') or "chrome"
            }

        if cfg.get('net') == 'ws':
            stream['wsSettings'] = {
                "path": cfg.get('path', '/'),
                "headers": {"Host": cfg.get('host', cfg.get('addr'))}
            }
        elif cfg.get('net') == 'grpc':
            stream['grpcSettings'] = {
                "serviceName": cfg.get('path', 'grpc'),
                "multiMode": False
            }

        outbound = {"tag": "proxy", "streamSettings": stream}
        
        if cfg['type'] == 'vmess':
            outbound.update({
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": cfg['addr'],
                        "port": cfg['port'],
                        "users": [{
                            "id": cfg['uuid'],
                            "alterId": 0,
                            "security": "auto",
                            "level": 0
                        }]
                    }]
                }
            })
        elif cfg['type'] == 'vless':
            user = {
                "id": cfg['uuid'],
                "encryption": "none",
                "level": 0
            }
            if cfg.get('flow'):
                user['flow'] = cfg['flow']
            
            outbound.update({
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": cfg['addr'],
                        "port": cfg['port'],
                        "users": [user]
                    }]
                }
            })
        elif cfg['type'] == 'trojan':
            outbound.update({
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": cfg['addr'],
                        "port": cfg['port'],
                        "password": cfg['uuid'],
                        "level": 0
                    }]
                }
            })
        elif cfg['type'] == 'shadowsocks':
            outbound.update({
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{
                        "address": cfg['addr'],
                        "port": cfg['port'],
                        "password": cfg['uuid'],
                        "method": cfg['method']
                    }]
                }
            })
        
        dns = {
            "servers": ["8.8.8.8", "1.1.1.1"],
            "queryStrategy": "UseIPv4"
        }

        routing = {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type": "field",
                    "ip": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"],
                    "outboundTag": "direct"
                },
                {
                    "type": "field",
                    "port": "0-65535",
                    "outboundTag": "proxy"
                }
            ]
        }

        return {
            "log": {"loglevel": "warning"},
            "dns": dns,
            "inbounds": [
                {
                    "port": SOCKS_PORT,
                    "protocol": "socks",
                    "settings": {"udp": True},
                    "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
                },
                {
                    "port": HTTP_PORT,
                    "protocol": "http",
                    "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
                }
            ],
            "outbounds": [
                outbound,
                {"protocol": "freedom", "tag": "direct"},
                {"protocol": "blackhole", "tag": "block"}
            ],
            "routing": routing
        }

    def start(self, cfg: Dict[str, Any]) -> Tuple[bool, str]:
        """Start Xray"""
        self.stop()
        
        try:
            xray_config = self.generate_config(cfg)
            with open(CONFIG_JSON, "w", encoding="utf-8") as f:
                json.dump(xray_config, f, indent=2)
            
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
            self.process = subprocess.Popen(
                [str(XRAY_EXE), "run", "-c", str(CONFIG_JSON)],
                startupinfo=si,
                creationflags=subprocess.CREATE_NO_WINDOW,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE
            )
            
            time.sleep(1.5)
            
            if self.process.poll() is not None:
                error_output = self.process.stderr.read().decode(errors='ignore')
                return False, f"Core Error: {error_output[:200]}"
            
            if not self._test_ports():
                self.stop()
                return False, "Ports not responding"
            
            logger.info("Xray started successfully")
            return True, "Connected"
            
        except Exception as e:
            logger.error(f"Xray start error: {e}")
            return False, str(e)

    def stop(self) -> None:
        """Stop Xray"""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
            except:
                pass
            finally:
                self.process = None
        
        try:
            subprocess.run(["taskkill", "/f", "/im", "xray.exe"], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        except:
            pass
        
        if CONFIG_JSON.exists():
            try:
                CONFIG_JSON.unlink()
            except:
                pass

    def _test_ports(self) -> bool:
        """Test proxy ports"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                return s.connect_ex(("127.0.0.1", SOCKS_PORT)) == 0
        except:
            return False

class SingBoxManager:
    def __init__(self):
        self.process: Optional[subprocess.Popen] = None

    def start(self, cfg: Dict[str, Any]) -> Tuple[bool, str]:
        """Start Sing-Box"""
        self.stop()
        
        # Resolve subscription if needed
        if cfg.get('needs_resolve'):
            config = download_singbox_config(cfg['url'])
            if not config:
                return False, "Failed to download Sing-Box config"
            cfg['config'] = config
            cfg['needs_resolve'] = False
        
        try:
            final_cfg = cfg['config'].copy()
            
            # Set inbounds
            final_cfg['inbounds'] = [{
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": SOCKS_PORT,
                "sniff": True
            }]
            
            # Ensure outbounds exist
            if 'outbounds' not in final_cfg:
                return False, "Missing outbounds"
            
            # Add direct/block if not present
            outbound_tags = [out.get('tag') for out in final_cfg['outbounds']]
            if 'direct' not in outbound_tags:
                final_cfg['outbounds'].append({"type": "direct", "tag": "direct"})
            if 'block' not in outbound_tags:
                final_cfg['outbounds'].append({"type": "block", "tag": "block"})
            
            # Write config
            with open(SINGBOX_CONFIG_JSON, "w", encoding="utf-8") as f:
                json.dump(final_cfg, f, indent=2)
            
            # Start Sing-Box
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
            self.process = subprocess.Popen(
                [str(SINGBOX_EXE), "run", "-c", str(SINGBOX_CONFIG_JSON)],
                startupinfo=si,
                creationflags=subprocess.CREATE_NO_WINDOW,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE
            )
            
            time.sleep(1.5)
            
            if self.process.poll() is not None:
                error_output = self.process.stderr.read().decode(errors='ignore')
                return False, f"Sing-Box Error: {error_output[:200]}"
            
            if not self._test_ports():
                self.stop()
                return False, "Ports not responding"
            
            logger.info("Sing-Box started successfully")
            return True, "Connected"
            
        except Exception as e:
            logger.error(f"Sing-Box error: {e}")
            return False, str(e)

    def stop(self) -> None:
        """Stop Sing-Box"""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
            except:
                pass
            finally:
                self.process = None
        
        try:
            subprocess.run(["taskkill", "/f", "/im", "sing-box.exe"], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        except:
            pass
        
        if SINGBOX_CONFIG_JSON.exists():
            try:
                SINGBOX_CONFIG_JSON.unlink()
            except:
                pass

    def _test_ports(self) -> bool:
        """Test proxy ports"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                return s.connect_ex(("127.0.0.1", SOCKS_PORT)) == 0
        except:
            return False

class ProxyManager:
    @staticmethod
    def set_enabled(enable: bool) -> bool:
        """Enable/disable system proxy"""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                0, winreg.KEY_ALL_ACCESS
            )
            
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enable else 0)
            
            if enable:
                proxy_string = f"http=127.0.0.1:{HTTP_PORT};https=127.0.0.1:{HTTP_PORT};socks=127.0.0.1:{SOCKS_PORT}"
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_string)
            
            winreg.CloseKey(key)
            
            # Notify Windows
            ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)
            ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)
            
            logger.info(f"Proxy {'enabled' if enable else 'disabled'}")
            return True
            
        except Exception as e:
            logger.error(f"Proxy error: {e}")
            return False

# ================================
# IP Checker (PROXY AWARE)
# ================================
class IPChecker:
    @staticmethod
    async def check_ip_with_retry(use_proxy: bool = False) -> Dict[str, str]:
        """Check IP with multiple fallback services - proxy aware"""
        services = [
            ("http://ip-api.com/json/", "json"),
            ("https://ifconfig.me/all.json", "json"),
            ("https://icanhazip.com/", "text")
        ]
        
        timeout = aiohttp.ClientTimeout(total=10)
        
        # Use ProxyConnector from aiohttp_socks
        if use_proxy:
            try:
                from aiohttp_socks import ProxyConnector
                connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{SOCKS_PORT}")
            except ImportError:
                logger.error("aiohttp-socks not found, cannot use proxy for IP check")
                connector = aiohttp.TCPConnector()
        else:
            connector = aiohttp.TCPConnector()
        
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            for url, resp_type in services:
                try:
                    async with session.get(url, headers={'User-Agent': 'Mozilla/5.0'}) as resp:
                        if resp.status != 200:
                            continue
                            
                        if resp_type == "text":
                            ip = (await resp.text()).strip()
                            return {'full': f"🆔 IP: {ip}\n📍 Service: {url.split('/')[2]}"}
                        
                        data = await resp.json()
                        
                        if "ip-api.com" in url and data.get('status') == 'success':
                            return {
                                'full': f"🌍 {data.get('countryCode', 'Unknown')} - {data.get('isp', 'Unknown')}\n🆔 {data.get('query', 'Unknown')}"
                            }
                        elif "ifconfig.me" in url:
                            return {
                                'full': f"🌍 {data.get('country', 'Unknown')}\n🆔 {data.get('ip_addr', 'Unknown')}"
                            }
                        elif 'query' in data or 'ip_addr' in data:
                            ip = data.get('query') or data.get('ip_addr')
                            return {'full': f"🆔 IP: {ip}\n📍 Service: {url.split('/')[2]}"}
                            
                except asyncio.TimeoutError:
                    logger.warning(f"Timeout checking IP via {url}")
                except Exception as e:
                    logger.debug(f"IP check via {url} failed: {e}")
                    if url == services[-1][0]:  # Last service
                        return {'full': '❌ Network error'}
        
        return {'full': '❌ Network error'}

# ================================
# Main Application
# ================================
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Window setup
        self.title(f"{APP_NAME} {APP_VERSION}")
        self.geometry("1100x750")
        self.configure(fg_color=COLOR_BG)
        self.resizable(False, False)
        
        # Load icon if exists
        try:
            if Path("icon.ico").exists():
                self.iconbitmap("icon.ico")
        except:
            pass
        
        # Core managers
        self.xray = XrayManager()
        self.singbox = SingBoxManager()
        
        # State
        self.configs: List[Dict[str, Any]] = []
        self.widgets: Dict[str, Dict[str, Any]] = {}
        self.saved_configs = self.load_saved_configs()
        self.selected_config: Optional[Dict[str, Any]] = None
        self.is_connected = False
        self.monitor_running = False
        self.fetch_thread = None
        
        # Build UI
        self.build_ui()
        self.show("dashboard")
        
        # Initialize
        self.after(500, self.fetch_configs)
        self.after(1000, lambda: self.update_ip_info(use_proxy=False))
        self.after(2000, self.start_traffic_monitor)
        
        # Load settings
        self.load_settings()
        
        # Protocol
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def build_ui(self):
        """Build modern UI"""
        # Sidebar
        sidebar = ctk.CTkFrame(self, width=250, corner_radius=0, fg_color=COLOR_SIDEBAR)
        sidebar.pack(side="left", fill="y")
        
        # Logo/Title
        title_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        title_frame.pack(pady=(40, 30))
        
        ctk.CTkLabel(
            title_frame, text="    🛡️", font=("Segoe UI", 46)
        ).pack()
        
        ctk.CTkLabel(
            title_frame, text="REBEL VPN", font=("Segoe UI", 28, "bold"),
            text_color=COLOR_ACCENT
        ).pack()
        
        # Navigation buttons
        nav_items = [
            ("📊 Dashboard", "dashboard"),
            ("🌐 Servers", "servers"),
            ("➕ Add Config", "custom"),
            ("⚙️ Settings", "settings")
        ]
        
        for text, key in nav_items:
            btn = ctk.CTkButton(
                sidebar, text=text, fg_color="transparent", text_color=COLOR_TEXT_MAIN,
                hover_color=COLOR_CARD, height=55, anchor="w", font=("Segoe UI", 13),
                command=lambda k=key: self.show(k)
            )
            btn.pack(fill="x", padx=15, pady=3)
        
        # Version
        ctk.CTkLabel(
            sidebar, text=APP_VERSION, font=("Segoe UI", 10),
            text_color=COLOR_TEXT_DIM
        ).pack(side="bottom", pady=20)
        
        # Main area
        self.main_area = ctk.CTkFrame(self, fg_color=COLOR_BG)
        self.main_area.pack(side="right", fill="both", expand=True)
        
        self.frames = {}
        self.build_dashboard()
        self.build_servers()
        self.build_custom()
        self.build_settings()

    def build_dashboard(self):
        """Build professional dashboard"""
        f = ctk.CTkFrame(self.main_area, fg_color="transparent")
        self.frames["dashboard"] = f
        
        # Status card
        status_card = ctk.CTkFrame(f, fg_color=COLOR_CARD, corner_radius=20)
        status_card.pack(fill="x", padx=40, pady=(40, 20))
        
        self.status_label = ctk.CTkLabel(
            status_card, text="🔴 DISCONNECTED", font=("Segoe UI", 32, "bold"),
            text_color=COLOR_DISCONNECT_BTN
        )
        self.status_label.pack(pady=(30, 10))
        
        self.server_info = ctk.CTkLabel(
            status_card, text="No server selected", font=("Segoe UI", 14),
            text_color=COLOR_TEXT_DIM
        )
        self.server_info.pack(pady=(0, 20))
        
        # IP info
        ip_card = ctk.CTkFrame(f, fg_color=COLOR_CARD, corner_radius=16)
        ip_card.pack(fill="x", padx=40, pady=10)
        
        ctk.CTkLabel(
            ip_card, text="🌐 YOUR IP & LOCATION", font=("Segoe UI", 12, "bold"),
            text_color=COLOR_TEXT_DIM
        ).pack(pady=(15, 5))
        
        self.ip_label = ctk.CTkLabel(
            ip_card, text="Checking...", font=("Segoe UI", 16, "bold"),
            text_color=COLOR_TEXT_MAIN
        )
        self.ip_label.pack(pady=(0, 15))
        
        # Power button
        self.power_button = ctk.CTkButton(
            f, text="⚡ CONNECT", font=("Segoe UI", 18, "bold"), width=200, height=200,
            corner_radius=100, fg_color=COLOR_CARD, hover_color="#1A1C2A",
            command=self.toggle_connection
        )
        self.power_button.pack(pady=30)
        
        # Stats
        stats_frame = ctk.CTkFrame(f, fg_color="transparent")
        stats_frame.pack(pady=20)
        
        # Upload
        up_frame = ctk.CTkFrame(stats_frame, fg_color=COLOR_CARD, corner_radius=14)
        up_frame.pack(side="left", padx=20)
        
        ctk.CTkLabel(up_frame, text="⬆️ Upload", font=("Segoe UI", 11), text_color=COLOR_TEXT_DIM).pack(pady=(15, 5), padx=20)
        self.upload_label = ctk.CTkLabel(up_frame, text="0 KB/s", font=("Segoe UI", 16, "bold"))
        self.upload_label.pack(pady=(0, 15), padx=20)
        
        # Download
        down_frame = ctk.CTkFrame(stats_frame, fg_color=COLOR_CARD, corner_radius=14)
        down_frame.pack(side="left", padx=20)
        
        ctk.CTkLabel(down_frame, text="⬇️ Download", font=("Segoe UI", 11), text_color=COLOR_TEXT_DIM).pack(pady=(15, 5), padx=20)
        self.download_label = ctk.CTkLabel(down_frame, text="0 KB/s", font=("Segoe UI", 16, "bold"))
        self.download_label.pack(pady=(0, 15), padx=20)
        
        # Config count
        count_frame = ctk.CTkFrame(stats_frame, fg_color=COLOR_CARD, corner_radius=14)
        count_frame.pack(side="left", padx=20)
        
        ctk.CTkLabel(count_frame, text="📋 Servers", font=("Segoe UI", 11), text_color=COLOR_TEXT_DIM).pack(pady=(15, 5), padx=20)
        self.config_count_label = ctk.CTkLabel(count_frame, text="0", font=("Segoe UI", 16, "bold"))
        self.config_count_label.pack(pady=(0, 15), padx=20)

    def build_servers(self):
        """Build servers list"""
        f = ctk.CTkFrame(self.main_area, fg_color="transparent")
        self.frames["servers"] = f
        
        # Header
        header = ctk.CTkFrame(f, fg_color="transparent")
        header.pack(fill="x", padx=40, pady=(30, 20))
        
        ctk.CTkLabel(
            header, text="🌐 Server List", font=("Segoe UI", 24, "bold")
        ).pack(side="left")
        
        button_frame = ctk.CTkFrame(header, fg_color="transparent")
        button_frame.pack(side="right")
        
        ctk.CTkButton(
            button_frame, text="🎯 Check All Latency", width=130, font=("Segoe UI", 12),
            command=self.ping_all_servers
        ).pack(side="left", padx=5)
        
        # Refresh button with state tracking
        self.refresh_btn = ctk.CTkButton(
            button_frame, text="🔄 Refresh", width=90, font=("Segoe UI", 12),
            command=self.fetch_configs
        )
        self.refresh_btn.pack(side="left", padx=5)
        
        # Search
        self.search_var = tk.StringVar()
        self.search_var.trace("w", self.filter_servers)
        
        search_entry = ctk.CTkEntry(
            f, placeholder_text="🔍 Search servers...", textvariable=self.search_var,
            height=45, font=("Segoe UI", 13)
        )
        search_entry.pack(fill="x", padx=40, pady=(0, 15))
        
        # Server list
        self.server_list = ctk.CTkScrollableFrame(
            f, fg_color="transparent", height=500
        )
        self.server_list.pack(fill="both", expand=True, padx=40)

    def build_custom(self):
        """Build custom config section"""
        f = ctk.CTkFrame(self.main_area, fg_color="transparent")
        self.frames["custom"] = f
        
        ctk.CTkLabel(
            f, text="➕ Add Custom Config", font=("Segoe UI", 24, "bold")
        ).pack(pady=(40, 30))
        
        # Subscription URL
        ctk.CTkLabel(
            f, text="📤 Subscription URL or sing-box:// link:", font=("Segoe UI", 13),
            text_color=COLOR_TEXT_DIM
        ).pack(anchor="w", padx=40)
        
        self.url_entry = ctk.CTkEntry(
            f, placeholder_text="Paste URL here...", height=45,
            font=("Segoe UI", 13)
        )
        self.url_entry.pack(fill="x", padx=40, pady=(5, 15))
        
        ctk.CTkButton(
            f, text="📥 Fetch & Import", height=45, font=("Segoe UI", 13, "bold"),
            command=self.fetch_subscription
        ).pack(pady=(0, 30))
        
        # Manual input
        ctk.CTkLabel(
            f, text="✏️ Or paste configs manually (vless://, vmess://, trojan://, ss://, JSON):",
            font=("Segoe UI", 13), text_color=COLOR_TEXT_DIM
        ).pack(anchor="w", padx=40)
        
        self.manual_text = ctk.CTkTextbox(
            f, height=250, font=("Segoe UI", 12), corner_radius=14
        )
        self.manual_text.pack(fill="x", padx=40, pady=(5, 15))
        self.manual_text.insert("1.0", "vless://...\nvmess://...\ntrojan://...\n{...}")
        
        ctk.CTkButton(
            f, text="✅ Add Config(s)", height=45, font=("Segoe UI", 13, "bold"),
            command=self.add_manual_configs
        ).pack(pady=(0, 20))
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(f, mode='indeterminate')
        self.progress_bar.pack(fill="x", padx=40, pady=10)

    def build_settings(self):
        """Build settings"""
        f = ctk.CTkFrame(self.main_area, fg_color="transparent")
        self.frames["settings"] = f
        
        ctk.CTkLabel(
            f, text="⚙️ Settings", font=("Segoe UI", 24, "bold")
        ).pack(pady=(40, 30))
        
        # Auto-connect
        self.auto_connect_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            f, text=" Auto-connect on startup", variable=self.auto_connect_var,
            font=("Segoe UI", 13), command=self.save_settings
        ).pack(pady=10, anchor="w", padx=40)
        
        # System tray
        self.tray_var = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            f, text=" Minimize to system tray", variable=self.tray_var,
            font=("Segoe UI", 13), command=self.save_settings
        ).pack(pady=10, anchor="w", padx=40)
        
        # Auto-update
        self.auto_update_var = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            f, text=" Auto-update configs every hour", variable=self.auto_update_var,
            font=("Segoe UI", 13), command=self.save_settings
        ).pack(pady=10, anchor="w", padx=40)
        
        # Action buttons
        btn_frame = ctk.CTkFrame(f, fg_color="transparent")
        btn_frame.pack(pady=40)
        
        ctk.CTkButton(
            btn_frame, text="🗑️ Clear All Configs", width=180, height=45,
            fg_color=COLOR_DISCONNECT_BTN, hover_color="#C53030",
            font=("Segoe UI", 13, "bold"), command=self.clear_all_configs
        ).pack(side="left", padx=10)
        
        ctk.CTkButton(
            btn_frame, text="📊 Export Configs", width=180, height=45,
            fg_color=COLOR_ACCENT, font=("Segoe UI", 13, "bold"),
            command=self.export_configs
        ).pack(side="left", padx=10)

    def show(self, name: str):
        """Show frame"""
        for f in self.frames.values():
            f.pack_forget()
        
        frame = self.frames.get(name)
        if frame:
            frame.pack(fill="both", expand=True)

    def load_saved_configs(self) -> List[str]:
        """Load saved configs"""
        try:
            if SAVED_CONFIGS_FILE.exists():
                with open(SAVED_CONFIGS_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load saved configs: {e}")
        return []

    def save_configs_to_file(self) -> None:
        """Save configs"""
        try:
            raw_configs = [cfg['raw'] for cfg in self.configs]
            with open(SAVED_CONFIGS_FILE, "w", encoding="utf-8") as f:
                json.dump(raw_configs, f, indent=2)
            logger.info(f"Saved {len(raw_configs)} configs to file")
        except Exception as e:
            logger.error(f"Failed to save configs: {e}")

    def load_settings(self) -> None:
        """Load settings"""
        try:
            with open("settings.json", "r") as f:
                settings = json.load(f)
                self.auto_connect_var.set(settings.get("auto_connect", False))
                self.tray_var.set(settings.get("tray", True))
                self.auto_update_var.set(settings.get("auto_update", True))
                logger.info("Settings loaded successfully")
        except:
            logger.info("No settings file found, using defaults")

    def save_settings(self) -> None:
        """Save settings"""
        settings = {
            "auto_connect": self.auto_connect_var.get(),
            "tray": self.tray_var.get(),
            "auto_update": self.auto_update_var.get()
        }
        try:
            with open("settings.json", "w") as f:
                json.dump(settings, f)
            logger.info("Settings saved")
        except:
            pass

    def fetch_configs(self):
        """Load saved and remote configs - with thread safety"""
        # Prevent multiple simultaneous fetches
        if self.fetch_thread and self.fetch_thread.is_alive():
            logger.warning("Fetch already in progress, ignoring request")
            messagebox.showwarning("⚠️", "Fetch already in progress!")
            return
        
        # Clear UI
        for w in self.server_list.winfo_children():
            w.destroy()
        
        self.configs.clear()
        self.widgets.clear()
        
        # Load saved configs
        saved_count = 0
        for raw in self.saved_configs:
            if raw.startswith('#'):
                continue
            cfg = ConfigParser.parse(raw)
            if cfg and cfg.get('valid'):
                self.configs.append(cfg)
                self.add_server_card(cfg)
                saved_count += 1
        
        logger.info(f"Loaded {saved_count} saved configs")
        
        # Update UI
        self.update_stats()
        
        # Disable refresh button during fetch
        self.after(0, lambda: self.refresh_btn.configure(state="disabled", text="⏳ Fetching..."))
        
        # Fetch remote configs in thread
        self.fetch_thread = threading.Thread(target=self._fetch_remote_configs, daemon=True, name="Config-Fetcher")
        self.fetch_thread.start()

    def _fetch_remote_configs(self):
        """Fetch remote configs - runs in background thread"""
        try:
            logger.info(f"Fetching remote configs from: {CONFIG_FETCH_URL}")
            
            # Clean URL (double-check)
            url = CONFIG_FETCH_URL.strip()
            
            with urllib.request.urlopen(url, timeout=20) as response:
                content = response.read().decode('utf-8')
            
            logger.info(f"Successfully fetched {len(content)} bytes from remote")
            
            # Show preview in logs (first 100 chars)
            preview = content[:100].replace('\n', '\\n')
            logger.debug(f"Content preview: {preview}...")
            
            # Decrypt
            decrypted = ConfigDecryptor.decrypt_payload(content)
            
            if decrypted:
                logger.info(f"Successfully decrypted {len(decrypted)} characters")
                
                # Try to parse as JSON array first (MahsaNG format)
                try:
                    json_data = json.loads(decrypted)
                    if isinstance(json_data, list):
                        # It's a JSON array of objects with 'url' fields
                        lines = []
                        for item in json_data:
                            if isinstance(item, dict) and 'url' in item:
                                lines.append(item['url'])
                            elif isinstance(item, str):
                                lines.append(item)
                        logger.info(f"Extracted {len(lines)} URLs from JSON array")
                    else:
                        # Single JSON object or other format
                        if isinstance(json_data, dict) and 'url' in json_data:
                            lines = [json_data['url']]
                        else:
                            logger.warning("Unknown JSON format, trying as raw config")
                            lines = [decrypted]
                except json.JSONDecodeError:
                    # Not JSON, treat as newline-separated URLs (old format)
                    lines = [l.strip() for l in decrypted.splitlines() if l.strip() and not l.startswith('#')]
                    logger.info(f"Parsed as plaintext: {len(lines)} lines")
                
                # Log first few lines for debugging
                if lines:
                    logger.debug(f"First config line: {lines[0][:100]}...")
                
                # Process in main thread
                self.after(0, lambda: self._process_remote_links(lines))
            else:
                logger.error("Decryption failed - returned None")
                self.after(0, lambda: messagebox.showerror(
                    "❌ Decryption Error", 
                    "Failed to decrypt remote configs. The encryption key may be incorrect or the file format has changed."
                ))
        
        except urllib.error.HTTPError as e:
            logger.error(f"HTTP error: {e.code} - {e.reason}")
            self.after(0, lambda: messagebox.showerror(
                "❌ HTTP Error", 
                f"Failed to fetch configs: HTTP {e.code} - {e.reason}\n\nPlease check if the URL is accessible and the file exists."
            ))
        
        except urllib.error.URLError as e:
            logger.error(f"Network error: {e.reason}")
            self.after(0, lambda: messagebox.showerror(
                "❌ Network Error", 
                f"Network error: {e.reason}\n\nPlease check your internet connection and try again."
            ))
        
        except Exception as e:
            logger.error(f"Unexpected error in fetch: {e}", exc_info=True)
            self.after(0, lambda: messagebox.showerror(
                "❌ Unexpected Error", 
                f"An error occurred while fetching configs:\n{str(e)}\n\nCheck the log file for details."
            ))
        
        finally:
            # Re-enable refresh button
            self.after(0, lambda: self.refresh_btn.configure(state="normal", text="🔄 Refresh"))

    def _process_remote_links(self, lines: List[str]):
        """Process remote links and add to UI - runs in main thread"""
        if not lines:
            logger.warning("No config lines to process")
            messagebox.showwarning("⚠️", "No config data received from server")
            return
        
        added = 0
        duplicates = 0
        errors = 0
        
        for i, link in enumerate(lines):
            try:
                link = link.strip()
                if not link or link.startswith('#'):
                    continue
                
                if "://" not in link:
                    logger.debug(f"Skipping line {i+1}: no protocol found - {link[:50]}")
                    continue
                
                # Skip JSON fragments
                if link.startswith('"') or link.startswith('{'):
                    logger.debug(f"Skipping line {i+1}: JSON fragment - {link[:50]}")
                    continue
                
                cfg = ConfigParser.parse(link)
                if cfg and cfg.get('valid'):
                    if cfg['raw'] not in self.widgets:
                        self.configs.append(cfg)
                        self.add_server_card(cfg)
                        if link not in self.saved_configs:
                            self.saved_configs.append(link)
                        added += 1
                    else:
                        duplicates += 1
                else:
                    errors += 1
                    logger.debug(f"Failed to parse line {i+1}: {link[:50]}...")
        
            except Exception as e:
                errors += 1
                logger.error(f"Error processing line {i+1}: {e}")
        
        logger.info(f"Processing complete: added={added}, duplicates={duplicates}, errors={errors}")
        
        if added > 0:
            self.save_configs_to_file()
            self.update_stats()
            messagebox.showinfo("✅ Success", f"Successfully imported {added} new server(s)!")
        else:
            msg = f"No new configs added. Duplicates: {duplicates}, Errors: {errors}"
            logger.info(msg)
            messagebox.showinfo("ℹ️ Info", msg)

    def add_server_card(self, cfg: Dict[str, Any]):
        """Add server card"""
        if cfg['raw'] in self.widgets:
            logger.debug(f"Skipping duplicate server card: {cfg['remark']}")
            return
        
        card = ctk.CTkFrame(self.server_list, fg_color=COLOR_CARD, corner_radius=16)
        card.pack(fill="x", pady=6)
        
        # Type badge
        type_colors = {
            'vmess': '#BB9AF7',
            'vless': '#7DCFFF',
            'trojan': '#2DCE89',
            'shadowsocks': '#F5365C',
            'singbox': '#E0AF68',
            'singbox_subscription': '#FF9E64'
        }
        
        type_label = ctk.CTkLabel(
            card, text=cfg['type'].upper(), width=90,
            fg_color=type_colors.get(cfg['type'], COLOR_ACCENT),
            text_color="black", font=("Arial", 11, "bold"), corner_radius=8
        )
        type_label.pack(side="left", padx=15, pady=15)
        
        # Name
        name_label = ctk.CTkLabel(
            card, text=cfg['remark'][:50], font=("Segoe UI", 14, "bold"),
            anchor="w"
        )
        name_label.pack(side="left", fill="x", expand=True, padx=10)
        
        # Ping
        ping_label = ctk.CTkLabel(
            card, text=cfg.get('delay', '-'), width=80,
            text_color=COLOR_TEXT_DIM, font=("Segoe UI", 12)
        )
        ping_label.pack(side="right", padx=5)
        
        # Delete button
        delete_btn = ctk.CTkButton(
            card, text="🗑️", width=40, fg_color="transparent",
            hover_color=COLOR_DISCONNECT_BTN, text_color=COLOR_TEXT_DIM,
            command=lambda c=cfg: self.delete_config(c)
        )
        delete_btn.pack(side="right", padx=5)
        
        # Select button
        select_btn = ctk.CTkButton(
            card, text="Select", width=80, fg_color=COLOR_ACCENT,
            hover_color="#4A5BD4", command=lambda c=cfg: self.select_server(c)
        )
        select_btn.pack(side="right", padx=15)
        
        self.widgets[cfg['raw']] = {
            'card': card,
            'ping': ping_label,
            'cfg': cfg
        }

    def delete_config(self, cfg: Dict[str, Any]):
        """Delete a specific config"""
        if messagebox.askyesno("⚠️ Delete Config", f"Delete '{cfg['remark']}'?"):
            # Remove from lists
            if cfg in self.configs:
                self.configs.remove(cfg)
            if cfg['raw'] in self.widgets:
                del self.widgets[cfg['raw']]
            if cfg['raw'] in self.saved_configs:
                self.saved_configs.remove(cfg['raw'])
            
            # Remove UI card
            for widget in self.server_list.winfo_children():
                if hasattr(widget, 'winfo_children'):
                    for child in widget.winfo_children():
                        if isinstance(child, ctk.CTkButton) and child.cget('text') == "Select":
                            if child.cget('command') and child.cget('command').__closure__:
                                closure = child.cget('command').__closure__
                                if closure and any(c.cell_contents == cfg for c in closure):
                                    widget.destroy()
                                    break
            
            self.update_stats()
            logger.info(f"Deleted config: {cfg['remark']}")

    def filter_servers(self, *args):
        """Filter servers"""
        term = self.search_var.get().lower().strip()
        
        for widget in self.widgets.values():
            cfg = widget['cfg']
            if not term or term in cfg['remark'].lower() or term in cfg['type'].lower():
                widget['card'].pack(fill="x", pady=6)
            else:
                widget['card'].pack_forget()

    def select_server(self, cfg: Dict[str, Any]):
        """Select server"""
        self.selected_config = cfg
        self.server_info.configure(text=f"📡 {cfg['remark']}")
        self.show("dashboard")
        logger.info(f"Selected server: {cfg['remark']}")

    def toggle_connection(self):
        """Toggle VPN"""
        if self.is_connected:
            self.disconnect_vpn()
        else:
            self.connect_vpn()

    # ============================
    #  Connection handler
    # ============================
    def connect_vpn(self):
        """Connect VPN"""
        if not self.selected_config:
            messagebox.showwarning("⚠️", "Please select a server first!")
            return
        
        if self.selected_config.get('needs_resolve'):
            # Auto-resolve sing-box subscription
            messagebox.showinfo("ℹ️", "Resolving subscription, please wait...")
            self.resolve_and_connect_singbox(self.selected_config)
            return
        
        # Update UI
        self.status_label.configure(text="🟡 CONNECTING...", text_color=COLOR_WARNING)
        self.power_button.configure(state="disabled", text="⏳")
        
        # Connection task in thread
        def connect_task():
            try:
                cfg = self.selected_config
                
                # Choose correct core
                if cfg['type'] == 'singbox':
                    ok, msg = self.singbox.start(cfg)
                else:
                    ok, msg = self.xray.start(cfg)
                
                # Handle result in main thread
                self.after(0, lambda s=ok, m=msg: self._on_connect_result(s, m))
                
            except Exception as e:
                logger.error(f"Connection error: {e}", exc_info=True)
                self.after(0, lambda: self._on_connect_result(False, f"Connection error: {e}"))
        
        threading.Thread(target=connect_task, daemon=True, name="VPN-Connector").start()

    def resolve_and_connect_singbox(self, cfg: Dict[str, Any]):
        """Resolve sing-box subscription and connect"""
        def resolve_task():
            try:
                # Download config
                config = download_singbox_config(cfg['url'])
                if not config:
                    self.after(0, lambda: messagebox.showerror("❌ Error", "Failed to download Sing-Box config"))
                    self.after(0, lambda: self.power_button.configure(state="normal"))
                    return
                
                # Find first valid outbound
                outbounds = config.get('outbounds', [])
                proxy_outbound = None
                
                for out in outbounds:
                    if out.get('type') not in [None, 'direct', 'block'] and out.get('server'):
                        proxy_outbound = out
                        break
                
                if not proxy_outbound:
                    self.after(0, lambda: messagebox.showerror("❌ Error", "No valid outbound found in config"))
                    self.after(0, lambda: self.power_button.configure(state="normal"))
                    return
                
                # Create new config from outbound
                new_cfg = {
                    'type': 'singbox',
                    'remark': cfg['remark'],
                    'config': {
                        'inbounds': [{
                            "type": "mixed",
                            "tag": "mixed-in",
                            "listen": "127.0.0.1",
                            "listen_port": SOCKS_PORT,
                            "sniff": True
                        }],
                        'outbounds': [proxy_outbound, {"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}],
                        'route': config.get('route', {})
                    },
                    'raw': f"sb_resolved_{hashlib.md5(json.dumps(proxy_outbound).encode()).hexdigest()[:8]}",
                    'delay': "-",
                    'valid': True,
                    'needs_resolve': False
                }
                
                # Update selected config
                self.selected_config = new_cfg
                
                # Attempt connection
                ok, msg = self.singbox.start(new_cfg)
                self.after(0, lambda s=ok, m=msg: self._on_connect_result(s, m))
                
            except Exception as e:
                logger.error(f"Resolve error: {e}", exc_info=True)
                self.after(0, lambda: self._on_connect_result(False, f"Resolve error: {e}"))
        
        threading.Thread(target=resolve_task, daemon=True, name="SingBox-Resolver").start()

    def _on_connect_result(self, success: bool, message: str):
        """Handle connection result - in main thread"""
        self.power_button.configure(state="normal")
        
        if success:
            self.is_connected = True
            self.status_label.configure(text="🟢 CONNECTED", text_color=COLOR_CONNECT_BTN)
            self.power_button.configure(fg_color=COLOR_CONNECT_BTN, text="🔌 DISCONNECT")
            ProxyManager.set_enabled(True)
            # Update IP through proxy
            self.update_ip_info(use_proxy=True)
        else:
            self.is_connected = False
            self.status_label.configure(text="🔴 FAILED", text_color=COLOR_DISCONNECT_BTN)
            self.power_button.configure(fg_color=COLOR_CARD, text="⚡ CONNECT")
            messagebox.showerror("❌ Error", message)

    # ============================
    #  Disconnect
    # ============================
    def disconnect_vpn(self):
        """Disconnect VPN"""
        try:
            # Update UI immediately
            self.status_label.configure(text="🟠 DISCONNECTING...", text_color=COLOR_WARNING)
            
            # Stop cores
            ProxyManager.set_enabled(False)
            self.xray.stop()
            self.singbox.stop()
            
            # Reset state
            self.is_connected = False
            self.status_label.configure(text="🔴 DISCONNECTED", text_color=COLOR_DISCONNECT_BTN)
            self.power_button.configure(fg_color=COLOR_CARD, text="⚡ CONNECT")
            
            # Clear traffic stats
            self._update_traffic(0, 0)
            
            # Update IP without proxy (direct)
            self.update_ip_info(use_proxy=False)
            
            logger.info("VPN disconnected successfully")
        except Exception as e:
            logger.error(f"Disconnect error: {e}", exc_info=True)
            messagebox.showerror("❌ Error", f"Disconnect failed: {e}")

    # ============================
    #  IP Check with proxy support
    # ============================
    def update_ip_info(self, use_proxy: bool = False):
        """Update IP info - PROPERLY AWAITED with proxy support"""
        self.ip_label.configure(text="🌐 Checking...")
        
        def run_ip_check():
            try:
                # Create and run event loop for this thread
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                # Run the async function with proxy parameter
                result = loop.run_until_complete(IPChecker.check_ip_with_retry(use_proxy=use_proxy))
                
                # Schedule UI update in main thread
                self.after(0, lambda: self.ip_label.configure(text=result['full']))
                
                loop.close()
            except Exception as e:
                logger.error(f"IP check thread error: {e}")
                self.after(0, lambda: self.ip_label.configure(text="❌ IP check failed"))
        
        # Start in daemon thread
        threading.Thread(target=run_ip_check, daemon=True, name="IP-Checker").start()

    # ============================
    #  Traffic monitor
    # ============================
    def start_traffic_monitor(self):
        """Monitor traffic without blocking"""
        if self.monitor_running:
            return
            
        self.monitor_running = True
        
        # Ensure psutil is available
        try:
            import psutil
        except ImportError:
            logger.warning("psutil not available, using simulated traffic values")
            psutil = None
        
        def monitor():
            last_net = None
            
            while True:
                if self.is_connected:
                    try:
                        if psutil:
                            # Real traffic stats
                            net = psutil.net_io_counters()
                            
                            if last_net:
                                # Calculate per-second rate
                                up = (net.bytes_sent - last_net.bytes_sent) / 1024
                                down = (net.bytes_recv - last_net.bytes_recv) / 1024
                                
                                # Update UI (thread-safe)
                                self.after(0, lambda u=up, d=down: 
                                         self._update_traffic(int(u), int(d)))
                            
                            last_net = net
                        else:
                            # Fallback random values
                            self.after(0, lambda: self._update_traffic(
                                random.randint(100, 500), 
                                random.randint(500, 2000)
                            ))
                    except Exception as e:
                        logger.debug(f"Traffic monitor error: {e}")
                
                time.sleep(1)
        
        # Start monitor thread
        threading.Thread(target=monitor, daemon=True, name="Traffic-Monitor").start()

    def _update_traffic(self, up: int, down: int):
        """Update traffic labels - thread-safe"""
        self.upload_label.configure(text=f"⬆️ {up} KB/s")
        self.download_label.configure(text=f"⬇️ {down} KB/s")

    def update_stats(self):
        """Update stats"""
        self.config_count_label.configure(text=str(len(self.configs)))

    def fetch_subscription(self):
        """Fetch subscription with improved Google Drive and sing-box:// support"""
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("⚠️", "Enter a URL first!")
            return
        
        # Detect if it's a JSON/config URL or sing-box link
        is_config_url = (
            url.lower().endswith('.json') or 
            'drive.google.com' in url or
            url.startswith("sing-box://") or
            'raw.githubusercontent.com' in url
        )
        
        self.progress_bar.start()
        
        def fetch_task():
            try:
                if is_config_url:
                    if url.startswith("sing-box://"):
                        cfg = ConfigParser.parse(url)
                        if cfg and cfg.get('needs_resolve'):
                            json_data = download_singbox_config(cfg['url'])
                            if json_data:
                                self.after(0, lambda: self.process_singbox_json(json_data, cfg['url']))
                            else:
                                self.after(0, lambda: messagebox.showerror("❌ Error", "Failed to download config"))
                        else:
                            self.after(0, lambda: messagebox.showerror("❌ Error", "Invalid sing-box:// link"))
                    else:
                        json_data = download_singbox_config(url)
                        if json_data:
                            self.after(0, lambda: self.process_singbox_json(json_data, url))
                        else:
                            self.after(0, lambda: messagebox.showerror("❌ Error", "Failed to download JSON config"))
                else:
                    # Regular subscription
                    asyncio.run(self._async_fetch_subscription(url))
            except Exception as e:
                logger.error(f"Fetch error: {e}")
                self.after(0, lambda: messagebox.showerror("❌ Error", str(e)))
            finally:
                self.after(0, self.progress_bar.stop)
        
        threading.Thread(target=fetch_task, daemon=True, name="Config-Fetcher").start()

    def process_singbox_json(self, json_data: Dict[str, Any], source_url: str):
        """Process Sing-Box JSON and extract proxy outbounds - FIXED"""
        outbounds = json_data.get('outbounds', [])
        added = 0
        
        # Extract actual proxy outbounds (skip selectors, urltests, etc.)
        proxy_outbounds = []
        for outbound in outbounds:
            outbound_type = outbound.get('type', '')
            # Skip non-server outbounds
            if outbound_type in [None, 'direct', 'block', 'dns', 'selector', 'urltest']:
                continue
            
            # Must have a server field to be a real proxy
            if not outbound.get('server'):
                continue
            
            proxy_outbounds.append(outbound)
        
        logger.info(f"Found {len(proxy_outbounds)} valid proxy outbounds in Sing-Box config")
        
        # Process each proxy outbound
        for i, outbound in enumerate(proxy_outbounds):
            try:
                # Create remark from tag or generate one
                tag = outbound.get('tag', f"Server {i+1}")
                # Clean up the remark if it contains the source URL
                if source_url:
                    url_name = source_url.split('/')[-1].replace('.json', '').replace('.txt', '')
                    if len(url_name) > 30:
                        url_name = url_name[:27] + "..."
                    remark = f"{tag} ({url_name})"
                else:
                    remark = tag
                
                # Create a minimal sing-box config for this outbound
                config = {
                    'inbounds': [{
                        "type": "mixed",
                        "tag": "mixed-in",
                        "listen": "127.0.0.1",
                        "listen_port": SOCKS_PORT,
                        "sniff": True
                    }],
                    'outbounds': [
                        outbound,
                        {"type": "direct", "tag": "direct"},
                        {"type": "block", "tag": "block"}
                    ],
                    'route': json_data.get('route', {})
                }
                
                # Generate unique raw ID
                raw_id = f"sb_outbound_{i}_{hashlib.md5(json.dumps(outbound, sort_keys=True).encode()).hexdigest()[:8]}"
                
                new_cfg = {
                    'type': 'singbox',
                    'remark': remark,
                    'config': config,
                    'raw': raw_id,
                    'delay': "-",
                    'valid': True,
                    'needs_resolve': False
                }
                
                # Add to app
                self.configs.append(new_cfg)
                self.add_server_card(new_cfg)
                if raw_id not in self.saved_configs:
                    self.saved_configs.append(raw_id)
                added += 1
                
            except Exception as e:
                logger.error(f"Error processing outbound {i}: {e}")
        
        if added > 0:
            self.save_configs_to_file()
            self.update_stats()
            messagebox.showinfo("✅ Success", f"Imported {added} server(s) from Sing-Box config!")
        else:
            messagebox.showwarning("⚠️", "No valid proxy outbounds found in the JSON file!")
        
        self.url_entry.delete(0, 'end')
        self.show("servers")

    async def _async_fetch_subscription(self, url: str):
        """Async fetch subscription"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status != 200:
                        raise Exception(f"HTTP {resp.status}")
                    
                    content = await resp.text()
                    content = content.strip()
                    
                    # Try JSON (Sing-Box format)
                    try:
                        json_data = json.loads(content)
                        if isinstance(json_data, dict) and "outbounds" in json_data:
                            # This is a sing-box config file
                            self.after(0, lambda: self.process_singbox_json(json_data, url))
                            return
                    except:
                        pass
                    
                    # Try base64 decode
                    try:
                        decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                        lines = [ln.strip() for ln in decoded.splitlines() if ln.strip() and not ln.startswith('#')]
                    except:
                        lines = [ln.strip() for ln in content.splitlines() if ln.strip() and not ln.startswith('#')]
                    
                    # Parse lines
                    added = 0
                    for line in lines:
                        if line.startswith(("vless://", "vmess://", "trojan://", "ss://", "sing-box://")):
                            cfg = ConfigParser.parse(line)
                            if cfg and cfg.get('valid'):
                                self.after(0, lambda c=cfg: self._add_fetched_config(c))
                                added += 1
                    
                    if added > 0:
                        self.after(0, lambda: self._on_subscription_success(added))
                    else:
                        self.after(0, lambda: messagebox.showwarning("⚠️", "No valid configs found!"))
        
        except Exception as e:
            logger.error(f"Async fetch error: {e}")
            self.after(0, lambda: messagebox.showerror("❌ Error", str(e)))

    def _add_fetched_config(self, cfg: Dict[str, Any]):
        """Add fetched config"""
        if cfg['raw'] not in self.widgets:
            self.configs.append(cfg)
            self.add_server_card(cfg)

    def _on_subscription_success(self, count: int):
        """Subscription success"""
        self.save_configs_to_file()
        self.update_stats()
        messagebox.showinfo("✅ Success", f"Imported {count} config(s)!")
        self.url_entry.delete(0, 'end')
        self.show("servers")

    def add_manual_configs(self):
        """Add manual configs"""
        text = self.manual_text.get("1.0", "end").strip()
        if not text or text == "vless://...":
            messagebox.showwarning("⚠️", "Paste some configs first!")
            return
        
        added = 0
        
        # Single JSON
        if text.startswith("{") and text.endswith("}"):
            try:
                cfg = ConfigParser.parse(text)
                if cfg:
                    self._add_fetched_config(cfg)
                    added += 1
            except:
                pass
        
        # Multi-line
        for line in text.splitlines():
            line = line.strip()
            if line.startswith(("vless://", "vmess://", "trojan://", "ss://", "sing-box://")):
                cfg = ConfigParser.parse(line)
                if cfg and cfg.get('valid'):
                    self._add_fetched_config(cfg)
                    added += 1
        
        if added > 0:
            self.save_configs_to_file()
            self.update_stats()
            messagebox.showinfo("✅ Success", f"Added {added} config(s)!")
            self.manual_text.delete("1.0", "end")
            self.show("servers")
        else:
            messagebox.showwarning("⚠️", "No valid configs found!")

    def ping_all_servers(self):
        """Ping all servers"""
        for widget in self.widgets.values():
            widget['ping'].configure(text="⏳")
        
        # Safe ping with thread pool
        def safe_ping(cfg):
            try:
                if cfg.get('type') in ['singbox', 'singbox_subscription'] or cfg.get('needs_resolve'):
                    return cfg, "-"
                return cfg, DelayChecker.check(cfg)
            except:
                return cfg, "Error"
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(safe_ping, cfg) for cfg in self.configs]
            for future in as_completed(futures):
                try:
                    cfg, result = future.result(timeout=5)
                    self.after(0, lambda c=cfg, r=result: self._update_ping(c, r))
                except:
                    pass

    def _update_ping(self, cfg: Dict[str, Any], ping: str):
        """Update ping display"""
        if cfg['raw'] in self.widgets:
            self.widgets[cfg['raw']]['ping'].configure(text=ping)
            cfg['delay'] = ping

    def export_configs(self):
        """Export configs"""
        try:
            export_file = Path("exported_configs.txt")
            with open(export_file, "w", encoding="utf-8") as f:
                for cfg in self.configs:
                    f.write(cfg['raw'] + "\n\n")
            
            messagebox.showinfo("✅ Export", f"Exported to {export_file}")
        except Exception as e:
            messagebox.showerror("❌ Error", str(e))

    def clear_all_configs(self):
        """Clear all configs"""
        if not messagebox.askyesno("⚠️ Confirm", "Delete all configs?"):
            return
        
        self.configs.clear()
        self.widgets.clear()
        self.saved_configs.clear()
        
        for w in self.server_list.winfo_children():
            w.destroy()
        
        try:
            if SAVED_CONFIGS_FILE.exists():
                SAVED_CONFIGS_FILE.unlink()
        except:
            pass
        
        self.update_stats()
        messagebox.showinfo("✅ Success", "All configs cleared!")

    # ============================
    #  Proper cleanup on exit
    # ============================
    def on_close(self):
        """Close app"""
        try:
            logger.info("Shutting down...")
            
            if self.is_connected:
                self.disconnect_vpn()
            
            self.save_settings()
            
            # Ensure all processes killed
            for manager in [self.xray, self.singbox]:
                if hasattr(manager, 'process') and manager.process:
                    try:
                        manager.process.kill()
                    except:
                        pass
            
            logger.info("App closed safely")
            self.destroy()
        except Exception as e:
            logger.critical(f"Shutdown error: {e}", exc_info=True)
            self.destroy()
            sys.exit(1)

# ================================
# Entry Point
# ================================
def main():
    """Main entry"""
    try:
        if not is_admin():
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            return
        
        # Check requirements first
        check_requirements()
        check_cores()
        
        # Create and run app
        app = App()
        app.mainloop()
        
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        messagebox.showerror("❌ Critical Error", str(e))
        sys.exit(1)

if __name__ == "__main__":
    main()