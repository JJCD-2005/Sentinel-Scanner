import socket
import subprocess
import re

class SentinelScanner:
    def __init__(self, target, puertos_usuario=None):
        self.target = target
        self.ip = None
        self.puertos = puertos_usuario if puertos_usuario else [22, 80, 443, 465, 993, 8443]

    def preparar_objetivo(self):
        """Manejo de errores y resolución de IP"""
        target_limpio = re.sub(r'^https?://', '', self.target).split('/')[0]
        try:
            self.ip = socket.gethostbyname(target_limpio)
            return True
        except:
            return False

    def obtener_banner(self, puerto):
        """Banner Grabbing para identificar versiones reales del software"""
        try:
            with socket.socket() as s:
                s.settimeout(2.5)
                s.connect((self.ip, puerto))
                if puerto in [80, 443, 8443]:
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(1024).decode(errors='ignore').strip()
                if "Server:" in banner:
                    return banner.split("Server:")[1].split("\r\n")[0].strip()
                return banner[:60].replace("\n", " ")
        except:
            return None

    def analizar_tls_profundo(self, puerto):
        """Enumeración de protocolos habilitados (OpenSSL)"""
        soportados = []
        versiones = {
            "ssl3": "SSLv3", "tls1": "TLSv1.0", "tls1_1": "TLSv1.1", 
            "tls1_2": "TLSv1.2", "tls1_3": "TLSv1.3"
        }
        for flag, nombre in versiones.items():
            cmd = f"openssl s_client -connect {self.ip}:{puerto} -{flag} < /dev/null 2>&1"
            try:
                proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=3)
                if "Cipher" in proc.stdout and "BEGIN CERTIFICATE" in proc.stdout:
                    soportados.append(nombre)
            except:
                continue
        return soportados

    def ejecutar_escaneo(self):
        resultados = []
        for p in self.puertos:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.5)
                if s.connect_ex((self.ip, p)) == 0:
                    banner = self.obtener_banner(p)
                    protos = self.analizar_tls_profundo(p)
                    resultados.append({
                        "puerto": p,
                        "banner": banner,
                        "protocolos_activos": protos,
                        "protocolo_principal": protos[-1] if protos else "NOTLS"
                    })
        return resultados