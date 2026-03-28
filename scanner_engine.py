import socket
import ssl
import re
from concurrent.futures import ThreadPoolExecutor

class SentinelScanner:
    def __init__(self, target, puertos_usuario=None):
        # Limpieza de URL para evitar errores de socket
        self.target = re.sub(r'^https?://', '', target).split('/')[0].split(':')[0]
        self.ip = None
        self.puertos = puertos_usuario if puertos_usuario else [22, 80, 443, 465, 993]

    def preparar_objetivo(self):
        try:
            self.ip = socket.gethostbyname(self.target)
            return True
        except socket.gaierror:
            return False

    def verificar_puerto_abierto(self, p):
        """Escaneo rápido de cortesía técnica"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.8)
                if s.connect_ex((self.ip, p)) == 0:
                    return p
        except:
            return None
        return None

    def obtener_banner(self, puerto):
        try:
            with socket.create_connection((self.ip, puerto), timeout=1.5) as s:
                if puerto in [80, 443, 8080, 8443]:
                    s.send(b"HEAD / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\n\r\n")
                
                banner = s.recv(1024).decode(errors='ignore').strip()
                if "Server:" in banner:
                    return banner.split("Server:")[1].split("\r\n")[0].strip()
                return banner[:50].replace("\n", " ") if banner else "Desconocido"
        except:
            return "No disponible"

    def analizar_tls_profundo(self, puerto):
        """Detección con SNI para evitar falsos negativos (NOTLS)"""
        soportados = []
        versiones = {
            "TLSv1.0": ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None,
            "TLSv1.1": ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None,
            "TLSv1.2": ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None,
            "TLSv1.3": ssl.PROTOCOL_TLSv1_3 if hasattr(ssl, 'PROTOCOL_TLSv1_3') else None,
        }

        for nombre, prot in versiones.items():
            if prot is None: continue
            try:
                contexto = ssl.SSLContext(prot)
                contexto.check_hostname = False
                contexto.verify_mode = ssl.CERT_NONE
                with socket.create_connection((self.ip, puerto), timeout=1.5) as sock:
                    with contexto.wrap_socket(sock, server_hostname=self.target) as ssock:
                        soportados.append(nombre)
            except:
                continue
        return soportados

    def ejecutar_escaneo(self):
        resultados = []
        # Escaneo concurrente de puertos (100 hilos)
        with ThreadPoolExecutor(max_workers=100) as executor:
            abiertos = list(executor.map(self.verificar_puerto_abierto, self.puertos))
            puertos_activos = [p for p in abiertos if p is not None]

        # Auditoría profunda solo en puertos abiertos
        for p in puertos_activos:
            banner = self.obtener_banner(p)
            protos = self.analizar_tls_profundo(p)
            resultados.append({
                "puerto": p,
                "banner": banner,
                "protocolos_activos": protos,
                "protocolo_principal": protos[-1] if protos else "NOTLS"
            })
        return resultados