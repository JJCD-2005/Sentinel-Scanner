import sys
import re
from scanner_engine import SentinelScanner
from logic_engine import RiskEvaluator
from reporter_engine import AuditReporter

def es_objetivo_valido(target):
    # Regex para validar IP o Dominio
    patron = r'^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|(\d{1,3}\.){3}\d{1,3})$'
    return re.match(patron, target) is not None

def main():
    if len(sys.argv) < 2:
        print("Uso: python main.py <IP_o_Dominio>")
        return

    target = sys.argv[1]

    if not es_objetivo_valido(target):
        print(f"[!] Error: '{target}' no es un formato válido (Use google.com o 1.1.1.1)")
        return

    scanner = SentinelScanner(target)
    if not scanner.preparar_objetivo():
        print("[!] Error: No se pudo resolver el host.")
        return

    print(f"[*] Analizando {target}... Escaneando puertos y protocolos TLS...")
    raw = scanner.ejecutar_escaneo()
    
    evaluador = RiskEvaluator()
    data = evaluador.procesar(raw)
    
    reportero = AuditReporter(target)
    reportero.consola(data)
    reportero.guardar_formatos(data)

if __name__ == "__main__":
    main()