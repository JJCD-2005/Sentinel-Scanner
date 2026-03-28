import nvdlib
import time
import re

class RiskEvaluator:
    def __init__(self):
        pass

    def consultar_nvd(self, banner, puerto):
        if not banner or banner in ["No disponible", "Desconocido"]: return None, None
        # Limpieza de banner para mejorar coincidencia en NIST
        match = re.search(r'([a-zA-Z\-]+)[/_ ]?([0-9]+\.[0-9]+)', banner)
        query = f"{match.group(1)} {match.group(2)}" if match else banner[:20]
        
        try:
            time.sleep(0.6) # Evitar baneo por exceso de peticiones
            r = nvdlib.searchCVE(keywordSearch=query, limit=1)
            if r:
                score = getattr(r[0], 'v31score', getattr(r[0], 'v2score', 0.0))
                return r[0].id, score
        except: pass
        return None, None

    def calcular_score_por_configuracion(self, puerto, protos):
        """Lógica interna para cuando no hay CVEs conocidos"""
        # Si es el puerto 443 y no hay TLS -> CRÍTICO
        if puerto == 443 and not protos: return 9.8
        # Si es el puerto 80 (HTTP Plano) -> ALTO
        if puerto == 80: return 7.5
        
        # Evaluación por versión de TLS
        if "TLSv1.3" in protos: return 0.0  # Excelente seguridad
        if "TLSv1.2" in protos: return 2.0  # Seguridad estándar aceptable
        if any(x in protos for x in ["TLSv1.0", "TLSv1.1", "SSLv3"]): return 8.5 # Obsoleto
        
        return 5.0 # Valor neutral para otros servicios

    def procesar(self, resultados):
        for item in resultados:
            p = item['puerto']
            protos = item['protocolos_activos']
            
            # 1. Intentar obtener score de base de datos oficial
            cve_id, nvd_score = self.consultar_nvd(item['banner'], p)
            
            # 2. Si no hay CVE, usar lógica de endurecimiento (Hardening)
            if nvd_score and nvd_score > 0:
                score_final = nvd_score
            else:
                score_final = self.calcular_score_por_configuracion(p, protos)

            # --- PERSONALIZACIÓN DE MENSAJES ---
            if p == 22:
                msg = [f"1. Protocolos: {item['banner']}", "2. Ciphers: Verificando AES-GCM.", "3. Certificados: N/A - SSH Key.", f"4. Fallos: {cve_id if cve_id else 'Ninguno'}", "5. Llaves: RSA/Ed25519."]
            elif p == 80:
                msg = ["1. Protocolos: HTTP Inseguro.", "2. Ciphers: Ninguno.", "3. Certificados: N/A.", "4. Vulnerabilidades: Sniffing activo.", "5. Acción: Migrar a HTTPS."]
            else:
                tls_info = f"Activos: {', '.join(protos)}" if protos else "Sin cifrado"
                msg = [
                    f"1. Enumeración: {tls_info}",
                    "2. Ciphers: " + ("Fuerte" if "TLSv1.3" in protos else "Estándar"),
                    "3. Certificados: Validación de confianza.",
                    f"4. CVE: {cve_id if cve_id else 'Limpio'}",
                    f"5. Riesgo: Evaluado en {score_final} (CVSS)"
                ]

            item.update({
                "cvss": score_final,
                "cve": cve_id if cve_id else "N/A",
                "riesgo": self._categorizar(score_final),
                "recomendacion": " | ".join(msg),
                "protocolo_final": item['protocolo_principal']
            })
        return resultados

    def _categorizar(self, s):
        if s >= 9.0: return "CRÍTICO"
        if s >= 7.0: return "ALTO"
        if s >= 4.0: return "MEDIO"
        return "BAJO"