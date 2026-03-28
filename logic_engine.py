import nvdlib
import time
import re

class RiskEvaluator:
    def __init__(self):
        # Base de conocimientos extendida para remediación
        self.catalogo_remediacion = {
            22: {
                "nombre": "SSH",
                "basico": "Administración remota expuesta.",
                "remediacion": "Implementar autenticación por llaves RSA/Ed25519, deshabilitar el acceso root y cambiar el puerto por defecto. Instalar Fail2Ban."
            },
            80: {
                "nombre": "HTTP",
                "basico": "Tráfico web sin cifrar (Cleartext).",
                "remediacion": "Configurar una redirección permanente (301) hacia el puerto 443 e instalar un certificado SSL/TLS (Let's Encrypt)."
            },
            443: {
                "nombre": "HTTPS",
                "basico": "Servicio web cifrado.",
                "remediacion": "Deshabilitar TLS 1.0/1.1. Forzar el uso de HSTS (HTTP Strict Transport Security) y Diffie-Hellman de 2048 bits."
            },
            "GENERAL": "Revisar la necesidad de exposición del servicio y aplicar reglas de Firewall (ACL) para restringir el acceso por IP."
        }

    def consultar_nvd(self, banner, puerto):
        """Limpiador Heurístico de Banners para precisión en NVD"""
        query = ""
        if banner:
            match = re.search(r'([a-zA-Z\-]+)[/_ ]?([0-9]+\.[0-9]+)', banner)
            if match:
                query = f"{match.group(1)} {match.group(2)}"
        
        if not query:
            query = self.catalogo_remediacion.get(puerto, {}).get("nombre", "")

        try:
            time.sleep(0.6) 
            r = nvdlib.searchCVE(keywordSearch=query, limit=1, sortBy='publishDate')
            if r:
                score = getattr(r[0], 'v31score', getattr(r[0], 'v2score', 0.0))
                return r[0].id, score
        except: pass
        return None, None

    def procesar(self, resultados):
        for item in resultados:
            p = item['puerto']
            proto_main = item['protocolo_principal']
            protos_all = item['protocolos_activos']
            banner = item['banner']

            cve_id, nvd_score = self.consultar_nvd(banner, p)
            obsoletos = [v for v in protos_all if v in ["SSLv3", "TLSv1.0", "TLSv1.1"]]
            
            # 1. Determinación de Score
            if p == 443 and proto_main == "NOTLS":
                score_final = 9.8
            elif obsoletos:
                score_final = 7.5
            else:
                score_final = nvd_score if (nvd_score and nvd_score > 0) else 5.0

            # 2. Generación de Recomendación Inteligente
            # Si el puerto está en nuestro catálogo técnico, damos la solución experta
            if p in self.catalogo_remediacion:
                if score_final >= 7.0:
                    recom = f"URGENTE: {self.catalogo_remediacion[p]['remediacion']}"
                else:
                    recom = self.catalogo_remediacion[p]['basico']
            else:
                # Recomendación genérica para cualquier otro puerto detectado
                recom = f"Servicio detectado en puerto {p}. {self.catalogo_remediacion['GENERAL']}"

            item.update({
                "cvss": score_final,
                "cve": cve_id if cve_id else "N/A",
                "riesgo": self._categorizar(score_final),
                "recomendacion": recom,
                "protocolo_final": proto_main if proto_main != "NOTLS" else f"PLAIN-TEXT"
            })
        return resultados

    def _categorizar(self, s):
        if s >= 9.0: return "CRÍTICO"
        if s >= 7.0: return "ALTO"
        if s >= 4.0: return "MEDIO"
        return "BAJO"