import json
import csv
import os
from datetime import datetime

class AuditReporter:
    def __init__(self, target):
        self.target_name = target.replace(".", "_").replace("/", "")
        self.folder = "reportes"
        if not os.path.exists(self.folder): os.makedirs(self.folder)

    def consola(self, data):
        print(f"\n[!] SENTINEL TLS - AUDITORÍA: {self.target_name}")
        print(f"{'PUERTO':<8} {'SERVICIO/PROTO':<25} {'CVSS':<6} {'CVE':<18} {'RIESGO'}")
        print("-" * 85)
        for d in data:
            print(f"{d['puerto']:<8} {d['protocolo_final']:<25} {d['cvss']:<6} {d['cve']:<18} {d['riesgo']}")

    def guardar_formatos(self, data):
        # 1. Cálculo de Índice de Salud
        peor_hallazgo = max([d['cvss'] for d in data]) if data else 0
        salud = max(0, 100 - (sum([d['cvss'] for d in data]) * 3))
        estado = "CRÍTICO" if peor_hallazgo >= 9.0 else ("RIESGO" if peor_hallazgo >= 7.0 else "ESTABLE")

        # 2. Generar JSON
        reporte_json = {
            "metadata": {"objetivo": self.target_name, "fecha": datetime.now().isoformat()},
            "evaluacion_ejecutiva": {"salud": f"{int(salud)}/100", "estado": estado},
            "plan_remediacion": [f"Puerto {d['puerto']}: {d['recomendacion']}" for d in sorted(data, key=lambda x: x['cvss'], reverse=True)],
            "hallazgos": data
        }
        with open(os.path.join(self.folder, f"audit_{self.target_name}.json"), "w", encoding="utf-8") as f:
            json.dump(reporte_json, f, indent=4, ensure_ascii=False)

        # 3. Generar CSV (Para la Rúbrica)
        with open(os.path.join(self.folder, f"audit_{self.target_name}.csv"), "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Puerto", "Protocolo", "CVSS", "CVE", "Riesgo", "Recomendacion"])
            for d in data:
                writer.writerow([d['puerto'], d['protocolo_final'], d['cvss'], d['cve'], d['riesgo'], d['recomendacion']])
        
        print(f"\n[+] Reportes generados en la carpeta '{self.folder}' (JSON y CSV)")