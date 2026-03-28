# 🛡️ Sentinel TLS + Groq AI Auditor

**Sentinel TLS** es una herramienta de auditoría de red automatizada diseñada para identificar servicios abiertos, evaluar la seguridad de los protocolos criptográficos (TLS/SSL) y proporcionar recomendaciones técnicas y normativas basadas en inteligencia artificial.

Desarrollado para la facultad de Ingeniería de Sistemas - Universidad Libre, Seccional Pereira.

## 🚀 Características Principales

* **Escaneo Multi-Objetivo:** Permite auditar múltiples IPs o dominios simultáneamente separados por comas.
* **Análisis de Certificados:** Extrae la versión del protocolo TLS y la fecha de expiración de los certificados de seguridad.
* **Cerebro de IA (Groq):** Utiliza el modelo `Llama-3.1-8b-instant` para generar diagnósticos técnicos precisos.
* **Enfoque Normativo:** Las recomendaciones incluyen referencias directas a controles de **ISO 27001** y **NIST SP 800-53**.
* **Reportes Profesionales:** Generación de archivos PDF con semáforo de riesgo (colores dinámicos según la severidad CVSS).

## 🛠️ Requisitos Previos

Antes de iniciar, asegúrate de tener instalado:
* Python 3.9 o superior.
* Una API Key de Groq (Obtenla gratis en [console.groq.com](https://console.groq.com/)).

## 📦 Instalación

1. **Clonar o descargar el proyecto** en una carpeta local.
2. **Instalar las dependencias** necesarias usando el archivo de requerimientos:
   ```bash
   pip install -r requirements.txt
