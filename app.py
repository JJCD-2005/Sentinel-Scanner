import streamlit as st
import pandas as pd
from scanner_engine import SentinelScanner
from logic_engine import RiskEvaluator

# Configuración de página sencilla
st.set_page_config(page_title="Sentinel TLS", page_icon="🛡️")

st.title("🛡️ Sentinel TLS")
st.markdown("### Sistema de Análisis de Riesgo y Configuración TLS")

# Entrada de usuario
target = st.text_input("Ingrese IP o Dominio a analizar:", placeholder="ej. google.com")

if st.button("Iniciar Auditoría"):
    if target:
        with st.spinner(f"Analizando {target}..."):
            # 1. Escaneo
            scanner = SentinelScanner(target)
            if scanner.preparar_objetivo():
                raw_data = scanner.ejecutar_escaneo()
                
                # 2. Evaluación de Riesgo
                evaluador = RiskEvaluator()
                data = evaluador.procesar(raw_data)
                
                # 3. Mostrar Resultados
                st.success("Análisis Completado")
                
                # Resumen Ejecutivo
                peor_riesgo = max([d['cvss'] for d in data]) if data else 0
                col1, col2 = st.columns(2)
                col1.metric("Peor CVSS detectado", peor_riesgo)
                col2.metric("Estado", "CRÍTICO" if peor_riesgo >= 9.0 else "ESTABLE")

                # Tabla de Hallazgos
                st.subheader("📋 Hallazgos Técnicos")
                df = pd.DataFrame(data)
                # Seleccionamos solo lo más importante para la vista simple
                st.table(df[['puerto', 'protocolo_final', 'cvss', 'riesgo', 'cve']])

                # Recomendaciones Dinámicas
                st.subheader("💡 Plan de Acción")
                for d in sorted(data, key=lambda x: x['cvss'], reverse=True):
                    with st.expander(f"Puerto {d['puerto']} - {d['riesgo']}"):
                        st.write(f"**Recomendación:** {d['recomendacion']}")
            else:
                st.error("No se pudo resolver el host.")
    else:
        st.warning("Por favor, ingrese un objetivo válido.")