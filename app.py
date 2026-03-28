import streamlit as st
import pandas as pd
from scanner_engine import SentinelScanner
from logic_engine import RiskEvaluator
import io

# 1. Configuración de la interfaz
st.set_page_config(
    page_title="Sentinel TLS - Auditoría Proactiva",
    page_icon="🛡️",
    layout="wide"
)

# Estilos básicos
st.title("🛡️ Sentinel TLS")
st.markdown("### Sistema de Análisis de Cifrado y Gestión de Riesgo")
st.info("Herramienta de diagnóstico para protocolos de transporte y cumplimiento de estándares criptográficos.")

# --- SECCIÓN DE ENTRADA DE USUARIO ---
with st.container():
    col1, col2 = st.columns([2, 1])
    
    with col1:
        target = st.text_input("🌐 Objetivo de Auditoría (IP o Dominio):", placeholder="ej. google.com o 1.1.1.1")
    
    with col2:
        tipo_escaneo = st.selectbox(
            "🔌 Configuración de Puertos:",
            ["Rango Estándar (Top 5)", "Escaneo Completo (1-1024)", "Personalizado"]
        )

    # Lógica de puertos dinámica
    if tipo_escaneo == "Escaneo Completo (1-1024)":
        puertos_finales = list(range(1, 1025))
        st.warning("⚠️ Escaneando 1024 puertos. La tecnología de hilos mantendrá la velocidad.")
    elif tipo_escaneo == "Personalizado":
        puertos_str = st.text_input("Especifique puertos (separados por coma):", "22, 80, 443, 3306")
        try:
            puertos_finales = [int(p.strip()) for p in puertos_str.split(",") if p.strip().isdigit()]
        except:
            st.error("Formato de puertos inválido. Usando 80, 443 por defecto.")
            puertos_finales = [80, 443]
    else:
        # Puertos por defecto: SSH, HTTP, HTTPS, SMTPS, IMAPS
        puertos_finales = [22, 80, 443, 465, 993]

# --- MOTOR DE EJECUCIÓN ---
if st.button("🚀 Iniciar Auditoría Profunda"):
    if not target:
        st.warning("⚠️ Por favor ingrese un objetivo válido.")
    else:
        with st.spinner(f"Ejecutando handshakes TLS y análisis de vulnerabilidades en {target}..."):
            # 1. Inicializar Scanner (Backend de red)
            scanner = SentinelScanner(target, puertos_usuario=puertos_finales)
            
            if scanner.preparar_objetivo():
                # 2. Ejecutar escaneo concurrente
                raw_results = scanner.ejecutar_escaneo()
                
                # 3. Procesar con el motor de lógica (Análisis de Riesgo)
                evaluador = RiskEvaluator()
                data_final = evaluador.procesar(raw_results)
                
                if not data_final:
                    st.error("No se detectaron servicios activos en los puertos seleccionados.")
                else:
                    # --- DASHBOARD DE RESULTADOS ---
                    st.divider()
                    st.success(f"Análisis finalizado para: {target} ({scanner.ip})")
                    
                    # Cálculo de métricas ejecutivas
                    peor_cvss = max([d['cvss'] for d in data_final])
                    indice_salud = max(0, 100 - (peor_cvss * 10))
                    
                    m1, m2, m3 = st.columns(3)
                    m1.metric("Puntaje Máximo (CVSS)", peor_cvss)
                    m2.metric("Salud de Infraestructura", f"{int(indice_salud)}%")
                    
                    # Estado dinámico por color
                    estado = "SEGURO"
                    if peor_cvss >= 9.0: estado = "CRÍTICO"
                    elif peor_cvss >= 7.0: estado = "PELIGRO"
                    elif peor_cvss >= 4.0: estado = "ADVERTENCIA"
                    m3.metric("Estado General", estado)

                    # --- TABLA RESUMEN ---
                    st.subheader("📋 Resumen de Hallazgos")
                    df = pd.DataFrame(data_final)
                    st.dataframe(
                        df[['puerto', 'protocolo_final', 'cvss', 'riesgo', 'cve']], 
                        use_container_width=True,
                        hide_index=True
                    )

                    # --- DETALLE TÉCNICO DE 5 PILARES ---
                    st.subheader("💡 Checklist de Auditoría Técnica")
                    st.caption("Desglose detallado basado en los pilares de seguridad criptográfica.")
                    
                    # Ordenar por nivel de riesgo para mostrar lo más grave primero
                    for d in sorted(data_final, key=lambda x: x['cvss'], reverse=True):
                        # Icono por nivel de riesgo
                        icon = "🔴" if d['cvss'] >= 7.0 else ("🟡" if d['cvss'] >= 4.0 else "🟢")
                        
                        with st.expander(f"{icon} Puerto {d['puerto']} | {d['protocolo_final']} | Riesgo: {d['riesgo']}"):
                            # Separar el string de recomendaciones por el delimitador ' | '
                            puntos = d['recomendacion'].split(" | ")
                            
                            st.markdown("**Matriz de Evaluación de Seguridad:**")
                            for p in puntos:
                                st.write(f"• {p}")
                            
                            st.divider()
                            st.markdown(f"**Identificación de Banner:** `{d['banner']}`")
                            st.markdown(f"**Referencia de Vulnerabilidad:** {d['cve']}")

                    # --- EXPORTACIÓN DE EVIDENCIAS (BOTÓN CORREGIDO) ---
                    st.divider()
                    st.subheader("📥 Reporte de Salida")
                    
                    csv_buffer = io.BytesIO()
                    df.to_csv(csv_buffer, index=False, encoding='utf-8')
                    
                    st.download_button(
                        label="Descargar Reporte de Auditoría (CSV)",
                        data=csv_buffer.getvalue(),
                        file_name=f"Sentinel_Report_{target.replace('.', '_')}.csv",
                        mime="text/csv",
                        help="Descarga los resultados para gestión de incidentes o documentación técnica.",
                        key="main_download_btn"
                    )
            else:
                st.error("❌ Error de resolución: El host no responde o el dominio es inválido.")

# --- PIE DE PÁGINA ---
st.divider()
st.caption("Sentinel TLS v1.0 | Hackathon Talento Tech 2026 | Pereira, Colombia")