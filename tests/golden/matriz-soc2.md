# Matriz de criterios SOC 2 (Trust Services Criteria)

- **Escaneo:** 01a1e65c-e279-7558-9355-5aa6612eb8fd · prowler 5.48.0 · 2026-11-17 02:56 UTC
- **Cuentas:** 123456789001 · **Metodología de riesgo:** v0.2

Borrador generado a partir del escaneo. Los criterios comunes (CC) siempre están en el alcance de un informe SOC 2; Disponibilidad, Confidencialidad, Integridad del procesamiento y Privacidad solo si la organización las incluye. **En alcance** y **Justificación** los decide la organización. Un escaneo es evidencia de un momento (sirve para un informe Tipo I); un Tipo II exige evidencia de que los controles funcionaron durante un período. "Sin brechas detectadas" no equivale a cumplimiento: solo indica que los checks automáticos no encontraron fallos.

## CC1 · Entorno de control (5)

| Criterio | Título | Estado técnico | PASS | FAIL | MANUAL | Riesgo máximo | En alcance | Justificación |
|---|---|---|---|---|---|---|---|---|
| CC1.1 | Compromiso con la integridad y los valores éticos | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| CC1.2 | Independencia y supervisión del órgano de gobierno | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| CC1.3 | Estructuras, líneas de reporte y autoridades definidas | Con brechas | 2 | 1 | 0 | Bajo |  |  |
| CC1.4 | Compromiso con la competencia del personal | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| CC1.5 | Rendición de cuentas por las responsabilidades de control | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |

## CC2 · Información y comunicación (3)

| Criterio | Título | Estado técnico | PASS | FAIL | MANUAL | Riesgo máximo | En alcance | Justificación |
|---|---|---|---|---|---|---|---|---|
| CC2.1 | Información relevante y de calidad para el control interno | Sin brechas detectadas | 1 | 0 | 0 | - |  |  |
| CC2.2 | Comunicación interna de objetivos y responsabilidades de control | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| CC2.3 | Comunicación con partes externas | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |

## CC3 · Evaluación de riesgos (4)

| Criterio | Título | Estado técnico | PASS | FAIL | MANUAL | Riesgo máximo | En alcance | Justificación |
|---|---|---|---|---|---|---|---|---|
| CC3.1 | Objetivos definidos que permiten identificar riesgos | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| CC3.2 | Identificación y análisis de riesgos | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| CC3.3 | Consideración del riesgo de fraude | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| CC3.4 | Identificación de cambios significativos | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |

## CC4 · Actividades de monitoreo (2)

| Criterio | Título | Estado técnico | PASS | FAIL | MANUAL | Riesgo máximo | En alcance | Justificación |
|---|---|---|---|---|---|---|---|---|
| CC4.1 | Evaluaciones continuas o independientes de los controles | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| CC4.2 | Comunicación oportuna de deficiencias de control | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |

## CC5 · Actividades de control (3)

| Criterio | Título | Estado técnico | PASS | FAIL | MANUAL | Riesgo máximo | En alcance | Justificación |
|---|---|---|---|---|---|---|---|---|
| CC5.1 | Selección de actividades de control que mitigan riesgos | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| CC5.2 | Controles generales sobre la tecnología | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| CC5.3 | Despliegue de controles mediante políticas y procedimientos | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |

## CC6 · Acceso lógico y físico (8)

| Criterio | Título | Estado técnico | PASS | FAIL | MANUAL | Riesgo máximo | En alcance | Justificación |
|---|---|---|---|---|---|---|---|---|
| CC6.1 | Seguridad del acceso lógico a la información y los sistemas | Sin brechas detectadas | 2 | 0 | 0 | - |  |  |
| CC6.2 | Registro y autorización de usuarios antes de dar acceso | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| CC6.3 | Gestión de accesos por roles y mínimo privilegio | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| CC6.4 | Restricción del acceso físico a instalaciones y activos | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| CC6.5 | Baja segura de activos y protección de datos al desecharlos | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| CC6.6 | Protección contra amenazas externas al perímetro | Con brechas | 17 | 1 | 0 | Medio |  |  |
| CC6.7 | Protección de la información en transmisión y movimiento | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| CC6.8 | Prevención y detección de software no autorizado o malicioso | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |

## CC7 · Operaciones del sistema (5)

| Criterio | Título | Estado técnico | PASS | FAIL | MANUAL | Riesgo máximo | En alcance | Justificación |
|---|---|---|---|---|---|---|---|---|
| CC7.1 | Detección de cambios de configuración y vulnerabilidades | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| CC7.2 | Monitoreo de componentes para detectar anomalías | Con brechas | 2 | 4 | 0 | Alto |  |  |
| CC7.3 | Evaluación de eventos de seguridad para identificar incidentes | Con brechas | 0 | 4 | 0 | Alto |  |  |
| CC7.4 | Respuesta a incidentes de seguridad | Con brechas | 0 | 2 | 0 | Alto |  |  |
| CC7.5 | Recuperación tras incidentes de seguridad | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |

## CC8 · Gestión de cambios (1)

| Criterio | Título | Estado técnico | PASS | FAIL | MANUAL | Riesgo máximo | En alcance | Justificación |
|---|---|---|---|---|---|---|---|---|
| CC8.1 | Autorización, prueba y aprobación de cambios | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |

## CC9 · Mitigación de riesgos (2)

| Criterio | Título | Estado técnico | PASS | FAIL | MANUAL | Riesgo máximo | En alcance | Justificación |
|---|---|---|---|---|---|---|---|---|
| CC9.1 | Mitigación de riesgos de interrupción del negocio | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| CC9.2 | Gestión de riesgos de proveedores y socios | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |

## A · Disponibilidad (3)

| Criterio | Título | Estado técnico | PASS | FAIL | MANUAL | Riesgo máximo | En alcance | Justificación |
|---|---|---|---|---|---|---|---|---|
| A1.1 | Gestión de la capacidad | Con brechas | 1 | 6 | 0 | Alto |  |  |
| A1.2 | Protección ambiental, respaldo e infraestructura de recuperación | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| A1.3 | Pruebas de los planes de recuperación | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |

## C · Confidencialidad (2)

| Criterio | Título | Estado técnico | PASS | FAIL | MANUAL | Riesgo máximo | En alcance | Justificación |
|---|---|---|---|---|---|---|---|---|
| C1.1 | Identificación y protección de la información confidencial | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| C1.2 | Eliminación de la información confidencial | Con brechas | 0 | 2 | 0 | Alto |  |  |

## PI · Integridad del procesamiento (5)

| Criterio | Título | Estado técnico | PASS | FAIL | MANUAL | Riesgo máximo | En alcance | Justificación |
|---|---|---|---|---|---|---|---|---|
| PI1.1 | Especificaciones del procesamiento y de los datos | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| PI1.2 | Controles sobre las entradas del sistema | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| PI1.3 | Controles sobre el procesamiento | Con brechas | 1 | 2 | 0 | Alto |  |  |
| PI1.4 | Controles sobre las salidas del sistema | Con brechas | 2 | 2 | 0 | Alto |  |  |
| PI1.5 | Almacenamiento íntegro de entradas y salidas | Con brechas | 0 | 4 | 0 | Alto |  |  |

## P · Privacidad (18)

| Criterio | Título | Estado técnico | PASS | FAIL | MANUAL | Riesgo máximo | En alcance | Justificación |
|---|---|---|---|---|---|---|---|---|
| P1.1 | Aviso de privacidad a los titulares | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| P2.1 | Opciones y consentimiento de los titulares | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| P3.1 | Recolección limitada a los objetivos de privacidad | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| P3.2 | Consentimiento explícito para los datos que lo requieren | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| P4.1 | Uso limitado a los fines informados | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| P4.2 | Conservación de los datos personales | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| P4.3 | Eliminación de los datos personales | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| P5.1 | Acceso de los titulares a sus datos | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| P5.2 | Corrección de los datos personales | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| P6.1 | Divulgación a terceros con consentimiento | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| P6.2 | Registro de las divulgaciones autorizadas | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| P6.3 | Registro de las divulgaciones no autorizadas | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| P6.4 | Compromisos de privacidad de los terceros | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| P6.5 | Notificación de incidentes por parte de los terceros | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| P6.6 | Notificación de incidentes a los titulares afectados | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| P6.7 | Información a los titulares sobre las divulgaciones | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| P7.1 | Calidad y exactitud de los datos personales | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
| P8.1 | Atención de consultas, quejas y disputas | Evidencia manual requerida | 0 | 0 | 0 | - |  |  |
