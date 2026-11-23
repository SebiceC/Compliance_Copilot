# Hoja de ruta a la versión 1.0

La v1.0 cumple el alcance que promete el README: **AWS y Azure**, con entregables para **ISO 27001:2022, SOC 2,
NIST CSF 2.0 y Ley 1581 de 2012**. Hoy están completos AWS e ISO 27001 (Fases 0 a 5).

Cada fase termina con: código y tests (Claude los genera cuando se le piden), documentación y ADR, verificación
con un escaneo real y un PR fusionado con el check `tests` en verde. La infraestructura y las conexiones (AWS,
Azure, GitHub) las configura Sebastian.

| Fase | Qué | Por qué en este orden |
|---|---|---|
| 6 | Base común para varios marcos y cierres pendientes | SOC 2, NIST y Ley 1581 reutilizan lo mismo; se construye una vez |
| 7 | SOC 2 | Los datos ya vienen en la salida de Prowler; es el marco más directo |
| 8 | NIST CSF 2.0 | Igual de directo, pero el mapeo de Prowler necesita corrección (ver abajo) |
| 9 | Ley 1581 de 2012 | Mapeo propio: no lo trae Prowler. Usa la base de las fases 6 a 8 |
| 10 | Azure | El cambio más grande: laboratorio, credenciales, parser, riesgo y CI |
| 11 | Calibración de la metodología v0.3 | Con datos de las dos nubes; calibrar antes de Azure obligaría a repetirlo |
| 12 | Cierre de la v1.0 | README, versión, escaneos finales firmados, tag y release |

---

## Fase 6. Base común

**Objetivo:** que agregar un marco sea agregar un catálogo, no reescribir los entregables.

| # | Paso | Quién |
|---|---|---|
| 6.1 | ✅ Registro de riesgos; retención del escaneo 5 verificada; repo endurecido (secret scanning, push protection, Dependabot alerts) | Tú |
| 6.2 | ✅ **Tag Policy** en AWS Organizations para `data-classification` (valores permitidos, en minúscula) y `project`. Pasa de detectar tags mal escritos a impedirlos | Tú, con guía |
| 6.3 | ✅ **Dependabot** (`.github/dependabot.yml`) para las acciones fijadas por hash y las dependencias de Python | Yo |
| 6.4 | ✅ Generalizar los catálogos: `load_catalog(marco)` para varios marcos, con un modelo `Requirement` común (id, título, agrupación) | Yo |
| 6.5 | ✅ Generalizar la SoA a una **declaración por marco**: misma lógica de estado técnico (con brechas, requiere revisión, sin brechas, evidencia manual), una hoja/archivo por marco | Yo |
| 6.6 | ✅ Normalizar los IDs de Prowler al formato oficial de cada marco, con un test que falle si aparece un ID que no está en el catálogo (hallazgo "sin mapeo" en vez de perderse, como en el ADR 0003) | Yo |
| 6.7 | ✅ **ADR 0007:** cómo se agregan marcos (catálogo propio, normalización, qué entregable corresponde a cada marco) | Yo |

**Terminado cuando:** los entregables de ISO 27001 salen idénticos a los de hoy (test de regresión) y el código
ya no tiene `ISO27001-2022` fijo fuera del catálogo.

## Fase 7. SOC 2

**Contexto:** SOC 2 no tiene SoA. El auditor evalúa los **Trust Services Criteria** (TSC) de AICPA: los comunes
(CC1 a CC9) y, según el alcance, Disponibilidad (A), Confidencialidad (C), Integridad del procesamiento (PI) y
Privacidad (P). El texto de los TSC tiene derechos de AICPA: igual que con ISO, solo identificadores y títulos
propios.

| # | Paso | Quién |
|---|---|---|
| 7.1 | ✅ Catálogo `soc2-tsc.json` con IDs oficiales (`CC6.1`, `A1.1`, `C1.2`, `PI1.2`…) y títulos propios en español | Yo, tú revisas |
| 7.2 | ✅ Normalización de Prowler: `cc_6_1` → `CC6.1`, `cc_a_1_1` → `A1.1`, `cc_c_1_2` → `C1.2`, `pi_1_2` → `PI1.2` | Yo |
| 7.3 | ✅ Entregable **Matriz de criterios SOC 2** (.md y hoja de Excel): por criterio, hallazgos, estado técnico y columnas para la decisión humana (en alcance, justificación) | Yo |
| 7.4 | ✅ Evidencia por criterio en el paquete (`evidencias/controles/SOC2/`), cubierta por el manifest | Yo |
| 7.5 | ✅ Documentar el límite **Tipo I / Tipo II**: un escaneo es evidencia de un momento (Tipo I); el Tipo II exige evidencia de funcionamiento durante un período, que darían escaneos periódicos (ver Fase 12, escaneo programado) | Yo |
| 7.6 | ✅ Escaneo desde CI y revisión de la matriz | Tú |

## Fase 8. NIST CSF 2.0

**Hallazgo al preparar esta fase:** el mapeo "NIST CSF 2.0" de Prowler 5.48 (AWS) mezcla categorías de la versión
1.1 que ya no existen en la 2.0 (por ejemplo `ac_1` = PR.AC, `ip_1` = PR.IP, `be_5` = ID.BE, `pt_1` = PR.PT,
`dp_4` = DE.DP) con categorías nuevas de la 2.0 (GV.OV, GV.RR…). Usarlo tal cual produciría un perfil con
subcategorías inexistentes.

| # | Paso | Quién |
|---|---|---|
| 8.1 | ✅ Catálogo `nist-csf-2.0.json`: 6 funciones, 22 categorías y 106 subcategorías (`GV.OC-01`…). El CSF es de NIST (gobierno de EE. UU.): se pueden usar sus títulos; verificar si existe traducción oficial al español, y si no, títulos propios | Yo |
| 8.2 | ✅ **Tabla de correspondencia** de los IDs de Prowler a subcategorías 2.0, basada en la correspondencia oficial 1.1 → 2.0 publicada por NIST. Cada ID de 1.1 se traduce o queda "sin correspondencia" (reportado, no descartado) | Yo, tú revisas |
| 8.3 | ✅ Entregable **Perfil actual NIST CSF 2.0**: por subcategoría, estado técnico; columnas para el perfil objetivo y la prioridad (decisión humana) | Yo |
| 8.4 | ✅ Evidencia por subcategoría en el paquete | Yo |
| 8.5 | ✅ Reportada en [prowler-cloud/prowler#13504](https://github.com/prowler-cloud/prowler/issues/13504). Documentar la discrepancia de Prowler en el ADR 0007 y evaluar reportarla al proyecto Prowler (issue público) | Tú decides |
| 8.6 | ✅ Escaneo desde CI y revisión del perfil | Tú |

## Fase 9. Ley 1581 de 2012

**Contexto:** Prowler no la mapea. Es una ley de protección de datos personales, no un marco de controles: la
herramienta solo puede evidenciar su **parte técnica**. Es la fase con más criterio propio, y la que más conecta
con el perfil de privacidad del proyecto.

| # | Paso | Quién |
|---|---|---|
| 9.1 | ✅ Delimitar el alcance normativo: Ley 1581 de 2012, Decreto 1377 de 2013 (compilado en el Decreto 1074 de 2015) y la Guía de Responsabilidad Demostrada de la SIC. Decidir qué obligaciones entran | **Tú** (criterio jurídico) |
| 9.2 | ✅ Catálogo de **obligaciones evaluables técnicamente**, por ejemplo: principio de seguridad (art. 4 lit. g), confidencialidad (lit. h), acceso y circulación restringida (lit. f), deber de conservar la información en condiciones de seguridad (art. 17 lit. d; art. 18 para el encargado), transferencias internacionales (art. 26) | Tú defines, yo estructuro |
| 9.3 | ✅ **Metodología de mapeo** (`docs/metodologia-ley-1581.md`): hallazgo técnico → control ISO 27001 → obligación de la ley. Prowler trae un mapeo a GDPR (art. 25, 30 y 32) que sirve de referencia, no de fuente | Tú decides, yo redacto |
| 9.4 | ✅ Regla propia de **circulación internacional**: recursos con `personal-data=yes` en regiones fuera de Colombia se señalan para revisión, como transmisión por defecto (Decreto 1377, art. 25) y con la transferencia (art. 26) como alternativa. Se usa el tag `personal-data`, no la clasificación: ver ADR 0008 | Yo |
| 9.5 | ✅ Entregable **Matriz técnica Ley 1581**: por obligación, hallazgos, estado y la evidencia manual requerida (autorización, finalidades, política de tratamiento, registro ante el RNBD, que la herramienta no puede ver) | Yo |
| 9.6 | ✅ **ADR 0008:** por qué un mapeo indirecto vía ISO y no directo, y sus límites | Yo |
| 9.7 | Revisión de la matriz como experto en privacidad: ¿un abogado o un auditor de la SIC aceptaría este mapeo? | Tú |

## Fase 10. Azure

La fase más grande. Repite para Azure lo que las Fases 0, 1, 2 y 5 hicieron para AWS.

### 10a. Laboratorio (tú)

| # | Paso |
|---|---|
| 10.1 | Diagnosticar "No subscriptions found": casi siempre es una cuenta sin suscripción activa o una identidad sin rol sobre la suscripción |
| 10.2 | Suscripción de laboratorio (gratuita o pago por uso) con **alerta de presupuesto** baja |
| 10.3 | Identidad de escaneo con mínimo privilegio: rol **Reader** sobre la suscripción y los permisos de Microsoft Graph de solo lectura que pide Prowler (verificar la lista en su documentación) |
| 10.4 | Recursos con debilidades deliberadas y costo cero o centavos, con tags `data-classification` y `project`; por ejemplo: storage account que permite acceso público a blobs, NSG con SSH abierto a Internet, Key Vault sin protección de purga. Documentar en `docs/laboratorio.md` como se hizo con AWS |
| 10.5 | Primer escaneo local: `prowler azure --az-cli-auth` con salida `json-ocsf` |

### 10b. Código (yo)

| # | Paso |
|---|---|
| 10.6 | Verificar qué marcos mapea Prowler para Azure (ISO 27001:2022, SOC 2, NIST CSF 2.0) y con qué formato de IDs |
| 10.7 | Parser multiproveedor: suscripción como cuenta, `location` como región, tipos de recurso de Azure, formato de tags |
| 10.8 | Anonimizador para Azure: IDs de suscripción y de tenant (GUID), object IDs, UPN y correos, nombres de recursos |
| 10.9 | Motor de riesgo: tipos de recurso de datos de Azure (storage, SQL, Cosmos DB, Key Vault), checks de privilegio administrativo de Azure, categoría de exposición a Internet |
| 10.10 | Muestra anonimizada `data/samples/prowler-azure-lab.ocsf.json` y tests equivalentes a los de AWS |
| 10.11 | Entregables con las dos nubes: un informe por escaneo, que indica el proveedor |

### 10c. CI sin secretos (tú configuras, yo escribo el workflow)

| # | Paso |
|---|---|
| 10.12 | App en Entra ID con **credencial federada** para GitHub (el equivalente de OIDC en Azure), restringida a `repo:…:environment:azure-lab` |
| 10.13 | Environment `azure-lab` con revisor obligatorio; secretos de cliente, tenant y suscripción (no son credenciales, solo identificadores) |
| 10.14 | Job de escaneo de Azure en `scan.yml` (`azure/login` fijado por hash), mismas reglas de logs públicos y la misma firma del manifest |
| 10.15 | Dónde guardar la evidencia de Azure: el mismo bucket de AWS (más simple) o una storage account con inmutabilidad (simétrico). Decisión tuya, en el ADR |
| 10.16 | **ADR 0009:** federación de identidades en Azure |

## Fase 11. Calibración de la metodología v0.3

| # | Paso | Quién |
|---|---|---|
| 11.1 | Analizar la distribución de riesgos de las dos nubes (hoy 63 de 113 son altos en AWS) | Yo |
| 11.2 | Proponer ajustes (pesos de severidad, modificadores de impacto, umbrales de niveles) con ejemplos de antes y después | Yo |
| 11.3 | Validar el supuesto "el dueño del activo clasifica" y documentar quién asigna `data-classification` | Tú |
| 11.4 | Aprobar, actualizar `docs/metodologia-riesgo.md` a v0.3 y el test de sincronía documento-código | Tú apruebas, yo actualizo |

## Fase 12. Cierre de la v1.0

| # | Paso | Quién |
|---|---|---|
| 12.1 | Escaneo programado: decidir cómo convive con el revisor obligatorio (por ejemplo, un Environment distinto para la ejecución programada) y actualizar el ADR 0006 | Tú decides |
| 12.2 | Política de versiones de Prowler (hoy fijo en 5.48.0): cada cuánto se actualiza y cómo se comprueba que no cambia los resultados | Tú decides, yo documento |
| 12.3 | Pendientes menores: asteriscos de markdown en el Excel; quitar "en construcción" del README | Yo |
| 12.4 | README final: qué hace, capacidades (todas listas), arquitectura, cómo correrlo de punta a punta, límites | Yo |
| 12.5 | `CHANGELOG.md` y versión `1.0.0` en `pyproject.toml` | Yo |
| 12.6 | Escaneos finales de AWS y Azure desde CI, con entregables de los cuatro marcos, `verify` y firma verificados | Tú |
| 12.7 | Tag `v1.0.0` y GitHub Release con el resumen de capacidades y los ADR | Tú |

**Definición de terminado de la v1.0:**

- Las cuatro filas de capacidades del README dicen "listo", sin excepciones.
- Escaneos de AWS y Azure desde CI, sin llaves de larga duración, con evidencia íntegra y firmada.
- Entregables de ISO 27001:2022, SOC 2, NIST CSF 2.0 y Ley 1581 generados a partir de esos escaneos.
- Todo el código con tests en verde; cada decisión de diseño con su ADR.
- Ningún dato real en el repo (revisión del historial antes del tag).

## Fuera de la v1.0

Quedan para después, en la sección de hoja de ruta del README: el conjunto de evaluación de la redacción con IA
(ADR 0004 y 0005), la redacción de hallazgos con criterio de SOC 2 / NIST / Ley 1581 (en la v1.0 la IA cita ISO
27001), y la revisión de R-05 (logs de acceso del bucket de evidencias).
