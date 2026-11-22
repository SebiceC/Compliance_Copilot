# Laboratorio de demostración

Cuenta AWS propia con **debilidades deliberadas y de costo cero** para que el escaneo de Prowler produzca
hallazgos reproducibles. Ningún recurso contiene datos reales.

## Requisitos del entorno

| Requisito | Detalle |
|---|---|
| Región | `us-east-1` (todos los recursos del laboratorio) |
| Perfil para crear el laboratorio | `cc-lab` (permission set `LabAdmin`) |
| Perfil para escanear | `cc-audit` (permission set `ProwlerAudit`: `SecurityAudit` + `ViewOnlyAccess`) |
| Escaneo desde CI | Rol IAM `GitHubActionsProwler` (OIDC desde GitHub Actions, mismos permisos de lectura); ver `docs/ci.md` |
| Windows: rutas largas | `LongPathsEnabled = 1` en el registro; sin esto, la instalación de Prowler falla por las rutas del SDK de Microsoft Graph |
| Windows: codificación | Variable de entorno de usuario `PYTHONUTF8=1`; sin esto, Prowler falla con `UnicodeEncodeError` (cp1252) al redirigir su salida a un pipe o archivo |
| Tags comunes | `project=compliance-copilot` en todos los recursos |

## Recursos

Cada recurso lleva un tag `data-classification` distinto, para que la demo recorra toda la escala de impacto
(ver `docs/metodologia-riesgo.md`). Los valores se escriben en minúscula y exactamente así: `public`,
`internal`, `confidential`, `restricted`.

> Los identificadores de cuenta se muestran como `<ACCOUNT_ID>`. Este documento es público y no debe exponer
> datos reales de la cuenta.

| # | Recurso | Nombre | Debilidad | `data-classification` | Check de Prowler esperado | Estado |
|---|---|---|---|---|---|---|
| 1 | Usuario IAM | `lab-user-nomfa` | Acceso a consola sin MFA | `internal` | `iam_user_mfa_enabled_console_access` (high) | creado |
| 2 | Security group | `lab-sg-ssh-open` | Ingreso TCP 22 desde `0.0.0.0/0` | `public` | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22` (high) | creado |
| 3 | Bucket S3 | `cc-lab-data-7asda3` | Versionado deshabilitado | `confidential` | `s3_bucket_object_versioning` (medium) | creado |
| 4 | Trail de CloudTrail | `lab-trail` | Validación de archivos de log deshabilitada | `restricted` | `cloudtrail_log_file_validation_enabled` (medium) | creado |
| 4b | Bucket de logs de CloudTrail | `aws-cloudtrail-logs-<ACCOUNT_ID>-<sufijo>` | (creado por CloudTrail) | `restricted` | — | creado |

**Por qué cada clasificación** (escenario simulado; criterios en `docs/metodologia-riesgo.md`):

- **Security group → `public`:** estaría delante de un servidor web público. El puerto abierto sube la
  *probabilidad*, no el impacto: el impacto depende de lo que hay detrás.
- **Usuario IAM → `internal`:** cuenta de empleado con acceso a herramientas internas; sin políticas adjuntas.
- **Bucket S3 → `confidential`:** guardaría una base de clientes con datos personales comunes.
- **CloudTrail → `restricted`:** es evidencia de auditoría; su alteración sin detección destruye la
  trazabilidad forense. El bucket que crea CloudTrail para los logs lleva la misma clasificación.

## Detalle de creación

Todos los recursos se crearon desde la consola web con el rol `LabAdmin`, en `us-east-1`, el 2026-11-11.

### 1. Usuario IAM sin MFA

- **Cómo se creó:** IAM → Users → Create user. Con acceso a la consola como usuario IAM (no Identity Center),
  contraseña aleatoria, sin políticas adjuntas y sin dispositivo MFA.
- **Por qué es costo cero:** los usuarios IAM no tienen costo.
- **Controles mitigantes del laboratorio:** sin políticas adjuntas; contraseña aleatoria no reutilizada; no
  se usa para iniciar sesión.

### 2. Security group con SSH abierto

- **Cómo se creó:** EC2 → Security Groups → Create security group, en la VPC por defecto. Regla de entrada
  SSH (TCP 22) desde `0.0.0.0/0`; reglas de salida por defecto.
- **Por qué es costo cero:** los security groups no tienen costo y este no está asociado a ninguna instancia.
- **Nota para el escaneo:** Prowler puede omitir por defecto los recursos que no están en uso. Si este check
  no aparece en el resultado, revisar la opción de escaneo de servicios no usados en `prowler aws --help`.

### 3. Bucket S3 sin versionado

- **Cómo se creó:** S3 → Create bucket (General purpose). ACLs deshabilitadas, Block Public Access activo,
  versionado deshabilitado, cifrado por defecto SSE-S3. Vacío.
- **Por qué es costo cero:** el bucket está vacío.
- **Controles mitigantes del laboratorio:** Block Public Access activo.

### 4. CloudTrail sin validación de logs

- **Cómo se creó:** CloudTrail → Trails → Create trail. Solo para esta cuenta (no para toda la organización),
  con un bucket S3 nuevo para los logs, sin SSE-KMS, sin validación de archivos de log, sin SNS y sin
  CloudWatch Logs. Eventos: solo management events (lectura y escritura). El bucket de logs se etiquetó
  manualmente después de crearlo.
- **Por qué es costo cero:** el primer trail de eventos de gestión es gratuito; sin cifrado SSE-KMS
  (una llave KMS cuesta por mes), sin CloudWatch Logs, sin data events ni Insights. El bucket de logs acumula
  pocos datos (centavos al mes como máximo).
- **Nota:** el bucket que crea CloudTrail para los logs genera hallazgos adicionales propios.

## Hallazgos adicionales esperados

Prowler reportará más fallos de los cuatro diseñados (por ejemplo, política de contraseñas, configuración de
la cuenta o el propio bucket de CloudTrail). Se registran aquí los relevantes tras el primer escaneo.

Previstos a partir de la lista de checks (severidad entre paréntesis):

| Check | Recurso | Por qué falla |
|---|---|---|
| `iam_user_hardware_mfa_enabled` (high) | `lab-user-nomfa` | No tiene ningún MFA, tampoco de hardware |
| `s3_bucket_object_versioning` (medium) | Bucket de logs de CloudTrail | CloudTrail lo crea sin versionado |
| `s3_bucket_no_mfa_delete` (medium) | Ambos buckets | MFA Delete requiere versionado y credenciales root |
| `cloudtrail_bucket_requires_mfa_delete` (medium) | Bucket de logs de CloudTrail | Igual que el anterior |

Todos los previstos se confirmaron como FAIL en el primer escaneo. Además aparecieron:

| Check | Recurso | Observación |
|---|---|---|
| `ec2_securitygroup_not_used` (low) | `lab-sg-ssh-open` | Esperado: el security group no está asociado a ninguna instancia |
| `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22` | 9 security groups `launch-wizard-N` | **No forman parte del laboratorio:** quedaron de pruebas anteriores con instancias EC2 (ya no hay instancias). **Eliminados el 2026-11-16** |
| Varios de S3 | Segundo bucket `aws-cloudtrail-logs-<ACCOUNT_ID>-<sufijo>` | **Bucket huérfano:** no estaba asociado a `lab-trail`. **Eliminado el 2026-11-16** |

**Arreglos tras el primer escaneo (2026-11-16):** se eliminaron los recursos ajenos al laboratorio y se etiquetó
el bucket de logs de `lab-trail` (ver la última observación de la sección siguiente). La cuenta quedó con los
recursos de la tabla de arriba más el security group `default` de la VPC.

## Resultado del primer escaneo

- **Fecha:** 2026-11-16
- **Perfil:** `cc-audit` · **Región:** `us-east-1` · **Duración:** ~4 min
- **Comando:** `prowler aws --profile cc-audit -f us-east-1 --scan-unused-services -M csv json-ocsf -o output`
- **Totales:** 665 checks ejecutados · 447 resultados · **150 FAIL** · 292 PASS · 0 muted
- **Marcos que usará el proyecto:** `ISO27001_2022_AWS` 110 FAIL / 243 PASS · `SOC2_AWS` 60 FAIL / 215 PASS ·
  `NIST_CSF_2.0_AWS` 90 FAIL / 141 PASS

| # | Check esperado | Recurso | Resultado | Tags leídos por Prowler |
|---|---|---|---|---|
| 1 | `iam_user_mfa_enabled_console_access` | `lab-user-nomfa` | ✅ FAIL | `data-classification=internal`, `project=compliance-copilot` |
| 2 | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22` | `lab-sg-ssh-open` | ✅ FAIL | (Prowler reporta el ID `sg-…` como nombre del recurso) |
| 3 | `s3_bucket_object_versioning` | `cc-lab-data-7asda3` | ✅ FAIL | `data-classification=confidential`, `project=compliance-copilot` |
| 4 | `cloudtrail_log_file_validation_enabled` | `lab-trail` | ✅ FAIL | `data-classification=restricted`, `project=compliance-copilot` |

**Observaciones para la Fase 1:**

- Prowler **sí exporta los tags** de cada recurso (columna `RESOURCE_TAGS` del CSV), con el formato
  `clave=valor | clave=valor`. Es la entrada del cálculo de impacto.
- En los security groups, el nombre del recurso es el ID (`sg-…`); el nombre legible solo aparece en el texto
  del estado.
- **El bucket de logs de `lab-trail` salió sin tags.** Se le aplicaron `data-classification=restricted` y
  `project=compliance-copilot` el 2026-11-16; sin ellos, el motor lo habría tratado como "sin clasificar".
  Pendiente: un segundo escaneo que confirme los arreglos y sirva de entrada para la Fase 1.
- Los nombres de archivo y varias columnas incluyen el **ID de cuenta**: confirma la necesidad del anonimizador.

## Segundo escaneo (tras los arreglos)

- **Fecha:** 2026-11-16 · mismo comando, perfil y región que el primero · ~4 min
- **Totales:** 232 resultados · **114 FAIL** · 113 PASS · 0 muted (antes: 447 · 150 · 292)
- **Marcos que usará el proyecto:** `ISO27001_2022_AWS` 78 FAIL / 78 PASS · `SOC2_AWS` 47 FAIL / 60 PASS ·
  `NIST_CSF_2.0_AWS` 67 FAIL / 71 PASS
- **Los 4 FAIL diseñados se mantienen**, ahora con los tags correctos también en el bucket de logs.
- **Por qué bajó el total:** desaparecieron 215 resultados (36 FAIL y 179 PASS), todos de los 9 security groups
  y del bucket huérfano eliminados. No apareció ningún FAIL nuevo y ningún recurso existente perdió resultados.
  Menos PASS no significa peor postura: cada recurso borrado dejó de aportar sus propios checks.

**Hallazgo fuera del laboratorio.** Existe un usuario IAM creado antes del proyecto, con **`AdministratorAccess`**,
contraseña de consola **sin MFA** y sin iniciar sesión hace más de 400 días (`iam_user_administrator_access_policy`,
critical; `iam_user_mfa_enabled_console_access`, high; `iam_user_console_access_unused`, medium). No es una
debilidad diseñada: es un riesgo real de la cuenta. **Eliminado el 2026-11-16**; el único usuario IAM que queda
es `lab-user-nomfa`. El acceso administrativo se hace solo por IAM Identity Center (`LabAdmin`), con MFA.

## Recursos del pipeline de CI (Fase 5)

No son debilidades del laboratorio: son la infraestructura del escaneo desde GitHub Actions
([ADR 0006](adr/0006-ci-con-oidc-sin-llaves.md)). Creados el 2026-11-21 desde la consola con `LabAdmin`.

| Recurso | Nombre | Para qué | Costo |
|---|---|---|---|
| Proveedor de identidad OIDC | `token.actions.githubusercontent.com` | Que AWS confíe en los tokens que firma GitHub | Gratis |
| Bucket S3 | `compliance-copilot-evidence-<sufijo>` | Paquetes de evidencia de cada escaneo: sin acceso público, SSE-S3, solo TLS, borrado a 30 días | Centavos (pocos MB que expiran) |
| Rol IAM | `GitHubActionsProwler` | `SecurityAudit` + `ViewOnlyAccess` + `s3:PutObject` en `scans/*`; confía solo en el Environment `aws-lab` | Gratis |

**Lecciones de la configuración:**

- El asistente de *Identidad web* de la consola generó una confianza con comodín
  (`StringLike` sobre `repo:SebiceC/Compliance_Copilot:*`), más amplia de lo pedido. Se reemplazó por
  `StringEquals` sobre el Environment. Solo la verificación posterior lo mostró.
- El primer escaneo desde CI fue rechazado (`Not authorized to perform sts:AssumeRoleWithWebIdentity`).
  CloudTrail mostró el `sub` real del token: GitHub incluye los IDs inmutables del dueño y del repo
  (`repo:SebiceC@<id>/Compliance_Copilot@<id>:environment:aws-lab`). Se corrigió la condición del rol.
- La primera regla de ciclo de vida usaba la acción de versiones *no actuales*; con el versionado deshabilitado
  no habría borrado nada. Se cambió a vencer las versiones actuales.

## Escaneos desde GitHub Actions (Fase 5)

Dos escaneos con `scan.yml` (Prowler 5.48.0, mismo comando que los locales), aprobados manualmente en el
Environment `aws-lab`. Unos 5 minutos cada uno, incluida la instalación.

| | Escaneo 3 | Escaneo 4 |
|---|---|---|
| Fecha (UTC) | 2026-11-22 02:33 | 2026-11-22 03:13 |
| Commit de `scan.yml` | `838a837` | `a79fe0b` |
| Resultados | 248 · **116 FAIL** · 127 PASS · 5 MANUAL | 248 · **115 FAIL** · 128 PASS · 5 MANUAL |
| Riesgos | 116: 2 crítico, 60 alto, 52 medio, 2 bajo | 115: 2 crítico, 60 alto, 51 medio, 2 bajo |
| `verify` (integridad) | ✅ | ✅ |
| Firma del manifest (origen) | ❌ sin firma: `gh attestation verify` responde 404 | ✅ `gh attestation verify` |

El escaneo 3 queda como **prueba negativa**: un manifest íntegro pero sin firma no pasa la verificación de
origen.

**Diferencias con el segundo escaneo (114 FAIL), todas explicadas:**

| Cambio | Checks | Causa |
|---|---|---|
| −1 FAIL cada uno | `iam_user_administrator_access_policy` (critical), `iam_user_mfa_enabled_console_access`, `iam_user_hardware_mfa_enabled`, `iam_user_console_access_unused`, `iam_user_access_not_stale_to_bedrock`, `iam_policy_attached_only_to_group_or_roles` | Usuario administrador previo al proyecto, eliminado el 2026-11-16 |
| +1 FAIL cada uno | `s3_bucket_object_versioning`, `s3_bucket_object_lock`, `s3_bucket_no_mfa_delete`, `s3_bucket_kms_encryption`, `s3_bucket_server_access_logging_enabled`, `s3_bucket_cross_region_replication`, `s3_bucket_event_notifications_enabled` | Bucket de evidencias nuevo |
| +1 FAIL solo en el escaneo 3 | `iam_role_access_not_stale_to_bedrock` | Rol `GitHubActionsProwler` recién creado; en el escaneo 4 ya no aparece |

Los +16 resultados totales (232 → 248) son los checks del bucket, del rol y de su política nueva.

**Pendiente (tratamiento de riesgos):**

<<<<<<< Updated upstream
- **Brechas del bucket de evidencias.** Decidir cuáles se aceptan por ser un laboratorio (KMS, replicación,
  notificaciones, logs de acceso) y cuáles se remedian por tratarse de evidencia: versionado y Object Lock la
  harían inmutable (hoy el rol de CI no puede borrar, pero un administrador sí).
- **Clasificación.** El bucket de evidencias y el rol no tienen tags, así que el motor los marca para el control
  A.5.12. Propuesto: `data-classification=restricted` para el bucket (es evidencia de auditoría, como
  CloudTrail) y `project=compliance-copilot` en ambos.
=======
**Tag Policy (2026-11-22).** Política `etiquetas-compliance-copilot` en AWS Organizations: la clave
`data-classification` solo admite `public`, `internal`, `confidential` y `restricted` (en minúscula), y `project`
solo `compliance-copilot`. En los buckets de S3 se **aplica** (rechaza el etiquetado incorrecto); en el resto se
reporta. Probada con la prueba negativa: etiquetar un bucket con `Confidential` fue rechazado. No obliga a poner
el tag: un recurso sin clasificar lo sigue detectando el motor de riesgo (A.5.12). Control preventivo más
control detectivo.

**Tratamiento de riesgos:** las 7 brechas del bucket de evidencias tienen decisión documentada en
[docs/tratamiento-riesgos.md](tratamiento-riesgos.md) (R-01 a R-07: mitigar versionado y Object Lock, aceptar
las otras cinco). El bucket se etiquetó `data-classification=restricted` y `project=compliance-copilot`; el rol,
`project=compliance-copilot` (es inventario: un rol no guarda datos y no entra en el control A.5.12).
>>>>>>> Stashed changes

## Desmontaje

Desde la consola con el rol `LabAdmin`, en `us-east-1`. El orden importa: primero se detiene CloudTrail
para que deje de escribir en su bucket.

1. **CloudTrail:** Trails → `lab-trail` → Delete.
2. **Bucket de logs de CloudTrail:** S3 → `aws-cloudtrail-logs-<ACCOUNT_ID>-<sufijo>` → Empty → Delete.
3. **Bucket de datos:** S3 → `cc-lab-data-7asda3` → Empty (si tiene objetos) → Delete.
4. **Security group:** EC2 → Security Groups → `lab-sg-ssh-open` → Actions → Delete security groups.
5. **Usuario IAM:** IAM → Users → `lab-user-nomfa` → Delete.

Recursos del pipeline de CI (solo si se abandona el escaneo desde GitHub Actions):

6. **Rol:** IAM → Roles → `GitHubActionsProwler` → Delete.
7. **Bucket de evidencias:** S3 → `compliance-copilot-evidence-<sufijo>` → Empty → Delete.
8. **Proveedor OIDC:** IAM → Identity providers → `token.actions.githubusercontent.com` → Delete.
9. En GitHub: borrar el Environment `aws-lab` (y con él sus secretos).

Verificación: buscar en Resource Groups & Tag Editor los recursos con `project=compliance-copilot`; no debe
quedar ninguno.
