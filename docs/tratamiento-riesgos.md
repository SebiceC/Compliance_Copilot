# Registro de tratamiento de riesgos

Decisiones sobre los hallazgos de la propia infraestructura del proyecto. Un riesgo aceptado sin justificación
documentada es una no conformidad; con justificación, dueño y fecha de revisión, es una decisión de gestión.

Opciones de tratamiento: **mitigar** (aplicar un control), **aceptar** (con justificación), **transferir** o
**evitar**.

## R-01 a R-07: bucket de evidencias de CI

- **Recurso:** `compliance-copilot-evidence-<sufijo>` (paquetes de evidencia de `scan.yml`, ver `docs/ci.md`)
- **Origen:** escaneo 4 desde GitHub Actions (2026-11-22)
- **Dueño del riesgo:** Sebastian Cerquera
- **Fecha de decisión:** 2026-11-22 · **Próxima revisión:** 2027-05-22, o antes si el proyecto deja de ser un
  laboratorio (datos reales de terceros, varias cuentas)

**Riesgo según el motor (metodología v0.2).** En el escaneo 4 el bucket aún no tenía tags: impacto 3
(clasificación faltante). Después se etiquetó `data-classification=restricted` (es evidencia de auditoría, como
CloudTrail), lo que sube el impacto a 4. La tabla usa el valor con la clasificación correcta: severidad media
→ 3 × 4 = **12, alto**; severidad baja → 2 × 4 = **8, medio**.

| ID | Check de Prowler | Control ISO 27001:2022 | Riesgo | Tratamiento | Justificación |
|---|---|---|---|---|---|
| R-01 | `s3_bucket_object_versioning` | A.8.3, A.8.10 | 12 alto | **Mitigar** | Conserva versiones ante sobrescritura o borrado. Costo casi nulo: cada escaneo escribe en una carpeta nueva. Requisito de Object Lock (R-02) |
| R-02 | `s3_bucket_object_lock` | — | 8 medio | **Mitigar** (modo Governance, 30 días) | Hace inmutable la evidencia durante su retención. El rol de CI ya no puede borrar; esto protege también contra un borrado de un administrador, que necesitaría un bypass explícito. Governance y no Compliance: permite desmontar el laboratorio sin esperar a que venza la retención |
| R-03 | `s3_bucket_no_mfa_delete` | — | 12 alto | **Aceptar** | Activarlo exige usar las credenciales root, contra la buena práctica de no usarlas. Control compensatorio: Object Lock (R-02) protege la misma propiedad (que no se borre evidencia) sin root |
| R-04 | `s3_bucket_kms_encryption` | A.8.11, A.8.24 | 12 alto | **Aceptar** | Los datos ya están cifrados en reposo (SSE-S3) y en tránsito (la política del bucket exige TLS). Una llave KMS propia agrega control de acceso separado y registro de cada uso, a ~1 USD/mes más solicitudes; no se justifica en un laboratorio con evidencia que expira a 30 días |
| R-05 | `s3_bucket_server_access_logging_enabled` | A.8.15 | 12 alto | **Aceptar (temporal)** | Saber quién descargó la evidencia es relevante para la cadena de custodia, pero requiere otro bucket de logs, que genera sus propios hallazgos. Hoy solo LabAdmin puede leer el bucket. Reevaluar si hay más personas con acceso o datos de terceros |
| R-06 | `s3_bucket_cross_region_replication` | A.8.14 | 8 medio | **Aceptar** | Protege ante la caída de una región. La evidencia dura 30 días y se puede regenerar con un escaneo nuevo; un segundo bucket y la transferencia entre regiones no se justifican |
| R-07 | `s3_bucket_event_notifications_enabled` | — | 8 medio | **Aceptar** | Las alertas servirían sobre todo para detectar borrados; con Object Lock (R-02) los objetos no se pueden borrar durante la retención |

### Implementación de las mitigaciones

| ID | Configuración | Estado |
|---|---|---|
| R-01 | Versionado habilitado. Regla de ciclo de vida: vencer versiones actuales a 30 días y borrar las no actuales 1 día después | aplicado y verificado (2026-11-22) |
| R-02 | Object Lock habilitado, retención por defecto Governance de 30 días | aplicado y verificado (2026-11-22) |

La configuración se verificó con el perfil de solo lectura (`get-bucket-versioning`,
`get-object-lock-configuration`, `get-bucket-lifecycle-configuration`). Object Lock necesitó dos correcciones:
la consola guardó primero una *retención por evento* (`DefaultEventHold`) en vez de un período de retención, y
después `Years: 30` en vez de `Days: 30`, que habría retenido la evidencia 30 años en contra de la minimización.

**Verificación:** el próximo escaneo desde CI debe mostrar R-01 y R-02 en PASS; R-03 a R-07 siguen en FAIL,
respaldados por este registro.

**Efecto sobre el desmontaje:** con Object Lock, vaciar el bucket antes de 30 días requiere el permiso
`s3:BypassGovernanceRetention` (LabAdmin lo tiene) y una solicitud explícita de bypass; o esperar a que venza la
retención.
