# Metodología de evaluación de riesgo

- **Versión:** 0.2
- **Fecha:** 2026-11-19
- **Estado:** Aprobada (clasificación, impacto, probabilidad, nivel y tratamiento)
- **Implementación:** `src/compliance_copilot/risk.py`; cada ejemplo de este documento es un test en
  `tests/test_risk.py`.

Este documento define cómo Compliance Copilot convierte un hallazgo técnico en un riesgo evaluado. El objetivo
es que el método sea **definido, consistente y repetible**, como exige ISO/IEC 27001 para la evaluación de
riesgos, y que cualquier persona pueda recalcular un resultado a mano a partir de los datos del escaneo.

**Riesgo = Probabilidad (1-5) × Impacto (1-5)**, sobre una matriz de 5×5 (escalas de 5 niveles, en línea con
NIST SP 800-30).

**Qué se evalúa.** Solo los hallazgos **FAIL**. Un PASS es evidencia de que el control funciona (va al paquete
de evidencias); un MANUAL requiere revisión humana y queda pendiente. La evaluación es un objeto aparte
(`RiskAssessment`) que referencia al hallazgo: el hallazgo es evidencia inmutable; la evaluación es una opinión
sobre esa evidencia y puede cambiar si cambia esta metodología.

**Justificación obligatoria.** Cada evaluación incluye qué regla produjo cada número, en texto legible.

---

## 1. Clasificación de la información

Cada recurso lleva el tag `data-classification` con uno de estos valores (en minúscula, exactamente como se
escriben aquí):

| Valor | Descripción | Ejemplos |
|---|---|---|
| `public` | Información aprobada para divulgación externa | Sitio web, comunicados, ofertas de empleo |
| `internal` | Información operativa de uso interno, sin datos personales | Procedimientos, directorios internos |
| `confidential` | Información de negocio o **datos personales** (Ley 1581 de 2012) cuya exposición o alteración causaría un daño notable | Bases de clientes, contratos, estados financieros no auditados |
| `restricted` | **Datos sensibles** (art. 5, Ley 1581), credenciales y llaves, registros cuya alteración destruye evidencia, y secretos empresariales | Historias clínicas, biometría, llaves criptográficas, logs de auditoría, algoritmos propietarios, invenciones no patentadas |

**Criterio único: el peor caso entre exposición y alteración.** Cada recurso recibe un solo nivel, el del
mayor daño que causaría que la información se **exponga** (confidencialidad) **o se altere** (integridad).
Es una simplificación del principio *high-water mark* de FIPS 199, que evalúa ambas dimensiones y toma la más
alta. Por eso un trail de CloudTrail es `restricted` aunque sus logs no contengan datos personales: su
alteración destruiría la evidencia forense.

**Quién clasifica.** La clasificación la asigna el **dueño del activo**, no el equipo de seguridad. Seguridad
define los niveles y verifica que se apliquen. *(Pendiente de validar con el autor.)*

### 1.1 Recursos sin tag: depende del tipo de recurso

No todos los recursos guardan información ni todos se pueden etiquetar (por ejemplo, las políticas
administradas por AWS o los controles de cuenta). Aplicar la misma regla a todos generaría cientos de
hallazgos imposibles de corregir. Por eso cada tipo de recurso pertenece a uno de tres grupos:

| Grupo | Tipos de recurso (`resource_type` de Prowler) | Sin tag |
|---|---|---|
| **Datos**: guardan o protegen información | `AwsS3Bucket`, `AwsEc2Instance`, `AwsEc2Volume`, `AwsEc2Snapshot`, `AwsRdsDbInstance`, `AwsRdsDbCluster`, `AwsRdsDbSnapshot`, `AwsDynamoDbTable`, `AwsEfsFileSystem`, `AwsRedshiftCluster`, `AwsBackupBackupVault`, `AwsKmsKey`, `AwsSecretsManagerSecret`, `AwsLogsLogGroup`, `AwsOpenSearchServiceDomain` | Base 3 (`confidential`) **y** hallazgo de clasificación faltante (`A.5.12`) |
| **Cuenta**: controles que protegen a toda la cuenta | `Other`, `AwsCloudTrailTrail`, `AwsCloudWatchAlarm`, `AwsConfigConfigurationRecorder`, `AwsConfigConfigurationAggregator`, `AwsGuardDutyDetector`, `AwsSecurityHubHub`, `AwsS3AccountPublicAccessBlock`, `AwsIamPasswordPolicy` | Base 3, sin hallazgo `A.5.12`; además aplica el modificador (a) |
| **Infraestructura**: todo lo demás (security groups, IAM, red…) | Cualquier otro tipo | Base 3, sin hallazgo `A.5.12`: el tag se recomienda, pero su ausencia no es un incumplimiento |

**Un tag presente siempre manda**, en cualquier grupo: `lab-trail` es del grupo Cuenta, pero su tag
`restricted` fija la base en 4.

**Tag con valor inválido** (por ejemplo `private` o `secreto`): se trata como sin tag (base 3) y genera el
hallazgo `A.5.12` en cualquier grupo, porque alguien intentó clasificar y lo hizo mal. Las mayúsculas y los
espacios se ignoran (`Confidential` es válido).

El hallazgo `A.5.12` no es un hallazgo de Prowler: el motor lo marca en la evaluación
(`requires_classification`) y los entregables lo reportan bajo el control de clasificación de la información de
ISO 27001:2022. No se castiga dos veces: el impacto usa un valor prudente y el incumplimiento se reporta aparte.

---

## 2. Impacto

**Impacto = Base por clasificación + Modificador de alcance (máximo 5)**

### 2.1 Base

| Clasificación | Base |
|---|---|
| `public` | 1 |
| `internal` | 2 |
| `confidential` (o sin tag, o tag inválido) | 3 |
| `restricted` | 4 |

### 2.2 Modificador de alcance (+1)

Se suma **+1** si el recurso cumple **al menos una** de estas condiciones:

| Condición | Qué se observa | Por qué amplía el daño |
|---|---|---|
| **(a) Alcance de toda la cuenta** | El tipo de recurso pertenece al grupo **Cuenta** (sección 1.1) | Su falla no expone un dato: debilita a toda la cuenta |
| **(b) Producción** | Tag `environment=prod` | Afecta a clientes y operaciones reales |
| **(c) Privilegios administrativos** | El **mismo recurso** tiene un FAIL en un check de privilegios administrativos (abajo) | Quien lo comprometa alcanza y puede modificar todos los recursos de la cuenta |

**Cómo se detecta (c).** El hallazgo no guarda las políticas de la identidad; en su lugar se reutiliza lo que
Prowler ya evalúa. Si un recurso tiene un FAIL en alguno de estos checks, el modificador (c) aplica a **todos**
los hallazgos de ese recurso:

- `iam_user_administrator_access_policy` (usuario con `AdministratorAccess`)
- `iam_role_administratoraccess_policy` (rol con `AdministratorAccess`)
- `iam_group_administrator_access_policy` (grupo con `AdministratorAccess`)
- `iam_aws_attached_policy_no_administrative_privileges`, `iam_customer_attached_policy_no_administrative_privileges`,
  `iam_inline_policy_no_administrative_privileges` (la política misma concede `"Action": "*"` sobre `"Resource": "*"`)

**Reglas:**

- **No se acumula.** Cumplir varias condiciones suma +1, no más.
- **Tope en 5.**
- **Solo condiciones observables** en la salida del escáner (tipo de recurso, tags, otros hallazgos).

---

## 3. Probabilidad

**Probabilidad = Base por severidad + Modificador de exposición (máximo 5)**

### 3.1 Base

La severidad que el escáner asigna al check resume qué tan fácil y frecuente es explotar la debilidad.

| Severidad del check | Base |
|---|---|
| `informational` | 1 |
| `low` | 2 |
| `medium` | 3 |
| `high` | 4 |
| `critical` | 5 |

### 3.2 Modificador de exposición (+1)

Se suma **+1** si el check tiene la categoría **`internet-exposed`** de Prowler: un recurso alcanzable desde
internet puede ser atacado por cualquiera, no solo por alguien con acceso a la red interna. Tope en 5.

---

## 4. Ejemplos (laboratorio)

| Hallazgo | Probabilidad | Impacto | Riesgo | Nivel |
|---|---|---|---|---|
| Security group con SSH abierto (`public`) | high 4 + internet 1 = **5** | public **1** | **5** | Medio |
| Usuario IAM sin MFA (`internal`) | high **4** | internal **2** | **8** | Medio |
| Bucket S3 sin versionado (`confidential`) | medium **3** | confidential **3** | **9** | Medio |
| Bucket de logs de CloudTrail sin versionado (`restricted`) | medium **3** | restricted **4** | **12** | Alto |
| Trail sin validación de logs (`restricted`, grupo Cuenta) | medium **3** | 4 + (a) = **5** | **15** | Alto |
| Usuario administrador sin MFA (sin tag) | high **4** | 3 + (c) = **4** | **16** | Alto |
| Usuario con `AdministratorAccess` (sin tag) | critical **5** | 3 + (c) = **4** | **20** | Crítico |
| Bucket con datos sin tag | medium **3** | **3**, + hallazgo `A.5.12` | **9** | Medio |
| El mismo bucket con `environment=prod` y `restricted` | medium **3** | 4 + (b) = **5** | **15** | Alto |

---

## 5. Nivel de riesgo y tratamiento sugerido

| Puntuación | Nivel | Tratamiento sugerido |
|---|---|---|
| 1-4 | Bajo | Aceptar |
| 5-9 | Medio | Mitigar, o aceptar con justificación documentada |
| 10-16 | Alto | Mitigar |
| 20-25 | Crítico | Mitigar con prioridad |

Las puntuaciones 17-19 no pueden ocurrir: no son producto de dos valores entre 1 y 5.

El tratamiento es una **sugerencia del motor**. La decisión final y su justificación corresponden a una
persona.

---

## 6. Hallazgos sin control mapeado

Algunos checks no corresponden a ningún control de los marcos del proyecto (ISO 27001:2022, SOC 2,
NIST CSF 2.0). **Se evalúan igual**: el riesgo existe aunque ningún marco lo nombre. En la matriz de riesgos se
marcan como "sin control mapeado" (`has_control_mapping = false`) y **no** entran en la SoA: esconderlos
perdería información; incluirlos en la SoA inventaría un control.

---

## 7. Límites conocidos

- **Matriz cualitativa.** No reemplaza un análisis cuantitativo (por ejemplo, FAIR) que exprese el riesgo en
  términos financieros. Multiplicar valores ordinales es una convención, no una medición.
- **Doble conteo parcial.** La severidad de Prowler, base de la probabilidad, también refleja en parte el
  impacto potencial del check. Se acepta por ser observable y consistente.
- **Exposición simplificada.** Solo se observa la categoría `internet-exposed` del check; no se analiza la
  topología de red (rutas, NACL, balanceadores) para confirmar que el recurso es realmente alcanzable.
- **No estima volumen ni impacto financiero.** El escaneo no sabe cuántos registros hay en un recurso ni cuánto
  vale la información.
- **La clasificación depende del etiquetado.** La herramienta no inspecciona el contenido de los recursos; un
  tag incorrecto produce un impacto incorrecto.
- **Privilegios efectivos simplificados.** La condición (c) depende de los checks de Prowler listados. No
  evalúa permission boundaries, SCP de Organizations ni cadenas de roles asumibles.
- **Listas de tipos de recurso cerradas.** Un tipo nuevo de Prowler cae en el grupo Infraestructura hasta que
  se agregue a la lista correspondiente.
- **Configuraciones de cuenta con tipo de datos.** Prowler reporta algunos ajustes de la cuenta con un tipo de
  datos y sin recurso concreto (por ejemplo, `ec2_ebs_default_encryption` como `AwsEc2Volume`). En la v0.2
  caen en el grupo Datos: sin tag, generan el hallazgo `A.5.12` y no reciben el modificador (a). La matriz de
  la Ley 1581 ya los trata como hallazgos de cuenta; el motor lo hará en la v0.3 (hoja de ruta, paso 11.2).

## Historial

| Versión | Fecha | Cambio |
|---|---|---|
| 0.1 | 2026-11-11 | Clasificación e impacto |
| 0.2 | 2026-11-19 | Probabilidad (severidad + exposición), recursos sin tag según su grupo, detección de (c) por hallazgos cruzados, hallazgos sin control mapeado, ejemplos verificados con tests |

## Referencias

- ISO/IEC 27001:2022 y 27005:2022: requisitos y guía de gestión de riesgos (solo se citan identificadores de
  control).
- NIST SP 800-30 Rev. 1: escalas de evaluación de riesgo de 5 niveles.
- FIPS 199: categorización de impacto por confidencialidad, integridad y disponibilidad.
- Ley 1581 de 2012 (Colombia), art. 5: definición de datos sensibles.
