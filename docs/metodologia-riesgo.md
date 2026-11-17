# Metodología de evaluación de riesgo

- **Versión:** 0.1 (borrador)
- **Fecha:** 2026-11-11
- **Estado:** Clasificación e impacto aprobados; probabilidad pendiente (Fase 2)

Este documento define cómo Compliance Copilot convierte un hallazgo técnico en un riesgo evaluado. El objetivo
es que el método sea **definido, consistente y repetible**, como exige ISO/IEC 27001 para la evaluación de
riesgos, y que cualquier persona pueda recalcular un resultado a mano a partir de los datos del escaneo.

**Riesgo = Probabilidad (1-5) × Impacto (1-5)**, sobre una matriz de 5×5 (escalas de 5 niveles, en línea con
NIST SP 800-30).

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

**Recursos sin tag.** Se tratan como `confidential` hasta que su dueño los clasifique. Además, la falta de
clasificación genera un **hallazgo propio**, mapeado al control de clasificación de la información de
ISO 27001:2022 (`A.5.12`). Así no se castiga dos veces: el impacto usa un valor prudente y el incumplimiento se
reporta aparte.

---

## 2. Impacto

**Impacto = Base por clasificación + Modificador de alcance (máximo 5)**

### 2.1 Base

| Clasificación | Base |
|---|---|
| `public` | 1 |
| `internal` | 2 |
| `confidential` (o sin tag) | 3 |
| `restricted` | 4 |

### 2.2 Modificador de alcance (+1)

Se suma **+1** si el recurso cumple **al menos una** de estas condiciones:

| Condición | Qué se observa | Por qué amplía el daño |
|---|---|---|
| **(a) Alcance de toda la cuenta** | El tipo de recurso es un control de cuenta: CloudTrail, política de contraseñas, usuario root, configuración de Organizations | Su falla no expone un dato: debilita a toda la cuenta |
| **(b) Producción** | Tag `environment=prod` | Afecta a clientes y operaciones reales |
| **(c) Privilegios administrativos** | La identidad tiene `AdministratorAccess` o una política con `"Action": "*"` sobre `"Resource": "*"`, directamente o vía grupo | Quien la comprometa alcanza y puede modificar todos los recursos de la cuenta |

**Reglas:**

- **No se acumula.** Cumplir varias condiciones suma +1, no más. Así el contexto ajusta la clasificación sin
  reemplazarla, y la escala conserva su capacidad de distinguir.
- **Tope en 5.**
- **Solo condiciones observables.** Todo lo que usa el modificador está en la salida del escáner (tipo de
  recurso, tags, políticas). No depende de información de negocio que el escaneo no tiene.

### 2.3 Ejemplos

| Recurso | Clasificación | Base | Condición | Impacto |
|---|---|---|---|---|
| Security group con SSH abierto | `public` | 1 | — | **1** |
| Usuario IAM sin MFA, sin políticas | `internal` | 2 | — | **2** |
| El mismo usuario con `AdministratorAccess` | `internal` | 2 | (c) | **3** |
| Bucket S3 de pruebas | `confidential` | 3 | — | **3** |
| El mismo bucket con `environment=prod` | `confidential` | 3 | (b) | **4** |
| Trail de CloudTrail | `restricted` | 4 | (a) | **5** |
| Trail de CloudTrail en producción | `restricted` | 4 | (a) y (b), no se acumula | **5** |

---

## 3. Probabilidad

*Pendiente (Fase 2).* Se calculará a partir de la **severidad del check** de Prowler y de factores de
**exposición** observables (por ejemplo, recurso accesible desde internet, identidad sin MFA, ausencia de
logging).

---

## 4. Nivel de riesgo y tratamiento sugerido

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

## 5. Límites conocidos

- **Matriz cualitativa.** No reemplaza un análisis cuantitativo (por ejemplo, FAIR) que exprese el riesgo en
  términos financieros. Multiplicar valores ordinales es una convención, no una medición.
- **No estima volumen ni impacto financiero.** El escaneo no sabe cuántos registros hay en un recurso ni cuánto
  vale la información.
- **La clasificación depende del etiquetado.** La herramienta no inspecciona el contenido de los recursos; un
  tag incorrecto produce un impacto incorrecto.
- **Privilegios efectivos simplificados.** La condición (c) solo detecta casos evidentes. No evalúa políticas
  inline complejas, permission boundaries, SCP de Organizations ni cadenas de roles asumibles.

## Referencias

- ISO/IEC 27001:2022 y 27005:2022: requisitos y guía de gestión de riesgos (solo se citan identificadores de
  control).
- NIST SP 800-30 Rev. 1: escalas de evaluación de riesgo de 5 niveles.
- FIPS 199: categorización de impacto por confidencialidad, integridad y disponibilidad.
- Ley 1581 de 2012 (Colombia), art. 5: definición de datos sensibles.
