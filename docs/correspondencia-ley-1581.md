# Correspondencia ISO 27001 → Ley 1581 de 2012

> **Revisado fila por fila por el responsable del análisis de privacidad (2026-11-23).** La herramienta no da
> asesoría jurídica: codifica ese criterio. Un cambio en una fila exige repetir su revisión (ver
> `docs/metodologia-ley-1581.md`, sección 5).

Prowler no mapea la Ley 1581. La matriz técnica se **deriva** del mapeo a ISO 27001:2022 que ya se revisó
(decisión L3): hallazgo → control ISO → obligación de la ley. Este documento tiene las tres piezas:

1. El **catálogo de obligaciones** (`catalogs/ley-1581.json`), con todas las obligaciones (decisión L2).
2. La **tabla ISO → obligación**, con su justificación.
3. Las **reglas propias**: qué hallazgos cuentan (L4) y la circulación internacional (L5).

**Fuentes:** Ley Estatutaria 1581 de 2012; Decreto 1377 de 2013, compilado en el Decreto 1074 de 2015 (Libro 2,
Parte 2, Título 2, Capítulo 25); SIC, Circular Externa 005 de 2017; SIC, *Guía para la implementación del
principio de responsabilidad demostrada (accountability)*. Los artículos del decreto se citan con su número
original del 1377.

## 1. Catálogo de obligaciones

**50 obligaciones.** *Técnica*: recibe hallazgos (vía ISO o por la regla de región). *Documental*: sale
sin estado técnico y con la columna **Evidencia manual** para que el responsable anote la prueba.

Técnicas: **12**. Documentales: **38**.

**Alcance del estado técnico en `L1581-17n` y `L1581-18k`** (decidido el 2026-11-25, en la revisión de la
matriz con el primer escaneo en CI). Las dos obligaciones piden *informar* a la SIC, y ningún escáner ve si
alguien lo hizo. Sus controles ISO (gestión de incidentes, registro y monitoreo) evidencian el paso previo: poder
detectar la violación. La matriz lo dice en la fila:
*Estado técnico: mide la capacidad de detectar la violación, no la notificación a la SIC*. La notificación misma
va en **Evidencia manual**.

### Art. 4 · Principios

| ID | Obligación | Fuente | Tipo |
|---|---|---|---|
| `L1581-4a` | Legalidad: el tratamiento se sujeta a la ley | Ley 1581, art. 4 lit. a | Documental |
| `L1581-4b` | Finalidad legítima, informada al titular | Ley 1581, art. 4 lit. b | Documental |
| `L1581-4c` | Libertad: tratamiento con autorización previa, expresa e informada | Ley 1581, art. 4 lit. c | Documental |
| `L1581-4d` | Veracidad o calidad: información completa, exacta y actualizada | Ley 1581, art. 4 lit. d | Documental |
| `L1581-4e` | Transparencia: el titular puede conocer sus datos | Ley 1581, art. 4 lit. e | Documental |
| `L1581-4f` | Acceso y circulación restringida; no expuestos en Internet sin control | Ley 1581, art. 4 lit. f | Técnica |
| `L1581-4g` | Seguridad: medidas técnicas, humanas y administrativas | Ley 1581, art. 4 lit. g | Técnica |
| `L1581-4h` | Confidencialidad de los datos que no son públicos | Ley 1581, art. 4 lit. h | Técnica |

### Arts. 5 a 7 · Datos sensibles y de menores

| ID | Obligación | Fuente | Tipo |
|---|---|---|---|
| `L1581-6` | Tratamiento de datos sensibles solo en los casos permitidos | Ley 1581, arts. 5 y 6 | Documental |
| `L1581-7` | Datos de niños, niñas y adolescentes: interés superior | Ley 1581, art. 7 | Documental |

### Arts. 8 a 16 · Derechos, autorización y procedimientos

| ID | Obligación | Fuente | Tipo |
|---|---|---|---|
| `L1581-8` | Derechos de los titulares: conocer, actualizar, rectificar, revocar | Ley 1581, art. 8 | Documental |
| `L1581-9` | Autorización previa e informada del titular | Ley 1581, art. 9 | Documental |
| `L1581-12` | Deber de informar al titular al pedir la autorización | Ley 1581, art. 12 | Documental |
| `L1581-14` | Atención de consultas en los plazos de ley | Ley 1581, art. 14 | Documental |
| `L1581-15` | Atención de reclamos en los plazos de ley | Ley 1581, art. 15 | Documental |

### Art. 17 · Deberes del responsable

| ID | Obligación | Fuente | Tipo |
|---|---|---|---|
| `L1581-17a` | Garantizar el ejercicio pleno del hábeas data | Ley 1581, art. 17 lit. a | Documental |
| `L1581-17b` | Solicitar y conservar copia de la autorización | Ley 1581, art. 17 lit. b | Documental |
| `L1581-17c` | Informar al titular la finalidad y sus derechos | Ley 1581, art. 17 lit. c | Documental |
| `L1581-17d` | Conservar la información en condiciones de seguridad | Ley 1581, art. 17 lit. d | Técnica |
| `L1581-17e` | Entregar al encargado información veraz y completa | Ley 1581, art. 17 lit. e | Documental |
| `L1581-17f` | Mantener la información actualizada y comunicarlo al encargado | Ley 1581, art. 17 lit. f | Documental |
| `L1581-17g` | Rectificar la información incorrecta y comunicarlo al encargado | Ley 1581, art. 17 lit. g | Documental |
| `L1581-17h` | Entregar al encargado solo datos con tratamiento autorizado | Ley 1581, art. 17 lit. h | Documental |
| `L1581-17i` | Exigir al encargado condiciones de seguridad y privacidad | Ley 1581, art. 17 lit. i | Documental |
| `L1581-17j` | Tramitar las consultas y los reclamos | Ley 1581, art. 17 lit. j | Documental |
| `L1581-17k` | Adoptar un manual interno de políticas y procedimientos | Ley 1581, art. 17 lit. k | Documental |
| `L1581-17l` | Informar al encargado los datos en discusión por el titular | Ley 1581, art. 17 lit. l | Documental |
| `L1581-17m` | Informar al titular, si lo pide, el uso dado a sus datos | Ley 1581, art. 17 lit. m | Documental |
| `L1581-17n` | Informar a la SIC las violaciones a los códigos de seguridad | Ley 1581, art. 17 lit. n | Técnica |
| `L1581-17o` | Cumplir las instrucciones y requerimientos de la SIC | Ley 1581, art. 17 lit. o | Documental |

### Art. 18 · Deberes del encargado

| ID | Obligación | Fuente | Tipo |
|---|---|---|---|
| `L1581-18a` | Garantizar el ejercicio pleno del hábeas data | Ley 1581, art. 18 lit. a | Documental |
| `L1581-18b` | Conservar la información en condiciones de seguridad | Ley 1581, art. 18 lit. b | Técnica |
| `L1581-18c` | Actualizar, rectificar o suprimir los datos oportunamente | Ley 1581, art. 18 lit. c | Documental |
| `L1581-18d` | Actualizar lo reportado por el responsable en cinco días hábiles | Ley 1581, art. 18 lit. d | Documental |
| `L1581-18e` | Tramitar las consultas y los reclamos | Ley 1581, art. 18 lit. e | Documental |
| `L1581-18f` | Adoptar un manual interno de políticas y procedimientos | Ley 1581, art. 18 lit. f | Documental |
| `L1581-18g` | Registrar la leyenda "reclamo en trámite" | Ley 1581, art. 18 lit. g | Documental |
| `L1581-18h` | Insertar la leyenda "información en discusión judicial" | Ley 1581, art. 18 lit. h | Documental |
| `L1581-18i` | No circular información cuyo bloqueo ordenó la SIC | Ley 1581, art. 18 lit. i | Documental |
| `L1581-18j` | Permitir el acceso solo a las personas autorizadas | Ley 1581, art. 18 lit. j | Técnica |
| `L1581-18k` | Informar a la SIC las violaciones a los códigos de seguridad | Ley 1581, art. 18 lit. k | Técnica |
| `L1581-18l` | Cumplir las instrucciones y requerimientos de la SIC | Ley 1581, art. 18 lit. l | Documental |

### Art. 25 · Registro Nacional de Bases de Datos

| ID | Obligación | Fuente | Tipo |
|---|---|---|---|
| `L1581-25` | Inscribir las bases de datos en el RNBD | Ley 1581, art. 25 | Documental |

### Circulación internacional de datos

| ID | Obligación | Fuente | Tipo |
|---|---|---|---|
| `L1581-26` | Transferir solo a países con nivel adecuado, salvo excepciones | Ley 1581, art. 26 | Técnica (región) |
| `D1377-25` | Contrato de transmisión con el encargado fuera del país | Decreto 1377, arts. 24 y 25 | Técnica (región) |
| `SIC-C005` | Países con nivel adecuado según la Circular Externa 005 de 2017 | SIC, Circular Externa 005 de 2017 | Técnica (región) |

### Decreto 1377 de 2013 · Reglamentación

| ID | Obligación | Fuente | Tipo |
|---|---|---|---|
| `D1377-11` | Conservar los datos solo el tiempo necesario para la finalidad | Decreto 1377, art. 11 | Técnica |
| `D1377-13` | Política de tratamiento de la información | Decreto 1377, art. 13 | Documental |
| `D1377-14` | Aviso de privacidad cuando no se puede entregar la política | Decreto 1377, arts. 14 y 15 | Documental |
| `D1377-26` | Responsabilidad demostrada (Guía de la SIC) | Decreto 1377, arts. 26 y 27 | Documental |

## 2. Tabla ISO 27001 → obligación

**Base de cada fila:** *texto*, el artículo nombra el riesgo o la medida que el control trata (por ejemplo, la
"pérdida" del art. 17 d y las copias de respaldo); *criterio*, la relación es razonable pero no literal y es
la primera que conviene revisar.

Los arts. 17 d (responsable) y 18 b (encargado) tienen el mismo texto y siempre van juntos: la matriz no sabe si
la organización actúa como responsable, como encargada o como ambas. La columna **Aplica** lo resuelve.

| Control ISO | Obligaciones | Base | Justificación |
|---|---|---|---|
| A.5.15 Control de acceso | `L1581-4f` · `L1581-18j` · `L1581-4g` · `L1581-17d` · `L1581-18b` | texto | Las reglas de acceso impiden la consulta y el acceso no autorizado que nombran los arts. 17 d y 18 b; 4 f exige un acceso restringido. |
| A.5.16 Gestión de identidades | `L1581-4f` · `L1581-18j` | criterio | Sin identidades únicas y vigentes no se puede limitar el acceso a las personas autorizadas (18 j). |
| A.5.17 Información de autenticación | `L1581-4g` · `L1581-17d` · `L1581-18b` | criterio | Contraseñas y llaves débiles o expuestas permiten el acceso fraudulento a los datos. |
| A.5.18 Derechos de acceso | `L1581-4f` · `L1581-18j` | texto | Asignar y revisar derechos es la forma de "permitir el acceso solo a las personas que pueden tener acceso" (18 j). |
| A.5.24 Planificación y preparación para la gestión de incidentes | `L1581-17n` · `L1581-18k` | criterio | Sin un proceso de incidentes no hay quien detecte una violación de seguridad ni la reporte a la SIC. |
| A.5.25 Evaluación y decisión sobre eventos de seguridad | `L1581-17n` · `L1581-18k` | criterio | Decidir si un evento es un incidente es el paso previo al reporte de los arts. 17 n y 18 k. |
| A.5.26 Respuesta a incidentes de seguridad | `L1581-17n` · `L1581-18k` | criterio | La respuesta incluye la notificación a la autoridad cuando hay riesgo para los titulares. |
| A.8.2 Derechos de acceso privilegiado | `L1581-4f` · `L1581-18j` · `L1581-4g` · `L1581-17d` · `L1581-18b` | texto | Un acceso privilegiado sin control (root sin MFA, permisos amplios) abre todos los datos a un acceso no autorizado. |
| A.8.3 Restricción de acceso a la información | `L1581-4f` · `L1581-18j` · `L1581-4h` · `L1581-4g` · `L1581-17d` · `L1581-18b` | texto | Un bucket público pone los datos "disponibles en Internet" sin acceso técnicamente controlable: es el supuesto literal del art. 4 f. |
| A.8.5 Autenticación segura | `L1581-4g` · `L1581-17d` · `L1581-18b` | criterio | La autenticación débil (sin MFA) facilita el acceso fraudulento que el art. 17 d manda impedir. |
| A.8.8 Gestión de vulnerabilidades técnicas | `L1581-4g` · `L1581-17d` · `L1581-18b` | criterio | Una vulnerabilidad conocida sin corregir es una vía de acceso no autorizado a los datos. |
| A.8.9 Gestión de la configuración | `L1581-4g` · `L1581-17d` · `L1581-18b` | criterio | Las configuraciones inseguras son la causa más común de exposición de datos en la nube. |
| A.8.10 Eliminación de información | `D1377-11` | texto | Las reglas de ciclo de vida evidencian que los datos se suprimen cuando ya no se necesitan para la finalidad. |
| A.8.11 Enmascaramiento de datos | `L1581-4h` | criterio | Enmascarar o seudonimizar reduce quién puede conocer el dato, que es lo que protege la confidencialidad. |
| A.8.12 Prevención de fuga de datos | `L1581-4f` · `L1581-18j` · `L1581-4h` | criterio | Impedir la fuga es impedir la circulación no autorizada de los datos. |
| A.8.13 Copias de respaldo | `L1581-4g` · `L1581-17d` · `L1581-18b` | texto | Los arts. 17 d y 18 b nombran la "pérdida": el respaldo es el control contra ella. |
| A.8.15 Registro de eventos | `L1581-4g` · `L1581-17d` · `L1581-18b` · `L1581-17n` · `L1581-18k` | texto | Sin registros íntegros no se puede detectar la adulteración ni el acceso no autorizado, ni reportar una violación. |
| A.8.16 Actividades de monitoreo | `L1581-4g` · `L1581-17d` · `L1581-18b` · `L1581-17n` · `L1581-18k` | criterio | El monitoreo detecta la violación de seguridad que después se informa a la SIC. |
| A.8.20 Seguridad de redes | `L1581-4f` · `L1581-18j` · `L1581-4g` · `L1581-17d` · `L1581-18b` | criterio | Un puerto de administración abierto a Internet es una vía de entrada hacia los datos. |
| A.8.21 Seguridad de los servicios de red | `L1581-4g` · `L1581-17d` · `L1581-18b` | criterio | Los servicios de red expuestos sin protección facilitan el acceso no autorizado. |
| A.8.22 Segmentación de redes | `L1581-4f` · `L1581-18j` | criterio | Segmentar limita qué sistemas pueden llegar a los datos personales. |
| A.8.24 Uso de criptografía | `L1581-4h` · `L1581-4g` · `L1581-17d` · `L1581-18b` | texto | El cifrado impide la consulta no autorizada aunque el medio se exponga: protege la confidencialidad y la seguridad. |

**22 controles:** 8 por texto y 14 por criterio.

### Controles que Prowler mapea y no se llevan a la ley

Un hallazgo de estos controles sigue en la SoA de ISO, pero no cuenta en la matriz de la ley. No es una omisión
silenciosa: está decidido aquí.

| Control ISO | Motivo |
|---|---|
| A.5.1 Políticas de seguridad | Organizacional: la política de tratamiento es la D1377-13 y es evidencia manual. |
| A.5.3 Segregación de funciones | Útil, pero la ley no la exige de forma específica. |
| A.5.5 Contacto con las autoridades | Sería apoyo del 17 n, pero lo que Prowler evidencia (contactos de la cuenta) es demasiado débil. |
| A.5.13 Etiquetado de la información | Prowler lo usa para etiquetas de recursos; el tag `personal-data` es la regla de la L4, no un hallazgo. |
| A.5.19 Seguridad en las relaciones con proveedores | Relacionado con el 17 i, que es documental: el contrato con el encargado. |
| A.5.21 Seguridad en la cadena de suministro TIC | Sin relación directa con una obligación de la ley. |
| A.5.22 Seguimiento de los servicios de proveedores | Igual que A.5.19: documental. |
| A.5.28 Recolección de evidencias | Forense: apoyo muy indirecto del reporte de incidentes. |
| A.5.29 Seguridad durante una interrupción | Continuidad del negocio: la ley protege la pérdida (cubierta por A.8.13), no la disponibilidad del servicio. |
| A.8.1 Dispositivos de usuario final | Prowler le asigna checks de la nube que no son de dispositivos; el mapeo es débil. |
| A.8.7 Protección contra malware | Débil en la nube; se deja fuera para no sobrerreportar. |
| A.8.14 Redundancia | Disponibilidad del servicio, no pérdida de los datos. |
| A.8.23 Filtrado web | Sin relación con los datos de los titulares. |

## 3. Reglas propias

### Qué hallazgos cuentan (decisión L4)

La Ley 1581 solo aplica a datos personales. Un tag `personal-data=yes|no`, que decide una persona y controla la
Tag Policy, marca los recursos que los tratan. Es independiente de `data-classification`: la clasificación mide
el impacto de la divulgación; el tag dice si aplica la ley.

| Grupo del hallazgo | Cuenta en la matriz si... | Por qué |
|---|---|---|
| **Datos** (S3, bases de datos) | el recurso tiene `personal-data=yes` | El hallazgo es sobre el dato mismo |
| **Cuenta** (root, CloudTrail, IAM) | la cuenta tiene al menos un recurso con `personal-data=yes` | Un control de la cuenta protege todos los datos que hay en ella |
| **Infraestructura** (redes, cómputo) | igual que la cuenta | Es una vía de entrada hacia los datos |

Un recurso de datos **sin** el tag no se cuenta ni se descarta: aparece en la sección **"Requiere revisión:
recurso de datos sin calificar"**.

### Circulación internacional (decisión L5)

**Calificación por defecto: transmisión.** El proveedor de nube almacena y procesa los datos por cuenta de la
organización, sin decidir sobre ellos: actúa como **encargado** (Decreto 1377, art. 3). La transmisión exige un
contrato con el contenido del art. 25 del decreto; con ese contrato, el art. 24 no exige informar al titular ni
pedir su autorización. La **transferencia** (art. 26 de la Ley 1581 y Circular Externa 005 de 2017) queda como
alternativa a verificar, para los casos en que quien recibe los datos decide sobre ellos.

La herramienta solo ve la región. Por cada recurso con `personal-data=yes` en una región que no está en la lista
de regiones en Colombia (configurable; hoy vacía, porque el proveedor no tiene región en el país), la matriz
señala para revisión las obligaciones `L1581-26`, `D1377-25`, `SIC-C005` con este texto:

> Recurso con datos personales fuera de Colombia: `<recurso>` · región `<región>` (<país>). Verificar: si el proveedor actúa como encargado, que exista un contrato de transmisión conforme al art. 25 del Decreto 1377 de 2013; si se trata de una transferencia, el fundamento del art. 26 de la Ley 1581.

Es un **señalamiento**, no un incumplimiento: el responsable anota en **Evidencia manual** el contrato o el
fundamento revisado.

## Preguntas de la revisión

Las que se respondieron en la revisión, y las que conviene repetir cuando cambie una fila:

Para cada fila:

1. ¿El artículo citado dice realmente eso?
2. ¿El control ISO **de verdad** evidencia la obligación, o la relación es débil? Empieza por las filas *criterio*.
3. ¿Falta una obligación técnica que un auditor de la SIC esperaría ver?

Y en conjunto:

- **Formato de los IDs:** `L1581-17d` (ley, artículo y literal), `D1377-25` (decreto 1377, artículo) y `SIC-C005`.
- **Obligaciones agrupadas:** los arts. 5 y 6 van en `L1581-6`, los arts. 14 y 15 del decreto en `D1377-14`, los
  arts. 26 y 27 en `D1377-26` (con la Guía de Responsabilidad Demostrada) y los arts. 24 y 25 en `D1377-25`.
- **Fuera del catálogo:** arts. 10, 11, 13 y 16 de la ley (excepciones a la autorización, suministro, personas
  autorizadas, requisito de procedibilidad) y el reporte de incidentes en el RNBD según la Circular Única de la
  SIC, que se evidencia con el 17 n. ¿Alguno debería entrar?
