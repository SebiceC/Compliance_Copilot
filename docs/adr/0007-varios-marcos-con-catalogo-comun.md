# 7. Varios marcos con un catálogo común y una declaración por marco

- **Fecha:** 2026-11-22
- **Estado:** Aceptada

## Contexto

Las Fases 1 a 5 se construyeron para un solo marco, ISO 27001:2022, y el código lo tenía fijo: el patrón de los
IDs (`A.5.1`), los cuatro temas del Anexo A, las columnas de la SoA (*Aplicable* y *Justificación*) y una
constante usada por el informe, el plan y la IA. La v1.0 agrega SOC 2, NIST CSF 2.0 y Ley 1581
(`docs/hoja-de-ruta-v1.md`). Copiar el código por marco duplicaría cada corrección.

Además, al revisar el código apareció un hueco: si un hallazgo traía un ID que no estaba en el catálogo, la SoA lo
ignoraba **en silencio**. Con ISO no ocurre (los 31 IDs que trae Prowler existen), pero el mapeo "NIST CSF 2.0"
de Prowler mezcla categorías de la versión 1.1 que no existen en la 2.0: se habrían perdido sin aviso.

## Decisiones

| # | Decisión | Por qué |
|---|---|---|
| D1 | **Catálogo común.** Cada requisito tiene `id`, `group` y `title`. Lo propio de cada marco va en su JSON: el patrón de IDs (`id_pattern`, validado al cargar), los grupos con su etiqueta, el entregable y la traducción de IDs | Agregar un marco es agregar un JSON, no código. La validación de los IDs no se pierde: se declara por marco |
| D2 | **Una declaración por marco.** Misma lógica de estado técnico (con brechas, requiere revisión, sin brechas, evidencia manual); cada catálogo define el nombre del entregable, su archivo, su hoja de Excel y sus **columnas de decisión humana** | Cada auditor espera su vocabulario: SoA (ISO), matriz de criterios (SOC 2), perfil actual y objetivo (NIST), matriz técnica (Ley 1581). La herramienta deja vacías las decisiones humanas en todos los marcos |
| D3 | **Normalizar sin perder.** Cada catálogo traduce los IDs de Prowler (`normalization` para reglas, `aliases` para una tabla de correspondencia). Un ID sin correspondencia se reporta en el resumen, en la declaración, en la hoja *Sin correspondencia* y en `evidencias/controles/<marco>/_sin-correspondencia.json` | El mismo principio del ADR 0003: nada se pierde en silencio. Una persona decide si falta el requisito o si el mapeo está mal |
| D4 | **Test de regresión con referencia** (`tests/test_golden.py`, `tests/golden/`): la salida completa sobre la muestra del laboratorio (Markdown, evidencias y contenido del Excel) se compara con una referencia capturada **antes** del refactor | Un refactor no debe cambiar entregables. Si un cambio debe alterarlos, se regenera la referencia a propósito y el diff del PR lo muestra |
| D5 | **El plan de remediación, la matriz de riesgos y la redacción con IA siguen citando ISO 27001** (`PRIMARY_FRAMEWORK`) | Limita el alcance de la v1.0 y no invalida la evaluación de modelos del ADR 0005, hecha con hallazgos que citan ISO |

Formato de un catálogo (extracto de `iso27001-2022.json`):

```json
{
  "framework": "ISO27001-2022",
  "id_pattern": "A\\.[5-8]\\.\\d{1,2}",
  "normalization": "identity",
  "groups": [{ "id": "organizational", "label": "Organizacional" }, "..."],
  "statement": {
    "title": "Declaración de Aplicabilidad (SoA): ISO/IEC 27001:2022",
    "file": "soa-iso27001.md", "sheet": "SoA ISO 27001",
    "id_label": "Control", "group_label": "Tema",
    "human_columns": ["Aplicable", "Justificación"]
  },
  "requirements": [{ "id": "A.5.1", "group": "organizational", "title": "Políticas de seguridad de la información" }]
}
```

## Consecuencias

- **Ganamos:** SOC 2, NIST CSF 2.0 y Ley 1581 se agregan como catálogos; los IDs de Prowler sin correspondencia
  quedan visibles; una red de seguridad para todos los cambios futuros de los entregables.
- **Verificado:** después del refactor, los entregables de ISO 27001 salen **idénticos** a la referencia capturada
  antes (Markdown, evidencias, valores y formato del Excel).
- **Aceptamos:** los marcos nuevos no aparecen en el plan ni en la redacción con IA en la v1.0; la referencia de
  `tests/golden/` hay que regenerarla a propósito cuando un cambio deba alterar la salida.
- **Nos obliga a futuro:** cada catálogo nuevo trae su `id_pattern`, sus grupos y su tabla de correspondencia, y
  un test que compruebe que los IDs de la muestra del laboratorio se traducen o se reportan.

## Revisión

Reevaluar D5 cuando exista el conjunto de evaluación de la redacción con IA, o si un auditor pide el plan de
remediación referido a un marco distinto de ISO 27001.
