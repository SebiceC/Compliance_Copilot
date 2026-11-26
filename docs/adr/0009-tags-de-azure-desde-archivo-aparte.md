# 9. Tags de Azure desde un archivo aparte

- **Fecha:** 2026-11-25
- **Estado:** Aceptada

## Contexto

El primer escaneo de Azure del laboratorio (Fase 10, paso 10.5) trajo todos los recursos con
`resources[].labels` vacío, aunque en Azure tenían sus tags (`data-classification`, `personal-data`,
`project`). La causa está en Prowler (5.48 y `master` al 2026-11-25): cada hallazgo toma los tags del objeto que
arma el servicio (`getattr(resource, "tags", [])`), y los servicios de Azure no leen ese atributo.

Sin tags, dos piezas del proyecto dejan de funcionar para Azure:

- **El motor de riesgo** no ve `data-classification`: usa el impacto por defecto y marca `A.5.12` en todo recurso
  de datos (`docs/metodologia-riesgo.md`).
- **La matriz de la Ley 1581** no ve `personal-data`: ningún hallazgo de Azure cuenta y todos los recursos de datos
  quedan *sin calificar* (ADR 0008, L4).

## Decisión

| # | Decisión | Por qué |
|---|---|---|
| T1 | **Un archivo de tags exportado aparte**, con la identidad de solo lectura: `az resource list --query "[].{id:id, tags:tags}" -o json`. Los comandos `report`, `draft` y `review` lo reciben con `--resource-tags` y lo unen a los hallazgos por el ID del recurso, sin distinguir mayúsculas (`parsers/resource_tags.py`) | Desbloquea la Fase 10 sin esperar a Prowler. Es el mismo dato que ve el portal y lo lee una identidad que no puede modificar nada |
| T2 | **El escaneo manda:** el archivo solo completa los hallazgos que llegan **sin ningún** tag | Cuando Prowler exporte los tags de Azure, el archivo deja de tener efecto sin cambiar código, y nunca contradice al escáner |
| T3 | **El manifest registra el archivo** (`resource_tags`: nombre, SHA-256 y cuántos hallazgos completó) | Es un insumo que cambia la clasificación y, con ella, el riesgo: la cadena de custodia debe incluirlo |
| T4 | **Un archivo mal formado detiene todo**, como un escaneo ilegible | Unos tags a medias cambiarían la clasificación sin que nadie lo note (ADR 0003) |
| T5 | **Reportar la limitación a Prowler** (issue público), como se hizo con NIST CSF 2.0 | La corrección de origen beneficia a todos y permite retirar el archivo |

## Consecuencias

- **Un paso más en cada escaneo de Azure,** local y en CI: exportar los tags justo después del escaneo, para que
  ambos describan el mismo momento. Si pasa tiempo entre los dos, un tag cambiado puede no coincidir con el
  hallazgo.
- **El archivo tiene IDs de suscripción**: va a `output/` (ignorado por Git), y la anonimización (Fase 10, paso
  10.8) debe cubrirlo si se publica una muestra.
- **Solo recursos.** `az resource list` no incluye la suscripción ni los objetos de Entra ID; esos hallazgos
  siguen sin tags, igual que en AWS los de la cuenta.

## Revisión

Retirar el archivo cuando Prowler exporte los tags de Azure: el test de que *el escaneo manda* asegura que
mientras tanto no hay conflicto.
