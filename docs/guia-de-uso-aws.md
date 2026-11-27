# Guía de uso: de un escaneo de Prowler en AWS a un paquete revisado

El recorrido completo, desde el escaneo hasta el paquete que se entrega al auditor. Azure sigue el mismo
flujo con dos diferencias (ver [laboratorio.md](laboratorio.md) y el [ADR 0009](adr/0009-tags-de-azure-desde-archivo-aparte.md)).

No hay un solo botón de "aprobar". Una persona aprueba **tres cosas**, en momentos distintos:

1. **Los textos de la IA**, con el comando `review` (paso 5).
2. **Las decisiones de cada declaración**, en las columnas resaltadas del Excel (paso 7).
3. **Los riesgos que no se mitigan**, en el registro de tratamiento (paso 8).

```
1. Prowler ─► 2. report (sin IA) ─► 3. ¿escaneo sano? ──no──► corregir tags y volver a 1
                                          │ sí
                                          ▼
              4. draft (IA) ─► 5. review (textos) ─► 6. report --drafts
                                                            │
              9. verify ◄── 8. tratamiento de riesgos ◄── 7. revisar archivos y decidir
```

## Paso 0. Preparar la sesión

Siempre desde la raíz del repo: las salidas caen en `output/`, `reports/` y `drafts/`, que están en `.gitignore`
porque contienen datos reales de la cuenta.

```powershell
cd <ruta del repo>
.\.venv\Scripts\Activate.ps1
aws sso login --profile cc-audit
```

## Paso 1. Escanear con Prowler

```powershell
prowler aws --profile cc-audit -f us-east-1 --scan-unused-services -M csv json-ocsf -o output
```

- **`cc-audit`** es el perfil de solo lectura (`SecurityAudit` + `ViewOnlyAccess`): la herramienta que mide no
  puede modificar lo que mide.
- **`--scan-unused-services`** incluye los servicios que no se usan: uno mal configurado sigue siendo una puerta.
- Deja `output/prowler-output-<cuenta>-<fecha>.ocsf.json`, el insumo de todo lo demás. **No se edita:** su
  SHA-256 queda en el manifest.

## Paso 2. Generar los entregables (sin IA)

```powershell
python -m compliance_copilot report output\<escaneo>.ocsf.json -o reports\<fecha>
```

Todo número y estado sale de reglas documentadas ([metodología de riesgo](metodologia-riesgo.md)) y verificadas
con tests. Código de salida `0` si todo salió bien; `3` si algún hallazgo no se pudo leer
([ADR 0003](adr/0003-hallazgos-invalidos-se-reportan.md)): los entregables se generan igual y lo advierten.

## Paso 3. Comprobar que el escaneo está sano

En `reports/<fecha>/resumen.md`. Si algo falla, se corrige y se vuelve al paso 1: no tiene sentido redactar ni
aprobar sobre un escaneo incompleto.

| Qué mirar | Si aparece | Qué hacer |
|---|---|---|
| Hallazgos no leídos | Alguno | Revisar el motivo: suele ser un cambio de formato de Prowler |
| Recursos sin clasificar (`A.5.12`) | Recursos de datos sin `data-classification` | Poner el tag y escanear de nuevo; sin él, el motor usa un impacto por defecto |
| Ley 1581: recursos sin calificar | Recursos de datos sin `personal-data` | Decidir `yes` o `no`, poner el tag y escanear de nuevo |

## Paso 4. Redactar con la IA

Primero, sin costo, qué datos saldrían hacia la API (anonimizados y con seudónimos):

```powershell
python -m compliance_copilot draft output\<escaneo>.ocsf.json --levels critical,high --dry-run
```

Después, la redacción:

```powershell
python -m compliance_copilot draft output\<escaneo>.ocsf.json --levels critical,high
```

- La llave se lee de la variable de entorno `ANTHROPIC_API_KEY`; nunca va en un archivo.
- `--levels critical,high`: solo los riesgos que merecen un hallazgo de auditoría formal.
- Deja `drafts/<fecha>-sonnet.json`, con cada borrador **pendiente**.
- El modelo no puede cambiar cifras: la validación rechaza un borrador que altere el nivel, el riesgo o los
  controles ([redaccion-ia.md](redaccion-ia.md)).

## Paso 5. Aprobar los textos de la IA (aprobación 1)

```powershell
python -m compliance_copilot review output\<escaneo>.ocsf.json --reviewer "Nombre Apellido"
```

Por cada borrador se muestran los datos y el texto, y se pide una decisión:

| Opción | Cuándo | Qué queda registrado |
|---|---|---|
| **a**probar | El texto es correcto tal cual | Nombre, fecha y hash del texto |
| **e**ditar | Casi bien: se edita campo por campo | Lo que escribió la IA y lo que dejó la persona |
| **r**echazar | Está mal; el motivo es obligatorio | El motivo; no se publica |
| **s**altar / **q** salir | Para después | Nada; se retoma luego |

No existe "aprobar todo" ([ADR 0004](adr/0004-ia-redacta-persona-aprueba.md)). Qué mirar: que describa el
hallazgo real, que el criterio cite el control correcto, que la corrección sea aplicable y que no invente nada
que no esté en los datos.

## Paso 6. Regenerar con los textos aprobados

```powershell
python -m compliance_copilot report output\<escaneo>.ocsf.json -o reports\<fecha> --drafts drafts\<fecha>-sonnet.json
```

Agrega `hallazgos-auditoria.md` (solo lo aprobado o editado) y `evidencias/redaccion-ia.json` (el registro
completo, incluidos los rechazados). Si el escaneo cambia después de aprobar, el texto queda **desactualizado**
y deja de publicarse.

## Paso 7. Revisar los archivos y decidir (aprobación 2)

De lo general a lo particular. Las decisiones se llenan en las **columnas resaltadas** de
`compliance-copilot.xlsx`; los `.md` son para leer ([entregables.md](entregables.md)).

| # | Archivo | Qué revisar | Qué decide la persona |
|---|---|---|---|
| 1 | `resumen.md` | Riesgos por nivel, mapa de calor, estado de cada marco | — |
| 2 | `matriz-riesgos.md` | Cada riesgo con su cálculo. ¿La clasificación de cada recurso es la correcta? | Confirmar o cambiar el tratamiento sugerido |
| 3 | `plan-remediacion.md` | Una acción por check, por riesgo. ¿El orden tiene sentido para el negocio? | — |
| 4 | `hallazgos-auditoria.md` | Los textos aprobados en el paso 5 | — |
| 5 | `soa-iso27001.md` | 93 controles; los organizacionales salen como *Evidencia manual requerida* | **Aplicable**, **Justificación** |
| 6 | `matriz-soc2.md` | 61 criterios | **En alcance**, **Justificación** |
| 7 | `perfil-nist-csf.md` | 106 subcategorías (perfil actual) | **Perfil objetivo**, **Prioridad** |
| 8 | `matriz-ley-1581.md` | 50 obligaciones, datos fuera del país, recursos sin calificar | **Aplica** (sugerida en los arts. 17 y 18), **Evidencia manual**; en la hoja *Revisión datos personales*, el contrato de transmisión de cada recurso |
| 9 | `evidencias/` | Muestreo: que cada `controles/<marco>/<requisito>.json` sustente su estado | — |

> **Importante:** el Excel está en el manifest. Editarlo en su lugar hace fallar `verify` (paso 9). Las
> decisiones se llenan en una **copia** fuera del paquete (por ejemplo, `compliance-copilot-revisado.xlsx`): el
> paquete original queda intacto y verificable, y la copia es la versión revisada.

## Paso 8. Registrar los riesgos que no se mitigan (aprobación 3)

Un riesgo que se acepta, transfiere o evita va a [tratamiento-riesgos.md](tratamiento-riesgos.md), con el formato
de R-01 a R-07: check, control ISO, riesgo calculado, tratamiento, **justificación**, **dueño** y **fecha de
revisión**. Sin justificación documentada, aceptar un riesgo es una no conformidad; con ella, es una decisión de
gestión.

## Paso 9. Verificar el paquete antes de entregarlo

```powershell
python -m compliance_copilot verify reports\<fecha>\manifest.json --source output\<escaneo>.ocsf.json
```

Debe responder *"Todos los archivos coinciden con el manifest."* Comprueba que ningún entregable cambió y que el
escaneo de origen es el que se usó. Si algo no coincide, sale con código `4` y dice qué archivo. Es la misma
verificación que hace el auditor al recibir el paquete.

## Variante: escaneo desde GitHub Actions

Los pasos 1 y 2 los hace el workflow `Scan` ([ci.md](ci.md)):

1. `gh workflow run Scan --ref main`, y aprobarlo en *Review deployments → aws-lab* (también es una aprobación).
2. Descargar el paquete del bucket de evidencias con el perfil `cc-lab` (`cc-audit` puede listar el bucket, pero
   no leer su contenido) a `escaneo-ci/`, que está en `.gitignore`.
3. Antes del paso 9, verificar la firma: prueba que el paquete lo generó el workflow del repo.

   ```powershell
   gh attestation verify escaneo-ci\reports\ci\manifest.json --repo SebiceC/Compliance_Copilot --signer-workflow SebiceC/Compliance_Copilot/.github/workflows/scan.yml
   ```

4. Los pasos 3 a 9 se hacen en local sobre el escaneo descargado.
