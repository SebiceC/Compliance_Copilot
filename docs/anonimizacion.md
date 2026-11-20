# Anonimización de la salida de Prowler

La salida de Prowler contiene identificadores de la cuenta real en cientos de lugares: ARN, nombres de bucket,
el nombre de la cuenta y el ID de la organización. El anonimizador (`src/compliance_copilot/sanitize.py`) los
reemplaza por seudónimos antes de que un archivo salga de la máquina del auditor.

## Para qué se usa

| Uso | Por qué hace falta anonimizar |
|---|---|
| Muestras en `data/samples/` | El repositorio es público; las muestras permiten probar el parser con datos reales |
| Tests (Fase 1, parte 5) | Los tests necesitan hallazgos reales, pero no pueden depender de `output/`, que no se versiona |
| Envío al agente de IA (fase posterior) | Minimización de datos: el modelo no necesita saber qué cuenta es para redactar un hallazgo |
| Compartir ejemplos | Un issue, una presentación o una entrevista no deben exponer la cuenta |

## Cómo se usa

```bash
python -m compliance_copilot.sanitize output/<escaneo>.ocsf.json data/samples/prowler-aws-lab.ocsf.json --only-label project:compliance-copilot
```

`--only-label` es opcional y conserva solo los hallazgos de los recursos del laboratorio. La muestra
`data/samples/prowler-aws-lab.ocsf.json` se generó así a partir del segundo escaneo (2026-11-16): 76 hallazgos
(29 FAIL, 47 PASS) que cubren los cuatro niveles de `data-classification`.

## Qué se reemplaza

| Categoría | Ejemplo de seudónimo | Por qué |
|---|---|---|
| ID de cuenta AWS (12 dígitos, también dentro de ARN y nombres) | `123456789001` | Identifica la cuenta |
| Nombre de la cuenta (`cloud.account.name`), en cualquier parte y sin distinguir mayúsculas | `example-account` | Suele ser el nombre de una persona o empresa; también aparece como nombre de usuario IAM |
| ID de organización (`o-…`) y de OU (`ou-…`) | `o-example00001` | Identifica la organización |
| ID canónico de S3 (64 hexadecimales) | `000…001` | Identifica al dueño de la cuenta en S3 |
| Sufijo de los roles de Identity Center (`AWSReservedSSO_<set>_<sufijo>`) | `AWSReservedSSO_LabAdmin_0000000000000001` | El sufijo es único de la instancia; el nombre del permission set se conserva porque describe el diseño |
| IDs únicos de IAM (`AIDA…`, `AROA…`, `AGPA…`, `ANPA…`, `AIPA…`) | `AIDAEXAMPLE0000000001` | Identifican un principal o política concretos |
| Llaves de acceso (`AKIA…`, `ASIA…`) | `AKIAEXAMPLE000000001` | No deberían aparecer; si aparecen, no pueden salir |
| Correos electrónicos | `user1@example.com` | Dato personal (Ley 1581) |
| IPv4 **públicas** | `203.0.113.N` (rango reservado para documentación, RFC 5737) | Pueden identificar infraestructura |

**Los seudónimos son consistentes dentro de un archivo:** el mismo valor real recibe siempre el mismo
seudónimo. Así se conservan las relaciones (dos hallazgos del mismo recurso siguen apuntando al mismo recurso).

## Qué no se reemplaza, a propósito

- **IP privadas y `0.0.0.0/0`:** son iguales en cualquier cuenta (`172.31.0.0/16` es el rango por defecto de la
  VPC) y `0.0.0.0/0` es justamente la evidencia del hallazgo de SSH abierto.
- **Identificadores de control bajo `compliance`:** valores como `3.5.1.2` tienen forma de IP, pero son
  controles de un marco.
- **IDs de recursos (`sg-…`, `vpc-…`) y nombres de recursos del laboratorio:** no identifican la cuenta por sí
  solos y son necesarios para leer el hallazgo.
- **Región:** es evidencia del alcance.

## Verificación

Antes de escribir el archivo, el anonimizador busca en el texto final **cada valor real que reemplazó**. Si
encuentra alguno, no escribe nada y termina con error. Al final imprime cuántos reemplazos hizo por categoría.

## Límites

- **Solo detecta lo que tiene un patrón.** Un dato personal escrito en un tag o en el nombre de un recurso
  (por ejemplo, un bucket llamado con el nombre de un cliente) no se detecta. Revisar a mano antes de publicar.
- **La consistencia es por archivo.** Dos ejecuciones sobre archivos distintos pueden asignar seudónimos
  diferentes al mismo valor real.
- **Cualquier número de 12 dígitos se trata como ID de cuenta.** Es preferible reemplazar de más que de menos.
- **Seudonimización, no anonimización irreversible:** quien tenga el archivo original puede relacionar los
  seudónimos. El archivo anonimizado por sí solo no permite recuperar los valores reales.
