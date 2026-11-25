# Metodología: matriz técnica de la Ley 1581 de 2012

Cómo se construye `matriz-ley-1581.md`. Las decisiones y su porqué están en el
[ADR 0008](adr/0008-ley-1581-derivada-de-iso.md); la tabla de correspondencia, revisada fila por fila, en
[correspondencia-ley-1581.md](correspondencia-ley-1581.md).

> **Límite.** La matriz evidencia la **parte técnica** de las obligaciones. No es una opinión jurídica ni una
> declaración de cumplimiento: *Aplica* y *Evidencia manual* los decide el responsable del tratamiento.

## 1. De un hallazgo a una obligación

```
Hallazgo de Prowler ─► controles ISO 27001 que Prowler le asigna ─► obligaciones de la ley
   (s3_bucket_default_encryption)        (A.8.24)                 (4 g, 4 h, 17 d, 18 b)
```

1. **Filtro de datos personales** (sección 2): si el hallazgo no cuenta, no llega a la matriz.
2. **Traducción:** cada control ISO del hallazgo se busca en la tabla (`aliases`). Un control puede llevar a
   varias obligaciones, y el hallazgo cuenta en todas.
3. **Exclusiones:** los controles ISO que se decidió no llevar a la ley (`excluded`) se ignoran. Un control que
   no está en la tabla ni en las exclusiones aparece en la sección *Controles sin correspondencia*.
4. **Estado técnico:** el mismo de las demás declaraciones (con brechas, requiere revisión, sin brechas
   detectadas, evidencia manual requerida). Una obligación sin controles ISO (las documentales) siempre sale como
   *Evidencia manual requerida*.
5. **Alcance del estado técnico:** cuando los controles ISO evidencian un paso previo y no la obligación misma,
   el catálogo lo declara (`technical_scope`) y la matriz lo muestra junto al título. Hoy aplica a `L1581-17n` y
   `L1581-18k`: el estado mide la capacidad de detectar una violación de seguridad, no su notificación a la SIC.

## 2. Qué hallazgos cuentan

El tag `personal-data=yes|no` lo pone el dueño del activo, y la Tag Policy solo admite esos dos valores. La
herramienta ignora mayúsculas y espacios al leerlo, como con `data-classification`.

| Grupo del recurso (motor de riesgo) | Cuenta si... |
|---|---|
| **Datos** (S3, bases de datos, volúmenes, llaves, logs) | tiene `personal-data=yes` |
| **Cuenta** (root, CloudTrail, políticas de la cuenta) | la cuenta tiene al menos un recurso con `personal-data=yes` |
| **Infraestructura** (redes, cómputo, identidades) | igual que la cuenta |

| Caso | Resultado |
|---|---|
| Recurso de datos con `personal-data=no` | No cuenta |
| Recurso de datos sin el tag o con otro valor | No cuenta; aparece en *Requiere revisión: recursos de datos sin calificar* |
| Cuenta sin ningún recurso con `yes` | Ningún hallazgo de cuenta o infraestructura cuenta |
| Varias cuentas en el escaneo | La regla se aplica por cuenta |
| Configuración de la cuenta que Prowler reporta con un tipo de datos (`ec2_ebs_default_encryption` como `AwsEc2Volume`, `backup_vaults_exist` como `AwsBackupBackupVault`) | Cuenta como hallazgo de **cuenta**: no hay un recurso que etiquetar. Se reconoce porque el nombre del recurso es el ID de la cuenta o el ARN no tiene ID de recurso (`risk.is_account_setting`) |

## 3. Circulación internacional

**Calificación por defecto: transmisión.** El proveedor de nube trata los datos por cuenta de la organización
(encargado, Decreto 1377, art. 3). La transmisión exige un contrato con el contenido del art. 25 del decreto; la
transferencia (art. 26 de la ley; Circular Externa 005 de 2017) queda como alternativa a verificar.

Por cada recurso con `personal-data=yes` cuya región no esté en `local_regions` (hoy ninguna, porque el proveedor
no tiene región en Colombia):

- la matriz lo lista en *Datos personales fuera del país*, con este texto:

  > Recurso con datos personales fuera de Colombia: `<recurso>` · región `<región>` (<país>). Verificar: si el
  > proveedor actúa como encargado, que exista un contrato de transmisión conforme al art. 25 del Decreto 1377 de
  > 2013; si se trata de una transferencia, el fundamento del art. 26 de la Ley 1581.

- las obligaciones `L1581-26`, `D1377-25` y `SIC-C005` pasan a *Requiere revisión*;
- la hoja *Revisión datos personales* deja la columna **Evidencia manual** para anotar el contrato o el
  fundamento revisado (por ejemplo, *"DPA del proveedor, revisado contra el art. 25"*).

Es un señalamiento, no un incumplimiento. Un recurso se señala una vez, aunque tenga muchos hallazgos.

## 4. Evidencias

- `evidencias/controles/LEY-1581/<obligación>.json`: los hallazgos que sustentan cada obligación técnica.
- `evidencias/controles/LEY-1581/_datos-personales.json`: los recursos fuera del país (con el texto del
  señalamiento) y los recursos sin calificar.

## 5. Mantenimiento

La fuente es una sola: el catálogo `src/compliance_copilot/catalogs/ley-1581.json`. Un test
(`tests/test_ley_1581.py`) comprueba que coincide con `docs/correspondencia-ley-1581.md`: obligaciones, tabla
ISO → obligación, exclusiones y texto del señalamiento. Cambiar una fila es cambiar los dos, y la revisión
jurídica se repite para esa fila.
