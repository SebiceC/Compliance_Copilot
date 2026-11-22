# 6. Escaneo desde GitHub Actions con OIDC, sin llaves de larga duración

- **Fecha:** 2026-11-21
- **Estado:** Aceptada

## Contexto

El escaneo se ejecutaba a mano, desde el equipo de una persona, con su sesión de IAM Identity Center. Para que
sea repetible y trazable al código que lo generó, debe correr en CI (GitHub Actions). CI necesita credenciales de
AWS, y el repo es **público**: cualquiera puede leer el código, los workflows y los logs de ejecución.

## Opciones consideradas

- **Usuario IAM con access key guardada como secreto de GitHub:** simple, pero la llave no expira; si se filtra
  (un log, una dependencia comprometida), sirve hasta que alguien la revoque. Es justo lo que Prowler reporta
  como hallazgo.
- **Runner propio en el equipo local:** las credenciales no salen de la máquina, pero un repo público permitiría
  que un pull request ejecute código en ella.
- **OIDC:** GitHub emite un token firmado de corta duración por ejecución; AWS lo verifica y entrega credenciales
  temporales de un rol.

## Decisión

OIDC, con estas restricciones:

| Control | Implementación |
|---|---|
| Quién puede asumir el rol | Política de confianza con `StringEquals` sobre `sub = repo:SebiceC@111653598/Compliance_Copilot@1450598856:environment:aws-lab` (sin comodines; incluye los IDs inmutables del dueño y del repo) |
| Aprobación humana | Environment `aws-lab` con revisor obligatorio y solo la rama `main` |
| Qué puede hacer el rol | `SecurityAudit` + `ViewOnlyAccess` (igual que el escaneo local) y `s3:PutObject` solo en `scans/*` del bucket de evidencias |
| Duración | Sesión de 1 hora; nombre de sesión `gha-scan-<run_id>` (trazable en CloudTrail) |
| Dónde quedan los resultados | Bucket S3 privado: sin acceso público, cifrado SSE-S3, solo TLS, borrado a los 30 días |
| Logs públicos | La salida de Prowler y de `report` va a archivos en el bucket, no al log; ID de cuenta enmascarado; el resumen solo tiene conteos |
| Cadena de suministro | Acciones fijadas por hash de commit; Prowler con versión fija; token de GitHub con permisos mínimos |
| Origen de la evidencia | El `manifest.json` se firma con artifact attestations (Sigstore, mismo OIDC, sin llaves): prueba qué repo, workflow y commit lo generaron |

El rol **escribe**, pero solo en su propio bucket de evidencias, nunca en los recursos que mide; y solo puede
crear objetos, no leerlos, listarlos ni borrarlos. El principio "la herramienta que mide no puede modificar lo
que mide" se mantiene.

**Formato del `sub`.** GitHub incluye en el token los IDs numéricos inmutables del dueño y del repo
(`repo:<dueño>@<id>/<repo>@<id>:...`). Si el repo se borra o cambia de nombre y alguien crea otro con el mismo
nombre, tendrá otro ID y no podrá asumir el rol. El valor exacto se obtuvo del evento de CloudTrail del primer
intento rechazado (`userName` de `AssumeRoleWithWebIdentity`).

## Consecuencias

- **Ganamos:** ninguna credencial de AWS guardada en GitHub; cada escaneo queda ligado a un commit, una ejecución
  y una aprobación; un workflow comprometido no puede leer ni borrar escaneos anteriores.
- **Aceptamos:** cada escaneo necesita un clic de aprobación; los resultados se descargan del bucket, no de
  GitHub; cuidar que ningún paso nuevo imprima datos de la cuenta en el log.
- **Nos obliga a futuro:** cualquier permiso nuevo del rol requiere actualizar este ADR. La redacción con IA
  sigue en local (ADR 0004): CI no recibe la credencial de Anthropic.

## Revisión

Reevaluar al agregar la ejecución programada (el revisor obligatorio la bloquearía), al escanear varias cuentas
o al agregar Azure (federación equivalente con Entra ID).
