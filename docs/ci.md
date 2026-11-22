# CI: tests y escaneo en GitHub Actions

Dos workflows en `.github/workflows/`, con niveles de riesgo distintos. Las decisiones están en el
[ADR 0006](adr/0006-ci-con-oidc-sin-llaves.md).

| Workflow | Cuándo | Credenciales | Qué hace |
|---|---|---|---|
| `ci.yml` | Cada push a `main` y cada pull request | Ninguna | Instala el proyecto con Python 3.13 y corre `pytest` con la muestra anonimizada |
| `scan.yml` | Manual (Actions → Scan → Run workflow), con aprobación | OIDC → rol de AWS, 1 hora | Prowler → `report` → bucket de evidencias |

## Cómo obtiene credenciales el escaneo

```
GitHub Actions (job en el Environment aws-lab, aprobado por una persona)
   │  1. pide un token OIDC firmado por GitHub ("repo:SebiceC@111653598/Compliance_Copilot@1450598856:environment:aws-lab")
   ▼
AWS STS
   │  2. verifica la firma con el proveedor OIDC de la cuenta
   │  3. compara el token con la política de confianza del rol GitHubActionsProwler
   ▼
Credenciales temporales (1 hora)
   │  SecurityAudit + ViewOnlyAccess → Prowler lee la configuración de la cuenta
   │  s3:PutObject en scans/*         → sube el paquete
   ▼
Bucket de evidencias (privado, cifrado, solo TLS, borrado a 30 días)
```

No hay ninguna llave de AWS guardada en GitHub. Los secretos del Environment (`AWS_ROLE_ARN`,
`EVIDENCE_BUCKET`) no son credenciales: son el nombre del rol y del bucket, guardados como secretos para que
GitHub los enmascare en los logs.

Si el rol rechaza el token (`Not authorized to perform sts:AssumeRoleWithWebIdentity`), el valor exacto que
envió GitHub está en CloudTrail: evento `AssumeRoleWithWebIdentity`, campo `userIdentity.userName`. Se compara
con la condición `sub` del rol.

## Logs públicos

El repo es público y los logs de Actions también. Por eso:

- la salida de Prowler y de `report` va a `logs/` y se sube al bucket, no al log (el banner de Prowler y los
  avisos del parser incluyen el ID de la cuenta);
- `mask-aws-account-id: true` al autenticarse;
- la subida a S3 no imprime rutas (`--only-show-errors`);
- el resumen de la ejecución solo muestra conteos (riesgos por nivel, controles, acciones).

Si se agrega un paso al workflow, comprobar que no imprima datos de la cuenta.

## Qué queda en el bucket

```
scans/<fecha UTC>-run<id de la ejecución>/
  output/    salida original de Prowler (OCSF y CSV)
  reports/   entregables, evidencias y manifest.json
  logs/      prowler.log y report.log
  attestation/manifest.sigstore.json   firma del manifest (para verificar sin conexión)
```

Para descargar y verificar un escaneo (con permisos de lectura sobre el bucket, por ejemplo LabAdmin):

```bash
aws s3 cp s3://<bucket>/scans/<carpeta>/ escaneo-ci --recursive --profile cc-lab
python -m compliance_copilot verify escaneo-ci/reports/ci/manifest.json --source escaneo-ci/output/<archivo>.ocsf.json
```

`escaneo-ci/` no debe quedar dentro del repo, o debe estar en `.gitignore`: contiene datos de la cuenta.

### Verificar el origen (firma)

`verify` prueba que nada cambió desde que se generó el manifest. La firma prueba **quién** lo generó: este repo,
el workflow `scan.yml`, en un commit y una ejecución concretos. Requiere la CLI de GitHub (`gh`):

```bash
gh attestation verify escaneo-ci/reports/ci/manifest.json --repo SebiceC/Compliance_Copilot --signer-workflow SebiceC/Compliance_Copilot/.github/workflows/scan.yml
```

Si alguien regenera el paquete fuera del workflow, los hashes pueden ser consistentes, pero la firma no
coincide. Cada ejecución muestra en su resumen el enlace a la firma que creó.

## Configuración (una sola vez)

En AWS (con LabAdmin): proveedor OIDC `token.actions.githubusercontent.com` (audiencia `sts.amazonaws.com`),
el bucket de evidencias y el rol `GitHubActionsProwler`; detalle en el ADR 0006.

En GitHub: Environment `aws-lab` con revisor obligatorio, solo la rama `main` y los secretos `AWS_ROLE_ARN` y
`EVIDENCE_BUCKET`. Recomendado en un repo público: secret scanning con push protection, Dependabot alerts,
permisos de workflow de solo lectura por defecto, aprobación para workflows de colaboradores externos y un
ruleset en `main` que exija el check `tests`.

## Exit codes

- Prowler termina con 3 si hay hallazgos FAIL: es lo normal y se ignora (`--ignore-exit-code-3`).
- `report` termina con 3 si hubo hallazgos que no se pudieron leer (ADR 0003): la ejecución sigue, con un aviso.
- Cualquier otro error marca la ejecución como fallida; los logs del bucket explican qué pasó.
