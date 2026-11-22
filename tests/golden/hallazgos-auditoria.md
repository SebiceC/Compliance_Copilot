# Hallazgos de auditoría

- **Escaneo:** 01a1e65c-e279-7558-9355-5aa6612eb8fd · prowler 5.48.0 · 2026-11-17 02:56 UTC
- **Cuentas:** 123456789001 · **Metodología de riesgo:** v0.2

Redacción asistida por IA. **Solo se muestra el texto aprobado por una persona**; el resto aparece con el texto técnico del escáner y su estado. Los niveles de riesgo y los controles los calcula la metodología, no la IA.

| Estado de la redacción | Hallazgos |
|---|---|
| Sin redacción | 20 |

## 1. CloudTrail trail S3 bucket has MFA delete enabled

**Riesgo:** Alto (15) · **Recursos:** lab-trail · **ISO 27001:** sin mapeo

> Redacción: **Sin redacción**. Texto técnico del escáner: CloudTrail trail S3 bucket has MFA delete enabled.

## 2. CloudTrail trail logs are encrypted at rest with a KMS key

**Riesgo:** Alto (15) · **Recursos:** lab-trail · **ISO 27001:** A.8.11, A.8.15, A.8.16, A.8.24

> Redacción: **Sin redacción**. Texto técnico del escáner: CloudTrail trail logs are encrypted at rest with a KMS key.

## 3. CloudTrail trail has log file validation enabled

**Riesgo:** Alto (15) · **Recursos:** lab-trail · **ISO 27001:** A.8.15, A.8.16

> Redacción: **Sin redacción**. Texto técnico del escáner: CloudTrail trail has log file validation enabled.

## 4. CloudTrail trail destination S3 bucket has access logging enabled

**Riesgo:** Alto (15) · **Recursos:** lab-trail · **ISO 27001:** A.8.15, A.8.16

> Redacción: **Sin redacción**. Texto técnico del escáner: CloudTrail trail destination S3 bucket has access logging enabled.

## 5. S3 bucket has server-side encryption with AWS KMS

**Riesgo:** Alto (12) · **Recursos:** aws-cloudtrail-logs-123456789001-5f59e248, cc-lab-data-7asda3 · **ISO 27001:** A.8.11, A.8.24

> Redacción: **Sin redacción**. Texto técnico del escáner: S3 bucket has server-side encryption with AWS KMS.

## 6. S3 bucket has MFA Delete enabled

**Riesgo:** Alto (12) · **Recursos:** aws-cloudtrail-logs-123456789001-5f59e248, cc-lab-data-7asda3 · **ISO 27001:** sin mapeo

> Redacción: **Sin redacción**. Texto técnico del escáner: S3 bucket has MFA Delete enabled.

## 7. S3 bucket has object versioning enabled

**Riesgo:** Alto (12) · **Recursos:** aws-cloudtrail-logs-123456789001-5f59e248, cc-lab-data-7asda3 · **ISO 27001:** A.8.10, A.8.3

> Redacción: **Sin redacción**. Texto técnico del escáner: S3 bucket has object versioning enabled.

## 8. S3 bucket policy denies requests over insecure transport

**Riesgo:** Alto (12) · **Recursos:** aws-cloudtrail-logs-123456789001-5f59e248, cc-lab-data-7asda3 · **ISO 27001:** sin mapeo

> Redacción: **Sin redacción**. Texto técnico del escáner: S3 bucket policy denies requests over insecure transport.

## 9. S3 bucket has server access logging enabled

**Riesgo:** Alto (12) · **Recursos:** aws-cloudtrail-logs-123456789001-5f59e248, cc-lab-data-7asda3 · **ISO 27001:** A.8.15

> Redacción: **Sin redacción**. Texto técnico del escáner: S3 bucket has server access logging enabled.

## 10. CloudTrail trail has delivered logs to CloudWatch Logs in the last 24 hours

**Riesgo:** Alto (10) · **Recursos:** lab-trail · **ISO 27001:** A.8.15, A.8.16

> Redacción: **Sin redacción**. Texto técnico del escáner: CloudTrail trail has delivered logs to CloudWatch Logs in the last 24 hours.

## 11. CloudTrail trail has Insights enabled

**Riesgo:** Alto (10) · **Recursos:** lab-trail · **ISO 27001:** sin mapeo

> Redacción: **Sin redacción**. Texto técnico del escáner: CloudTrail trail has Insights enabled.

## 12. S3 bucket has cross-region replication configured to a bucket in a different region

**Riesgo:** Medio (8) · **Recursos:** aws-cloudtrail-logs-123456789001-5f59e248, cc-lab-data-7asda3 · **ISO 27001:** A.8.14

> Redacción: **Sin redacción**. Texto técnico del escáner: S3 bucket has cross-region replication configured to a bucket in a different region.

## 13. S3 bucket has event notifications enabled

**Riesgo:** Medio (8) · **Recursos:** aws-cloudtrail-logs-123456789001-5f59e248, cc-lab-data-7asda3 · **ISO 27001:** sin mapeo

> Redacción: **Sin redacción**. Texto técnico del escáner: S3 bucket has event notifications enabled.

## 14. S3 bucket has a lifecycle configuration enabled

**Riesgo:** Medio (8) · **Recursos:** aws-cloudtrail-logs-123456789001-5f59e248, cc-lab-data-7asda3 · **ISO 27001:** A.8.10

> Redacción: **Sin redacción**. Texto técnico del escáner: S3 bucket has a lifecycle configuration enabled.

## 15. S3 bucket has Object Lock enabled

**Riesgo:** Medio (8) · **Recursos:** aws-cloudtrail-logs-123456789001-5f59e248, cc-lab-data-7asda3 · **ISO 27001:** sin mapeo

> Redacción: **Sin redacción**. Texto técnico del escáner: S3 bucket has Object Lock enabled.

## 16. IAM user has hardware MFA enabled

**Riesgo:** Medio (8) · **Recursos:** lab-user-nomfa · **ISO 27001:** A.8.5

> Redacción: **Sin redacción**. Texto técnico del escáner: IAM user has hardware MFA enabled.

## 17. IAM user has MFA enabled for console access or no console password is set

**Riesgo:** Medio (8) · **Recursos:** lab-user-nomfa · **ISO 27001:** A.5.15, A.5.17, A.8.5

> Redacción: **Sin redacción**. Texto técnico del escáner: IAM user has MFA enabled for console access or no console password is set.

## 18. Security group does not allow ingress from 0.0.0.0/0 or ::/0 to TCP port 22 (SSH)

**Riesgo:** Medio (5) · **Recursos:** sg-053b7f11882dc35d0 · **ISO 27001:** A.8.20, A.8.21, A.8.22

> Redacción: **Sin redacción**. Texto técnico del escáner: Security group does not allow ingress from 0.0.0.0/0 or ::/0 to TCP port 22 (SSH).

## 19. IAM user has no inline or attached policies

**Riesgo:** Bajo (4) · **Recursos:** lab-user-nomfa/IAMUserChangePassword · **ISO 27001:** A.5.15

> Redacción: **Sin redacción**. Texto técnico del escáner: IAM user has no inline or attached policies.

## 20. Non-default EC2 security group is in use

**Riesgo:** Bajo (2) · **Recursos:** sg-053b7f11882dc35d0 · **ISO 27001:** A.8.20, A.8.21, A.8.22

> Redacción: **Sin redacción**. Texto técnico del escáner: Non-default EC2 security group is in use.
