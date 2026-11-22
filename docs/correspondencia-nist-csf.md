# Correspondencia de los IDs de Prowler con NIST CSF 2.0

Prowler 5.48 llama "NIST CSF 2.0" a un mapeo cuyos IDs son, en su mayoría, de la **versión 1.1**: categorías que
ya no existen en la 2.0 (PR.AC, PR.IP, PR.PT, PR.MA, DE.DP, ID.BE, ID.SC), numeraciones de la 1.1 en categorías
que sí existen (PR.DS-03 a 08 no existen en la 2.0) e IDs sin la función (`co_1` podría ser RS.CO o RC.CO). Esta
tabla traduce cada uno de los 78 IDs a subcategorías de la versión 2.0 (ADR 0007, D3): los 68 de
Prowler 5.48 y los 10 que agregó después (rama `master` al 2026-11-22), para que una actualización de Prowler no
los deje sin correspondencia.

**Reportado a Prowler:** [prowler-cloud/prowler#13504](https://github.com/prowler-cloud/prowler/issues/13504)
(2026-11-22). Si Prowler adopta los IDs oficiales de la 2.0, los IDs nuevos se resolverán sin esta tabla
(normalización `identity`) y la tabla se podrá retirar.

**Fuentes:**

- NIST CSWP 29, *The NIST Cybersecurity Framework (CSF) 2.0* (2024-02-26), Apéndice A: las 106 subcategorías.
- NIST, *The NIST CSF 2.0 Core With Withdrawn CSF 1.1 Elements* (2024-03-25): a dónde se movió o incorporó cada
  elemento retirado de la 1.1. Cuando el documento nombra una categoría y además subcategorías, se usan las
  subcategorías.
- El texto de cada ID según el archivo de cumplimiento `nist_csf_2.0_aws` de Prowler (5.48 y `master`; categoría
  y descripción), para identificar a qué elemento de la 1.1 corresponde.

**Base de cada fila:**

| Base | Filas | Significado |
|---|---|---|
| Oficial | 56 | El ID es de la 1.1: destino según la tabla de NIST de elementos retirados, o el mismo ID si se conservó en la 2.0 |
| Texto 1.1 | 11 | Prowler lo rotula con una categoría de Gobernar (2.0), pero su texto es el de otro elemento de la 1.1 (columna "CSF 1.1"); destino según la tabla oficial de ese elemento |
| **Criterio** | 11 | Sin equivalencia oficial: el texto de Prowler no es de la 1.1 ni coincide con su número en la 2.0. Destino asignado por el significado. **Requiere revisión** |

Un ID con varios destinos cuenta en todas esas subcategorías: así reparte NIST el contenido de la 1.1. Un ID que
Prowler emita en el futuro y no esté en esta tabla aparece como "sin correspondencia" en los entregables.

| ID de Prowler | CSF 1.1 | Subcategorías CSF 2.0 | Base | Texto de Prowler (si la base no es oficial) |
|---|---|---|---|---|
| `ac_1` | PR.AC-01 | PR.AA-01, PR.AA-05 | Oficial |  |
| `ac_3` | PR.AC-03 | PR.AA-03, PR.AA-05, PR.IR-01 | Oficial |  |
| `ac_4` | PR.AC-04 | PR.AA-05 | Oficial |  |
| `ac_5` | PR.AC-05 | PR.IR-01 | Oficial |  |
| `ac_6` | PR.AC-06 | PR.AA-02 | Oficial |  |
| `ac_7` | PR.AC-07 | PR.AA-03 | Oficial |  |
| `ae_1` | DE.AE-01 | ID.AM-03 | Oficial |  |
| `ae_2` | DE.AE-02 | DE.AE-02 | Oficial |  |
| `ae_3` | DE.AE-03 | DE.AE-03 | Oficial |  |
| `ae_4` | DE.AE-04 | DE.AE-04 | Oficial |  |
| `ae_5` | DE.AE-05 | DE.AE-08 | Oficial |  |
| `am_1` | ID.AM-01 | ID.AM-01 | Oficial |  |
| `am_2` | ID.AM-02 | ID.AM-02 | Oficial |  |
| `am_3` | ID.AM-03 | ID.AM-03 | Oficial |  |
| `am_5` | ID.AM-05 | ID.AM-05 | Oficial |  |
| `am_6` | ID.AM-06 | GV.RR-02, GV.SC-02 | Oficial |  |
| `an_2` | RS.AN-02 | RS.MA-02, RS.MA-03, RS.MA-04 | Oficial |  |
| `be_5` | ID.BE-05 | GV.OC-04 | Oficial |  |
| `cm_1` | DE.CM-01 | DE.CM-01 | Oficial |  |
| `cm_2` | DE.CM-02 | DE.CM-02 | Oficial |  |
| `cm_3` | DE.CM-03 | DE.CM-03 | Oficial |  |
| `cm_4` | DE.CM-04 | DE.CM-01, DE.CM-09 | Oficial |  |
| `cm_5` | DE.CM-05 | DE.CM-01, DE.CM-09 | Oficial |  |
| `cm_6` | DE.CM-06 | DE.CM-06 | Oficial |  |
| `cm_7` | DE.CM-07 | DE.CM-01, DE.CM-03, DE.CM-06, DE.CM-09 | Oficial |  |
| `dp_4` | DE.DP-04 | DE.AE-06 | Oficial |  |
| `dp_5` | DE.DP-05 | ID.IM-03 | Oficial |  |
| `ds_1` | PR.DS-01 | PR.DS-01 | Oficial |  |
| `ds_2` | PR.DS-02 | PR.DS-02 | Oficial |  |
| `ds_3` | PR.DS-03 | ID.AM-08, PR.PS-03 | Oficial |  |
| `ds_4` | PR.DS-04 | PR.IR-04 | Oficial |  |
| `ds_5` | PR.DS-05 | PR.DS-01, PR.DS-02, PR.DS-10 | Oficial |  |
| `ds_6` | PR.DS-06 | PR.DS-01, DE.CM-09 | Oficial |  |
| `ds_7` | PR.DS-07 | PR.IR-01 | Oficial |  |
| `ds_8` | PR.DS-08 | ID.RA-09, DE.CM-09 | Oficial |  |
| `id_sc_4` | ID.SC-04 | GV.SC-07, ID.RA-10 | Oficial |  |
| `ip_1` | PR.IP-01 | PR.PS-01 | Oficial |  |
| `ip_12` | PR.IP-12 | ID.RA-01, PR.PS-02 | Oficial |  |
| `ip_2` | PR.IP-02 | ID.AM-08, PR.PS-06 | Oficial |  |
| `ip_3` | PR.IP-03 | PR.PS-01, ID.RA-07 | Oficial |  |
| `ip_4` | PR.IP-04 | PR.DS-11 | Oficial |  |
| `ip_7` | PR.IP-07 | ID.IM-03 | Oficial |  |
| `ip_8` | PR.IP-08 | ID.IM-03 | Oficial |  |
| `ip_9` | PR.IP-09 | ID.IM-04 | Oficial |  |
| `ma_2` | PR.MA-02 | ID.AM-08, PR.PS-02 | Oficial |  |
| `mi_3` | RS.MI-03 | ID.RA-06 | Oficial |  |
| `oc_1` | ID.BE-01 | GV.OC-05 | Texto 1.1 | El rol de la organización en la cadena de suministro se identifica y comunica |
| `oc_2` | ID.GV-03 | GV.OC-03 | Texto 1.1 | Requisitos legales, regulatorios y contractuales entendidos y gestionados |
| `oc_3` | ID.BE-02 | GV.OC-01 | Texto 1.1 | El lugar de la organización en la infraestructura crítica se identifica |
| `ov_1` | - | GV.OV-01 | **Criterio** | Los resultados de la estrategia de riesgo se revisan para ajustar prioridades |
| `ov_2` | - | GV.OV-03 | **Criterio** | El desempeño de la gestión de riesgos se mide y reporta |
| `ov_3` | - | GV.OV-02 | **Criterio** | La estrategia y las prácticas se revisan y ajustan ante cambios |
| `ov_4` | - | GV.OV-02 | **Criterio** | Los procesos se revisan para que cumplan requisitos legales y regulatorios |
| `po_1` | ID.GV-01 | GV.PO-01, GV.PO-02 | Texto 1.1 | La política de ciberseguridad se establece, comunica y aplica |
| `po_2` | - | GV.PO-02 | **Criterio** | La política se actualiza ante cambios de prioridades, amenazas o tecnología |
| `po_3` | ID.GV-03 | GV.OC-03 | Texto 1.1 | Requisitos legales y regulatorios entendidos y gestionados |
| `po_4` | ID.GV-04 | GV.RM-03 | Texto 1.1 | Los procesos de gobierno y gestión de riesgos abordan la ciberseguridad |
| `po_5` | - | GV.SC-05 | **Criterio** | Procesos para gestionar los requisitos de ciberseguridad de los proveedores |
| `pt_1` | PR.PT-01 | PR.PS-04 | Oficial |  |
| `pt_3` | PR.PT-03 | PR.PS-01 | Oficial |  |
| `pt_4` | PR.PT-04 | PR.AA-06, PR.IR-01 | Oficial |  |
| `pt_5` | PR.PT-05 | PR.IR-03 | Oficial |  |
| `ra_1` | ID.RA-01 | ID.RA-01 | Oficial |  |
| `ra_2` | ID.RA-02 | ID.RA-02 | Oficial |  |
| `ra_3` | ID.RA-03 | ID.RA-03 | Oficial |  |
| `ra_5` | ID.RA-05 | ID.RA-05 | Oficial |  |
| `rc_rp_1` | RC.RP-01 | RC.RP-01 | Oficial |  |
| `rm_1` | ID.RM-01 | GV.RM-01, GV.RM-06, GV.RR-03 | Texto 1.1 | Estrategia de gestión de riesgos establecida, comunicada y mantenida |
| `rm_2` | ID.RM-02 | GV.RM-02, GV.RM-04 | Texto 1.1 | Tolerancia al riesgo determinada y expresada |
| `rm_3` | ID.RM-03 | GV.RM-02 | Texto 1.1 | La tolerancia al riesgo considera el rol en infraestructura crítica |
| `rp_1` | RS.RP-01 | RS.MA-01 | Oficial |  |
| `rr_1` | ID.GV-02 | GV.OC-02, GV.RR-02 | Texto 1.1 | Roles coordinados y alineados con roles internos y socios externos |
| `rr_2` | - | GV.RR-02 | **Criterio** | Responsabilidades de ciberseguridad establecidas y comunicadas |
| `rr_3` | - | GV.RR-01 | **Criterio** | La alta dirección responde por el riesgo de ciberseguridad |
| `sc_1` | ID.SC-01 | GV.RM-05, GV.SC-01, GV.SC-06, GV.SC-09, GV.SC-10 | Texto 1.1 | Procesos de riesgo de la cadena de suministro identificados, evaluados y acordados |
| `sc_2` | - | GV.SC-01 | **Criterio** | Procesos de riesgo de la cadena de suministro establecidos y acordados |
| `sc_3` | - | GV.SC-07 | **Criterio** | Proveedores y terceros evaluados y monitoreados con esos procesos |
| `sc_4` | - | GV.SC-03 | **Criterio** | Los procesos de gestión de riesgos de la cadena de suministro se mejoran |
