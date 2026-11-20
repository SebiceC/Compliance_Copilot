# 2. Exigir Python 3.13 como versión mínima

- **Fecha:** 2026-11-19
- **Estado:** Aceptada

## Contexto

El proyecto se desarrolla con Python 3.13 y lo declara en `requires-python` de `pyproject.toml`. Ese campo es
una promesa: pip instalará el paquete en cualquier versión que lo cumpla. Python no tiene versiones LTS; cada
versión recibe unos 2 años de correcciones y parches de seguridad hasta cumplir 5 años. A la fecha, 3.10 ya
llegó a su fin de vida, 3.11 lo hace en octubre de 2027, 3.12 en octubre de 2028 y 3.13 en octubre de 2029.

## Opciones consideradas

- **`>=3.12`**
  - A favor: el paquete se instala en más entornos (runners de CI, máquinas de otros auditores).
  - En contra: se desarrolla en 3.13, así que usar sin querer algo exclusivo de 3.13 rompería la promesa sin
    aviso; obliga a probar en las dos versiones para que la promesa sea verificable.
- **`>=3.13`**
  - A favor: la versión declarada es la misma con la que se desarrolla y prueba; soporte de seguridad hasta
    2029; matriz de CI más simple.
  - En contra: no se instala en entornos que solo tengan 3.12 o anteriores.

## Decisión

Exigir **Python 3.13 o superior**. Para una herramienta de seguridad se prefiere no prometer compatibilidad que
no se está verificando.

## Consecuencias

- **Ganamos:** lo que se declara coincide con lo que se ejecuta; no hay desfase entre el entorno local y el
  de CI.
- **Aceptamos:** quien tenga 3.12 o anterior debe instalar 3.13 para usar la herramienta.
- **Nos obliga a futuro:** el workflow de GitHub Actions debe usar 3.13 (como mínimo), y una versión nueva de
  Python se agrega a la matriz de CI antes de declararla soportada.

## Revisión

Reevaluar si un entorno objetivo real (por ejemplo, el runner o la máquina de quien adopte la herramienta) no
puede usar 3.13, o al acercarse el fin de vida de 3.13 en octubre de 2029. Si cambia, se crea un nuevo ADR y
este pasa a estado *Reemplazada por ADR-XXXX*.
