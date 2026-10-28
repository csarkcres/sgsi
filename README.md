# SGSI Riesgos — MVP Docker

Aplicación web para administrar activos, riesgos de seguridad de la información, acciones de tratamiento, usuarios/roles y Declaración de Aplicabilidad (SoA). Diseñada como MVP inspirado en el enfoque de ISO/IEC 27001:2022 y la guía ISO/IEC 27005:2022; no certifica cumplimiento ni reemplaza la aprobación formal de la metodología institucional.

## Incluye

- Dashboard con distribución de riesgos y acciones pendientes/vencidas.
- Inventario de activos con criticidad y clasificación de confidencialidad, integridad y disponibilidad.
- Registro de riesgos con ID automático correlativo `RI-0001`, catálogo de amenazas y fuente derivada del evento seleccionado.
- Estimación preliminar de efectividad basada en oportunidad, periodicidad y automatización, con ponderación visible.
- Plan de tratamiento con múltiples acciones vinculadas a cada riesgo.
- Inicio de sesión local, contraseñas con hash seguro y permisos por rol.
- Mantenedor de usuarios (administrador, gestor de tratamiento y consulta).
- Historial de observaciones de seguimiento no destructivo.
- SoA precargada con los 93 controles del Anexo A 2022, aplicabilidad justificada y avance de implementación.
- Vinculación de controles con riesgos y acciones de tratamiento, más exportación SoA CSV.
- Exportación CSV compatible con Excel (separador `;`, codificación UTF-8 BOM).
- Base SQLite persistente mediante volumen Docker.
- Interfaz en español sin dependencias de CDN externas.

## Inicio rápido

1. Instala Docker Desktop (Windows/macOS) o Docker Engine + Compose (Linux).
2. Descomprime el proyecto en una carpeta.
3. Copia `.env.example` como `.env` y configura una clave secreta aleatoria. En PowerShell puedes generarla con `python -c "import secrets; print(secrets.token_hex(32))"` y pegar el resultado en `SECRET_KEY` dentro de `.env`. No compartas ni versionas ese archivo.
4. Desde esa carpeta ejecuta:

   ```bash
   docker compose up -d --build
   ```

5. Abre `http://localhost:8081` (el servicio queda publicado solo en el equipo local por defecto).
6. En el primer ingreso se abrirá una configuración inicial para crear la cuenta administradora; no existe una contraseña por defecto. Luego podrás crear usuarios desde **Usuarios**. Las cuentas nuevas deben cambiar su contraseña al iniciar sesión.
7. Comprueba estado en `http://localhost:8081/health`.

La base de datos queda en el volumen Docker `sgsi_data`.

## Copia de seguridad

Para una copia coherente con la aplicación detenida:

```bash
docker compose stop
docker run --rm -v sgsi-riesgos_sgsi_data:/data -v "$PWD":/backup alpine sh -c 'cp /data/sgsi.db /backup/sgsi-backup.db'
docker compose start
```

El nombre del volumen puede variar si cambias el nombre de la carpeta del proyecto. Revisa `docker volume ls`.

## Criterios iniciales del MVP

- Puntaje inherente = probabilidad × impacto global.
- Puntaje residual = probabilidad residual × impacto residual.
- Bandas iniciales: 1–4 Bajo, 5–9 Moderado, 10–16 Alto, 17–25 Crítico.
- Exposición informativa = 100 − efectividad estimada del control. No se usa para disminuir automáticamente el riesgo residual.
- El impacto global se ingresa por juicio experto; los impactos operacional, reputacional, político y normativo se conservan como dimensiones de contexto.

Estas bandas son una propuesta de implementación, no valores impuestos por ISO. Deben ser aprobadas y ajustadas a la metodología oficial del establecimiento y a las instrucciones ministeriales.

## Roles y permisos

- **Administrador:** administra activos, riesgos, SoA, acciones y usuarios.
- **Gestor de tratamiento:** consulta riesgos y acciones; puede actualizar el avance porcentual y agregar observaciones nuevas con fecha/autor, sin reemplazar las observaciones previas. No puede crear riesgos/activos ni modificar responsables, plazos o controles.
- **Solo consulta:** visualiza la información y los reportes sin modificar datos.

Las contraseñas se almacenan con hash, no en texto plano. La aplicación usa cookie de sesión HttpOnly y SameSite=Lax. Para un despliegue institucional real, mantén el servicio en red restringida y agrega HTTPS, revisión de seguridad, gestión formal de secretos, respaldo/restauración probados y evaluación institucional. La autenticación local no es todavía integración con Active Directory. El puerto se limita a localhost por defecto; para acceso desde otros equipos, primero completa la configuración inicial y luego publica el servicio solo en la red interna, con firewall y HTTPS/reverse proxy.

La migración crea tablas nuevas y precarga controles sin borrar los registros existentes. **No ejecutes `docker compose down -v`**, porque eliminaría el volumen persistente de datos.

## Próximas mejoras recomendadas

1. Integración con Active Directory/LDAP o SSO.
2. Catálogos administrables de amenazas y controles institucionales adicionales.
3. Matriz de tolerancia aprobable por la Dirección.
4. Historial versionado de las evaluaciones de riesgo.
5. Plantillas de exportación que reproduzcan exactamente los formatos ministeriales.
6. Exportación XLSX/PDF y tablero de tendencia temporal.
