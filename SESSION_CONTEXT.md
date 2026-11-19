# ClamGuard - Contexto de desarrollo para OpenCode

## Objetivo
Antivirus GUI gratuito para Windows basado en ClamAV/freshclam, con protección residente (servicio Windows), UI en español, icono en bandeja, convivencia con Windows Defender y desinstalación completa. Se añadieron módulos de IOCs (STIX2) y administrador de cortafuegos.

## Decisiones técnicas
- C# WinForms .NET Framework 4.8, compilado con csc.exe (C# 5), sin SDK.
- `ClamGuard.exe` manifiesto `requireAdministrator`.
- Datos en `%ProgramData%\ClamGuard` (override `CLAMGUARD_DATA` para pruebas).
- Servicio residente: `ClamGuardResident`, auto-start.
- GitHub: https://github.com/davidcasascompetenciadigital-prog/ClamGuard
- Versión actual: 1.1.0 (tag v1.1.0).

## Funciones implementadas
- Escaneo rápido/completo, cuarentena, firmas, configuración.
- Protección residente (FileSystemWatcher, clamd TCP INSTREAM).
- Tray icon, hide-to-tray, salida segura.
- Defender: exclusiones, pausa/restauración, orphan recovery, enforcement periódico.
- Desinstalación completa (servicio, motor, datos, cuarentena, programa, ARP).
- IOCs: descarga STIX2, búsqueda en procesos/archivos/DNS/registro, progreso en tiempo real, cancelación.
- Cortafuegos: modos, programas, puertos (abrir/cerrar/listar/editar), descripciones.
- Auto-actualización: consulta GitHub Releases.

## Estructura
- `src/*.cs` código fuente.
- `build.ps1` compila y crea ZIP.
- `dist/` ejecutable y paquete.

## Para continuar
1. Abrir esta carpeta en OpenCode.
2. Leer `README.md`.
3. Compilar: `.\build.ps1` o `.\build.ps1 -Test`.
4. El historial completo está en el repositorio Git (rama main).

## Contacto
David Casas M - GitHub: davidcasascompetenciadigital-prog
YT: Competencia_Digital - TWITCH: davidcasasm
Licencia: Creative Commons Compartir-Igual-Mención. Software GRATUITO.