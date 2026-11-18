# ClamGuard

ClamGuard es una interfaz gráfica gratuita para Windows que envuelve el motor
antivirus libre **ClamAV** y su actualizador **freshclam**. Incluye análisis bajo
demanda y una protección residente que analiza en segundo plano los archivos
nuevos o modificados de las carpetas configuradas.

ClamGuard **no incluye** el motor ni las firmas de ClamAV: en la primera ejecución
descarga el instalador oficial de Cisco Talos desde GitHub, verifica su huella
SHA-256 y lo instala de forma silenciosa. Después descarga las firmas de virus.

## Requisitos

- Windows 10 u 11 (x64 o ARM64).
- .NET Framework 4.8 (incluido en Windows 10/11 actualizados).
- Conexión a Internet para la primera instalación y para actualizar firmas.
- **Permisos de administrador (UAC)**.

## UAC y permisos

Instalar ClamAV, escribir en `%ProgramData%` y registrar el servicio residente
requieren privilegios de administrador. Por eso:

- `ClamGuard.exe` incluye un manifiesto con `requireAdministrator`; Windows
  mostrará el aviso de **Control de cuentas de usuario (UAC)** al abrirlo.
- Además, si el proceso arranca sin privilegios (por ejemplo, una compilación de
  prueba sin manifiesto), ClamGuard se relanza a sí mismo con el verbo `runas`
  para solicitar UAC antes de continuar.
- Si rechazas el aviso de UAC, la aplicación no podrá instalar ClamAV ni activar
  la protección residente y se cerrará.

Acepta el aviso de UAC para que la instalación funcione correctamente. La
variable `CLAMGUARD_NO_ELEVATE=1` y el argumento `--no-elevate` existen **solo
para pruebas automatizadas** y desactivan esta comprobación; no los uses en un
equipo real.

## Uso

1. Ejecuta `ClamGuard.exe` y acepta el aviso de UAC.
2. Pulsa **Instalar ClamAV** en el aviso superior. ClamGuard descarga el MSI
   oficial (unos 220 MB), comprueba su SHA-256, lo instala y descarga las firmas
   (varios cientos de MB). Puede tardar varios minutos.
3. **Análisis rápido**: analiza las carpetas habituales (Escritorio, Descargas,
   Documentos, temporal y carpeta de inicio). También puedes elegir otra carpeta.
4. **Instalar residente**: registra el servicio `ClamGuardResident`, que arranca
   con Windows y vigila las carpetas configuradas.
5. **Comprobar y actualizar**: ejecuta `freshclam`, recarga las firmas en `clamd`
   y muestra la fecha y el tamaño de la base de datos.

Mientras el residente está activo, ClamGuard muestra un icono en el **área de
notificación** (bandeja del sistema) con un punto verde. El menú del icono
permite abrir la ventana, iniciar un análisis rápido, activar o detener el
residente y salir. Si cierras la ventana con la protección residente activa,
ClamGuard se oculta en la bandeja y sigue protegiendo el equipo; para salir de
verdad usa **Salir de ClamGuard** en ese menú.

Si se detecta una amenaza, ClamGuard muestra un diálogo para poner el archivo en
cuarentena o eliminarlo. La cuarentena guarda una copia cifrada y permite
restaurarla si se trata de un falso positivo.

## Convivencia con Windows Defender

Dos antivirus analizando a la vez los mismos archivos consumen CPU y disco y
pueden interferir entre sí. Para evitarlo, cuando arranca el servicio residente
ClamGuard:

1. Añade **exclusiones** en Windows Defender para sus propias carpetas de datos,
   cuarentena, firmas y para la carpeta de instalación de ClamAV. Así Defender no
   vuelve a analizar los archivos internos de ClamGuard.
2. Si la opción **«Pausar Windows Defender mientras el residente esté activo»**
   está marcada (lo está por defecto), pausa la **protección en tiempo real** de
   Windows Defender y guarda una marca en `defender-state.json`.
3. Al **detener o desinstalar** el residente, o al salir de ClamGuard desde la
   bandeja, reactiva Windows Defender automáticamente. Si la aplicación se cerró
   de forma inesperada, la interfaz detecta la marca pendiente al arrancar y
   restaura Defender.
4. Cada pocos minutos comprueba que Defender no haya vuelto a activarse por su
   cuenta y, si es necesario, vuelve a pausarlo mientras el residente siga activo.

La pausa puede fallar si Windows Defender tiene la **protección contra
alteraciones (Tamper Protection)** activada o si una directiva de empresa lo
impide. En ese caso ClamGuard no fuerza el cambio: mantiene las exclusiones,
registra un aviso y sigue funcionando. Puedes desactivar la pausa automática en
**Configuración → General** si prefieres que Defender siga activo.

ClamGuard no se registra como antivirus en el Centro de seguridad de Windows, por
lo que Windows puede mostrar avisos de que Defender está desactivado mientras el
residente está en marcha. Es normal: al detener el residente, Defender vuelve a
su estado habitual.

## Datos y configuración

De forma predeterminada, ClamGuard guarda todo en `%ProgramData%\ClamGuard`:

| Ruta | Contenido |
| --- | --- |
| `settings.json` | Configuración de la interfaz y del residente. |
| `state.json` | Último análisis, última actualización y última amenaza. |
| `defender-state.json` | Marca temporal de pausa de Windows Defender (se elimina al restaurarlo). |
| `logs\clamguard.log` | Registro de la interfaz. |
| `logs\resident.log` | Registro del servicio residente. |
| `logs\clamd.log` | Registro del motor `clamd`. |
| `logs\msi-install.log` | Registro de la instalación del MSI de ClamAV. |
| `db\` | Base de firmas de ClamAV. |
| `quarantine\` | Archivos cifrados en cuarentena y sus metadatos. |
| `downloads\` | Instalador MSI descargado. |
| `temp\` | Archivos temporales del motor. |

Para pruebas o uso portable se puede cambiar la carpeta de datos con la variable
de entorno `CLAMGUARD_DATA`, por ejemplo:

```powershell
$env:CLAMGUARD_DATA = 'D:\ClamGuardData'
.\ClamGuard.exe
```

El servicio residente usa la misma carpeta de datos. No cambies esta variable
después de instalar el servicio salvo que quieras una instalación aislada.

## Seguridad

- El MSI se descarga únicamente desde las versiones oficiales de
  `Cisco-Talos/clamav` en GitHub. Si la API no está disponible se usa una versión
  de referencia fijada con su hash SHA-256.
- El hash del instalador se verifica antes de ejecutarlo. Si no coincide, el
  archivo se descarta.
- `clamd` escucha solo en `127.0.0.1` (puerto 3310 por defecto) y no se expone a
  la red.
- La cuarentena usa AES-256-CBC con autenticación HMAC-SHA256. La clave se
  protege con DPAPI (`LocalMachine`) y los metadatos se guardan en JSON.
- Si un archivo no se puede mover, ClamGuard intenta programar su eliminación
  para el siguiente reinicio mediante `MoveFileEx`.
- El servicio residente se ejecuta como `LocalSystem` para poder analizar
  archivos de todos los usuarios.

## Limitaciones

- La protección residente se basa en `FileSystemWatcher`, no en un minifiltro del
  kernel. No bloquea un archivo antes de que se ejecute; lo analiza al crearse o
  modificarse. No sustituye a una suite antivirus completa.
- No hay protección de arranque, correo, navegación web ni memoria en tiempo real.
- El análisis puede consumir CPU y disco, especialmente la primera vez que se
  cargan las firmas.
- ClamAV puede producir falsos positivos. Revisa siempre la cuarentena antes de
  eliminar archivos importantes.
- La aplicación se distribuye sin garantías. ClamAV es software libre de Cisco
  Talos bajo su propia licencia; consulta su documentación para más detalles.

## Créditos y licencia

- **Creado por:** David Casas M
- **YouTube:** Competencia_Digital
- **Twitch:** davidcasasm
- **Licencia:** Creative Commons Compartir-Igual-Mención
- **Software GRATUITO, sin garantía ni soporte adicional.**

ClamAV y freshclam son proyectos de Cisco Talos y se distribuyen bajo su propia
licencia. ClamGuard no incluye el motor ni las firmas: los descarga desde las
fuentes oficiales.

## Actualizaciones

ClamGuard comprueba automáticamente al iniciar si hay una nueva versión en GitHub Releases.
Si existe, avisa al usuario y permite descargarla. También se puede comprobar manualmente
desde el enlace «Actualizaciones» de la cabecera.

- **David Casas M**
- GitHub: https://github.com/davidcasascompetenciadigital-prog
- YouTube: Competencia_Digital
- Twitch: davidcasasm

## Compilación

El proyecto usa C# para .NET Framework 4.8 y se compila con el `csc.exe` incluido
en Windows, sin necesidad de instalar el SDK:

```powershell
cd ClamGuard
.\build.ps1          # genera dist\ClamGuard.exe con manifiesto UAC y el ZIP
.\build.ps1 -Test    # genera dist\ClamGuard.Test.exe sin manifiesto (pruebas)
```

La compilación final verifica que el ejecutable contenga la cadena
`requireAdministrator`; si falta, el script falla. El paquete resultante es
`dist\ClamGuard-1.0.0-win.zip`.

## Firma de código y SmartScreen

El ejecutable no está firmado. Windows SmartScreen puede mostrar una advertencia
al descargarlo o ejecutarlo por primera vez. Para distribuirlo de forma pública,
firma `ClamGuard.exe` con un certificado de firma de código y conserva el
manifiesto UAC.

## Indicadores de compromiso (IOC)

ClamGuard incluye un módulo para buscar **Indicadores de Compromiso** en el equipo,
descargando bases públicas en formato **STIX2** (repositorios como `mvt-indicators`,
AmnestyTech, etc.) y comparándolas con procesos, archivos, caché DNS y claves de
inicio del registro.

- **Actualizar IOCs**: descarga/actualiza la base local desde internet.
- **Buscar en el equipo**: muestra en tiempo real cada elemento analizado y lista
  las coincidencias.
- Los IOCs cubren spyware (Pegasus, Predator, stalkerware, etc.) y otras amenazas.

## Cortafuegos de Windows

Administrador sencillo del firewall de Windows (similar a TinyWall):

- **Modos**: Activo (recomendado), Permitir todo el tráfico, Bloquear todo el tráfico.
- **Programas**: añadir/quitar ejecutables de la lista de excepciones.
- **Puertos**: abrir/cerrar puertos TCP o UDP, listar abiertos/cerrados/todos y editar.

Requiere permisos de administrador para aplicar cambios.

ClamGuard incluye una desinstalación completa que elimina el programa, el motor
ClamAV, el servicio residente, las firmas, los registros, la configuración, las
descargas y la cuarentena.

Formas de iniciarla:

1. Desde la aplicación: **Configuración → Mantenimiento → Desinstalar ClamGuard
   por completo…**.
2. Desde la línea de comandos o el acceso directo: `ClamGuard.exe --uninstall`.
3. Desde Windows: **Configuración → Aplicaciones → Aplicaciones instaladas →
   ClamGuard → Desinstalar** (ClamGuard se registra ahí en cada arranque).

En la ventana de desinstalación puedes elegir qué eliminar:

- **Servicio residente**: se detiene y se quita el arranque automático (siempre
  se elimina cuando se borra el motor, los datos, la cuarentena o el programa).
- **Motor ClamAV**: se desinstala con su instalador oficial MSI. Si no se
  encuentra un instalador registrado y ClamAV está dentro de la carpeta de datos,
  se borra con ella; si está en otra ruta, no se toca para no eliminar una
  instalación ajena.
- **Registros, firmas, configuración y descargas**: se borra el contenido de
  `%ProgramData%\ClamGuard` salvo la cuarentena si la conservas.
- **Cuarentena**: se borran los archivos cifrados de forma **permanente**. Si
  necesitas conservarlos, restáuralos antes de continuar.
- **Archivos del programa**: `ClamGuard.exe`, `README.md`, el paquete ZIP y un
  proceso auxiliar que elimina lo que esté en uso después de cerrar la
  aplicación.

También se restaura Windows Defender si estaba en pausa y se retiran las
exclusiones que ClamGuard añadió.

**Advertencias:**

- La cuarentena puede contener malware real. Revísala antes de borrarla.
- Si ClamAV ya estaba instalado antes de usar ClamGuard, la desinstalación
  completa también lo desinstalará.
- Algunos archivos pueden estar en uso (por ejemplo, el registro). El proceso
  auxiliar los elimina tras cerrar ClamGuard; si algo queda, bórralo
  manualmente o reinicia Windows.
- Si ejecutas ClamGuard desde una carpeta de desarrollo (con `src` o
  `build.ps1`), los archivos del programa no se borran automáticamente para no
  perder el proyecto.

El servicio residente arranca automáticamente con Windows cuando está instalado,
así que la protección se mantiene tras reiniciar el equipo.

## Solución de problemas

- Revisa `%ProgramData%\ClamGuard\logs\clamguard.log` y `resident.log`.
- Si falla la instalación, revisa `logs\msi-install.log`.
- Si el residente no arranca, comprueba que el servicio `ClamGuardResident`
  existe y que el puerto configurado no esté ocupado.
- Si Windows Defender no se pausa, revisa `resident.log`: probablemente la
  protección contra alteraciones esté activa. ClamGuard seguirá funcionando con
  exclusiones y reactivará Defender al detener el residente.
- Si usas Windows Defender junto al residente con la pausa desactivada, pueden
  aparecer análisis duplicados y un mayor consumo de CPU.
- Si Windows Defender bloquea un archivo de prueba (por ejemplo, EICAR), no es un
  fallo de ClamGuard: Defender intercepta el archivo antes de que ClamAV lo vea.
- Para probar sin UAC, usa una compilación `-Test` y define
  `CLAMGUARD_NO_ELEVATE=1`. Esto no permite instalar el servicio ni el MSI.
