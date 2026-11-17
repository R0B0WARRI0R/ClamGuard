using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace ClamGuard
{
    /// <summary>
    /// Opciones de la desinstalación completa.
    /// </summary>
    public sealed class UninstallOptions
    {
        public bool RemoveService = true;
        public bool RemoveEngine = true;
        public bool RemoveData = true;
        public bool RemoveQuarantine = true;
        public bool RemoveAppFiles = true;

        public bool RemovesAnything
        {
            get
            {
                return RemoveService || RemoveEngine || RemoveData ||
                    RemoveQuarantine || RemoveAppFiles;
            }
        }
    }

    public sealed class UninstallProgress
    {
        public string Stage = string.Empty;
        public int Percent;
        public bool Indeterminate;
    }

    /// <summary>
    /// Resultado detallado de la desinstalación, para mostrarlo al usuario.
    /// </summary>
    public sealed class UninstallReport
    {
        public bool Success = true;
        public bool AppFilesScheduled;
        public bool RestartRecommended;
        public readonly List<string> Done = new List<string>();
        public readonly List<string> Warnings = new List<string>();
        public readonly List<string> Errors = new List<string>();

        public void AddDone(string text)
        {
            if (!string.IsNullOrEmpty(text)) Done.Add(text);
        }

        public void AddWarning(string text)
        {
            if (!string.IsNullOrEmpty(text)) Warnings.Add(text);
        }

        public void AddError(string text)
        {
            if (string.IsNullOrEmpty(text)) return;
            Errors.Add(text);
            Success = false;
        }

        public string ToMessage()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine(Success
                ? "ClamGuard se desinstaló correctamente."
                : "La desinstalación terminó con errores. Revisa los detalles.");

            AppendList(sb, "Completado:", Done);
            AppendList(sb, "Avisos:", Warnings);
            AppendList(sb, "Errores:", Errors);

            if (AppFilesScheduled)
            {
                sb.AppendLine();
                sb.AppendLine("ClamGuard se cerrará ahora y eliminará sus archivos restantes.");
            }
            if (RestartRecommended)
            {
                sb.AppendLine();
                sb.AppendLine("Reinicia Windows para completar la desinstalación del motor.");
            }
            return sb.ToString().TrimEnd();
        }

        private static void AppendList(StringBuilder sb, string title, List<string> items)
        {
            if (items == null || items.Count == 0) return;
            sb.AppendLine();
            sb.AppendLine(title);
            for (int i = 0; i < items.Count; i++)
                sb.AppendLine("  - " + items[i]);
        }
    }

    /// <summary>
    /// Desinstalación completa de ClamGuard: servicio residente, motor ClamAV,
    /// datos (registros, firmas, configuración, descargas), cuarentena,
    /// exclusiones de Windows Defender, registro en «Aplicaciones instaladas»
    /// y archivos del programa.
    ///
    /// Los archivos del propio ejecutable se borran con un script auxiliar en
    /// %TEMP% que espera a que ClamGuard termine. Si el programa se ejecuta
    /// desde un árbol de desarrollo o con CLAMGUARD_DATA definido (pruebas),
    /// no se tocan ni el servicio ni los archivos del programa.
    /// </summary>
    public static class Uninstaller
    {
        private const string AddRemoveKey =
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ClamGuard";
        private const string NoSelfDeleteVariable = "CLAMGUARD_NO_SELF_DELETE";

        private static readonly string[] UninstallRoots = new string[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        };

        public static bool IsTestMode
        {
            get
            {
                try
                {
                    if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("CLAMGUARD_DATA")))
                        return true;
                    string value = Environment.GetEnvironmentVariable(NoSelfDeleteVariable);
                    return string.Equals(value, "1", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(value, "true", StringComparison.OrdinalIgnoreCase);
                }
                catch
                {
                    return false;
                }
            }
        }

        /// <summary>
        /// Verdadero cuando CLAMGUARD_DATA apunta a una carpeta alternativa.
        /// En ese caso los datos que se borran son los de la carpeta de prueba,
        /// nunca los de %ProgramData%\ClamGuard.
        /// </summary>
        public static bool IsIsolatedData
        {
            get
            {
                try
                {
                    return !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("CLAMGUARD_DATA"));
                }
                catch
                {
                    return false;
                }
            }
        }

        // ------------------------------------------------------------------
        // Registro en «Aplicaciones y características»
        // ------------------------------------------------------------------

        /// <summary>
        /// Registra ClamGuard en Aplicaciones y características para que el
        /// usuario pueda desinstalarlo desde el Panel de control. Se actualiza
        /// en cada arranque para reflejar la ruta actual del ejecutable.
        /// </summary>
        public static void Register()
        {
            if (IsTestMode || !ResidentService.IsAdministrator()) return;
            try
            {
                string exe = AppPaths.ExePath;
                if (string.IsNullOrEmpty(exe) || !File.Exists(exe)) return;
                if (Path.GetFileName(exe).IndexOf(".Test", StringComparison.OrdinalIgnoreCase) >= 0)
                    return;

                string appDir = AppPaths.AppDir;
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(AddRemoveKey))
                {
                    if (key == null) return;
                    key.SetValue("DisplayName", "ClamGuard");
                    key.SetValue("DisplayVersion", AppPaths.ProductVersion);
                    key.SetValue("Publisher", "David Casas M");
                    key.SetValue("DisplayIcon", exe + ",0");
                    if (!string.IsNullOrEmpty(appDir)) key.SetValue("InstallLocation", appDir);
                    key.SetValue("UninstallString", "\"" + exe + "\" --uninstall");
                    key.SetValue("QuietUninstallString", "\"" + exe + "\" --uninstall");
                    key.SetValue("NoModify", 1, RegistryValueKind.DWord);
                    key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
                    key.SetValue("InstallDate", DateTime.Now.ToString("yyyyMMdd", CultureInfo.InvariantCulture));
                    key.SetValue("Comments",
                        "Antivirus gratuito con el motor ClamAV. Creado por David Casas M.");
                    long size = EstimateAppSize();
                    if (size > 0)
                        key.SetValue("EstimatedSize", (int)Math.Max(1, size / 1024), RegistryValueKind.DWord);
                }
            }
            catch (Exception ex)
            {
                AppLog.Warn("No se pudo registrar ClamGuard en Aplicaciones y características: " + ex.Message);
            }
        }

        public static void Unregister()
        {
            if (IsTestMode) return;
            try
            {
                Registry.LocalMachine.DeleteSubKeyTree(AddRemoveKey, false);
            }
            catch
            {
            }
        }

        public static bool IsRegistered()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(AddRemoveKey))
                    return key != null;
            }
            catch
            {
                return false;
            }
        }

        // ------------------------------------------------------------------
        // Detección del motor
        // ------------------------------------------------------------------

        /// <summary>
        /// Busca el código de producto MSI de ClamAV en el registro. Devuelve
        /// null si no encuentra un instalador registrado.
        /// </summary>
        public static string FindClamAvProductCode()
        {
            for (int i = 0; i < UninstallRoots.Length; i++)
            {
                try
                {
                    using (RegistryKey root = Registry.LocalMachine.OpenSubKey(UninstallRoots[i]))
                    {
                        if (root == null) continue;
                        string[] names = root.GetSubKeyNames();
                        for (int j = 0; j < names.Length; j++)
                        {
                            try
                            {
                                using (RegistryKey app = root.OpenSubKey(names[j]))
                                {
                                    if (app == null) continue;
                                    string display = app.GetValue("DisplayName") as string;
                                    if (string.IsNullOrEmpty(display) ||
                                        display.IndexOf("ClamAV", StringComparison.OrdinalIgnoreCase) < 0)
                                        continue;

                                    string code = ExtractProductCode(names[j]);
                                    if (code == null)
                                    {
                                        string uninstall = app.GetValue("QuietUninstallString") as string;
                                        if (string.IsNullOrEmpty(uninstall))
                                            uninstall = app.GetValue("UninstallString") as string;
                                        code = ExtractProductCode(uninstall);
                                    }
                                    if (code != null) return code;
                                }
                            }
                            catch
                            {
                            }
                        }
                    }
                }
                catch
                {
                }
            }
            return null;
        }

        private static string ExtractProductCode(string value)
        {
            if (string.IsNullOrEmpty(value)) return null;
            int start = value.IndexOf('{');
            while (start >= 0)
            {
                int end = value.IndexOf('}', start + 1);
                if (end > start && end - start == 37)
                    return value.Substring(start, end - start + 1);
                start = value.IndexOf('{', start + 1);
            }
            return null;
        }

        // ------------------------------------------------------------------
        // Estimaciones para la interfaz
        // ------------------------------------------------------------------

        public static long DirectorySize(string path)
        {
            try
            {
                if (File.Exists(path)) return new FileInfo(path).Length;
                if (!Directory.Exists(path)) return 0;

                long total = 0;
                string[] files = Directory.GetFiles(path);
                for (int i = 0; i < files.Length; i++)
                {
                    try { total += new FileInfo(files[i]).Length; }
                    catch { }
                }
                string[] dirs = Directory.GetDirectories(path);
                for (int i = 0; i < dirs.Length; i++)
                {
                    try
                    {
                        FileAttributes attrs = File.GetAttributes(dirs[i]);
                        if ((attrs & FileAttributes.ReparsePoint) != 0) continue;
                        total += DirectorySize(dirs[i]);
                    }
                    catch
                    {
                    }
                }
                return total;
            }
            catch
            {
                return 0;
            }
        }

        public static int QuarantineCount()
        {
            try
            {
                if (!Directory.Exists(AppPaths.QuarantineDir)) return 0;
                return Directory.GetFiles(AppPaths.QuarantineDir, "*.qtn").Length;
            }
            catch
            {
                return 0;
            }
        }

        public static long EstimateAppSize()
        {
            return DirectorySize(AppPaths.AppDir);
        }

        public static bool IsDevelopmentTree()
        {
            try
            {
                string appDir = AppPaths.AppDir;
                if (string.IsNullOrEmpty(appDir)) return true;
                if (Directory.Exists(Path.Combine(appDir, "src"))) return true;
                if (File.Exists(Path.Combine(appDir, "build.ps1"))) return true;
                string parent = Path.GetDirectoryName(appDir);
                if (!string.IsNullOrEmpty(parent))
                {
                    if (Directory.Exists(Path.Combine(parent, "src"))) return true;
                    if (File.Exists(Path.Combine(parent, "build.ps1"))) return true;
                }
                return false;
            }
            catch
            {
                return true;
            }
        }

        // ------------------------------------------------------------------
        // Desinstalación
        // ------------------------------------------------------------------

        public static UninstallReport Run(
            UninstallOptions options,
            AppSettings settings,
            IProgress<UninstallProgress> progress,
            CancellationToken token,
            Action<LogLevel, string> log)
        {
            UninstallReport report = new UninstallReport();
            if (options == null) options = new UninstallOptions();

            if (!options.RemovesAnything)
            {
                report.AddError("No se seleccionó nada que desinstalar.");
                return report;
            }
            if (!ResidentService.IsAdministrator())
            {
                report.AddError("Se necesitan permisos de administrador para desinstalar ClamGuard. " +
                    "Cierra la aplicación y vuelve a abrirla aceptando el aviso de UAC.");
                return report;
            }

            bool test = IsTestMode;
            try
            {
                // Si se elimina el motor, los datos o el programa, el servicio
                // residente ya no puede seguir funcionando: se elimina siempre.
                if (options.RemoveEngine || options.RemoveData ||
                    options.RemoveQuarantine || options.RemoveAppFiles)
                {
                    options.RemoveService = true;
                }

                string engineDir = AppPaths.FindClamAvDirectory(
                    settings == null ? null : settings.ClamAvDirectory);

                // 1. Servicio residente.
                Report(progress, "Deteniendo la protección residente…", 4, true);
                if (test)
                {
                    report.AddWarning("Modo de prueba: no se modifica el servicio residente.");
                }
                else if (options.RemoveService)
                {
                    if (ResidentService.IsInstalled())
                    {
                        string error = string.Empty;
                        bool ok = ResidentService.Uninstall(out error);
                        if (ok)
                        {
                            report.AddDone("Servicio residente detenido y eliminado.");
                            Emit(log, LogLevel.Ok, "Servicio residente detenido y eliminado.");
                        }
                        else
                        {
                            report.AddError("No se pudo eliminar el servicio residente: " + error);
                            Emit(log, LogLevel.Error, "No se pudo eliminar el servicio residente: " + error);
                        }
                    }
                    else
                    {
                        report.AddDone("El servicio residente no estaba instalado.");
                    }
                }
                else
                {
                    report.AddDone("Se conserva el servicio residente.");
                }

                if (Abort(report, token)) return report;

                // 2. Windows Defender: reactivar y retirar exclusiones.
                Report(progress, "Restaurando Windows Defender…", 12, true);
                if (test)
                {
                    report.AddWarning("Modo de prueba: no se modifican las preferencias de Windows Defender.");
                }
                else
                {
                    Defender.Restore(log);
                    if (Defender.HasPendingRestore())
                    {
                        report.AddWarning("Windows Defender no se pudo reactivar automáticamente. " +
                            "Abre Seguridad de Windows y activa la protección en tiempo real.");
                    }
                    else
                    {
                        report.AddDone("Windows Defender restaurado si estaba en pausa.");
                    }

                    if (options.RemoveEngine || options.RemoveData ||
                        options.RemoveQuarantine || options.RemoveAppFiles)
                    {
                        if (Defender.RemoveExclusions(settings, options.RemoveEngine, log))
                            report.AddDone("Exclusiones de ClamGuard retiradas de Windows Defender.");
                        else
                            report.AddWarning("No se pudieron retirar todas las exclusiones de Windows Defender. " +
                                "Puedes quitarlas manualmente en Seguridad de Windows.");
                    }
                }

                if (Abort(report, token)) return report;

                // 3. Motor ClamAV.
                if (options.RemoveEngine)
                {
                    Report(progress, "Desinstalando el motor ClamAV…", 25, true);
                    RemoveEngine(test, engineDir, report, log);
                    if (Abort(report, token)) return report;
                }
                else
                {
                    report.AddDone("Se conserva el motor ClamAV.");
                }

                // 4. Datos, registros, firmas y cuarentena.
                if (options.RemoveData || options.RemoveQuarantine)
                {
                    Report(progress, "Eliminando registros, firmas y cuarentena…", 68, true);
                    if (test && !IsIsolatedData)
                    {
                        report.AddWarning("Modo de prueba sin CLAMGUARD_DATA: no se borran datos reales. " +
                            "Define CLAMGUARD_DATA a una carpeta temporal para probar esta parte.");
                    }
                    else
                    {
                        try
                        {
                            DeleteData(options, report, test);
                        }
                        catch (Exception ex)
                        {
                            report.AddError("No se pudieron eliminar todos los datos: " + ex.Message);
                            Emit(log, LogLevel.Error, report.Errors[report.Errors.Count - 1]);
                        }
                    }
                    if (Abort(report, token)) return report;
                }
                else
                {
                    report.AddDone("Se conservan los datos y la cuarentena.");
                }

                // 5. Registro de desinstalación, accesos directos y programa.
                if (options.RemoveAppFiles)
                {
                    Report(progress, "Quitando el registro de desinstalación…", 84, true);
                    if (test)
                    {
                        report.AddWarning("Modo de prueba: no se elimina el registro de Aplicaciones instaladas.");
                    }
                    else
                    {
                        Unregister();
                        report.AddDone("ClamGuard retirado de Aplicaciones y características.");
                    }

                    Report(progress, "Preparando la eliminación de los archivos del programa…", 90, true);
                    ScheduleAppCleanup(options, report, log, test);
                }
                else
                {
                    report.AddDone("Se conservan los archivos del programa.");
                }

                Report(progress, "Desinstalación completada.", 100, false);
                if (report.AppFilesScheduled) report.RestartRecommended = false;
                if (!report.Success)
                    Emit(log, LogLevel.Warn, "La desinstalación terminó con avisos o errores.");
                return report;
            }
            catch (Exception ex)
            {
                report.AddError("Error inesperado durante la desinstalación: " + ex.Message);
                Emit(log, LogLevel.Error, report.Errors[report.Errors.Count - 1]);
                return report;
            }
        }

        private static bool Abort(UninstallReport report, CancellationToken token)
        {
            if (!token.IsCancellationRequested) return false;
            report.AddWarning("Desinstalación cancelada por el usuario.");
            return true;
        }

        private static void RemoveEngine(
            bool test, string engineDir, UninstallReport report, Action<LogLevel, string> log)
        {
            if (test)
            {
                report.AddWarning("Modo de prueba: no se desinstala el motor ClamAV.");
                return;
            }

            StopClamAvProcesses(engineDir);

            string productCode = FindClamAvProductCode();
            if (!string.IsNullOrEmpty(productCode))
            {
                string msiLog = Path.Combine(Path.GetTempPath(), "ClamGuard-uninstall-msi.log");
                string arguments = "/x " + productCode + " /qn /norestart /l*v " + Cmd.Quote(msiLog);
                Emit(log, LogLevel.Info, "Desinstalando ClamAV con msiexec " + productCode + "…");
                ProcessResult result = Proc.Run("msiexec.exe", arguments, null,
                    20 * 60 * 1000, CancellationToken.None);

                if (result.TimedOut)
                {
                    report.AddError("La desinstalación de ClamAV superó el tiempo máximo. Revisa " + msiLog);
                    return;
                }

                if (result.ExitCode == 0 || result.ExitCode == 3010 || result.ExitCode == 1641)
                {
                    report.AddDone("Motor ClamAV desinstalado.");
                    if (result.ExitCode != 0) report.RestartRecommended = true;
                    try { if (File.Exists(msiLog)) File.Delete(msiLog); } catch { }
                    Emit(log, LogLevel.Ok, "Motor ClamAV desinstalado.");
                    return;
                }

                if (result.ExitCode == 1605)
                {
                    report.AddDone("El motor ClamAV ya no estaba instalado.");
                    try { if (File.Exists(msiLog)) File.Delete(msiLog); } catch { }
                    return;
                }

                report.AddWarning("El desinstalador de ClamAV terminó con código " + result.ExitCode +
                    ". Revisa " + msiLog + " o desinstálalo desde Aplicaciones instaladas.");
                Emit(log, LogLevel.Warn, report.Warnings[report.Warnings.Count - 1]);
                return;
            }

            if (engineDir != null && AppPaths.IsUnder(engineDir, AppPaths.DataDir))
            {
                report.AddDone("El motor ClamAV está dentro de la carpeta de datos y se eliminará con ella.");
                return;
            }

            if (engineDir != null)
            {
                report.AddWarning("No se encontró un instalador MSI de ClamAV. No se borró " +
                    engineDir + " para no eliminar una instalación ajena; puedes desinstalarlo " +
                    "desde Aplicaciones instaladas.");
                Emit(log, LogLevel.Warn, report.Warnings[report.Warnings.Count - 1]);
                return;
            }

            report.AddDone("No se detectó el motor ClamAV.");
        }

        private static void StopClamAvProcesses(string engineDir)
        {
            string[] names = new string[] { "clamd", "clamdscan", "clamscan", "freshclam" };
            bool killed = false;
            for (int i = 0; i < names.Length; i++)
            {
                Process[] processes;
                try { processes = Process.GetProcessesByName(names[i]); }
                catch { continue; }

                for (int j = 0; j < processes.Length; j++)
                {
                    Process process = processes[j];
                    try
                    {
                        string path = null;
                        try { path = process.MainModule.FileName; } catch { }
                        bool ours = path != null &&
                            ((engineDir != null && AppPaths.IsUnder(path, engineDir)) ||
                             AppPaths.IsUnder(path, AppPaths.DataDir));
                        if (ours)
                        {
                            process.Kill();
                            killed = true;
                        }
                    }
                    catch
                    {
                    }
                    finally
                    {
                        try { process.Dispose(); } catch { }
                    }
                }
            }
            if (killed)
            {
                try { Thread.Sleep(700); } catch { }
            }
        }

        // ------------------------------------------------------------------
        // Borrado de datos
        // ------------------------------------------------------------------

        private static void DeleteData(UninstallOptions options, UninstallReport report, bool test)
        {
            bool dataExists = Directory.Exists(AppPaths.DataDir);
            bool quarantineExists = Directory.Exists(AppPaths.QuarantineDir);
            if (!dataExists && !quarantineExists)
            {
                report.AddDone("No quedaban datos de ClamGuard.");
                return;
            }

            int failures = 0;

            if (options.RemoveData && dataExists)
            {
                string[] entries;
                try
                {
                    entries = Directory.GetFileSystemEntries(AppPaths.DataDir);
                }
                catch
                {
                    entries = new string[0];
                    failures++;
                }

                for (int i = 0; i < entries.Length; i++)
                {
                    if (!options.RemoveQuarantine && PathsEqual(entries[i], AppPaths.QuarantineDir))
                        continue;
                    failures += DeletePath(entries[i]);
                }
            }

            if (options.RemoveQuarantine && quarantineExists)
                failures += DeletePath(AppPaths.QuarantineDir);

            // Quitar la carpeta raíz si quedó vacía.
            if (options.RemoveData && options.RemoveQuarantine && Directory.Exists(AppPaths.DataDir))
            {
                try
                {
                    if (Directory.GetFileSystemEntries(AppPaths.DataDir).Length == 0)
                        Directory.Delete(AppPaths.DataDir);
                }
                catch
                {
                    failures++;
                }
            }

            if (!test) DeleteLegacyFolders();

            if (!Directory.Exists(AppPaths.DataDir))
                report.AddDone("Registros, firmas, configuración, descargas y cuarentena eliminados.");
            else if (options.RemoveData && !options.RemoveQuarantine)
                report.AddDone("Registros, firmas, configuración y descargas eliminados. " +
                    "Se conservó la cuarentena en " + AppPaths.QuarantineDir + ".");
            else if (options.RemoveQuarantine && !Directory.Exists(AppPaths.QuarantineDir))
                report.AddDone("Cuarentena eliminada.");
            else
                report.AddDone("Datos de ClamGuard procesados.");

            if (failures > 0 && options.RemoveData && options.RemoveQuarantine &&
                Directory.Exists(AppPaths.DataDir))
            {
                report.AddWarning("Quedan archivos bloqueados en " + AppPaths.DataDir +
                    "; se intentará borrarlos al cerrar ClamGuard.");
            }
        }

        private static void DeleteLegacyFolders()
        {
            try
            {
                List<string> dirs = new List<string>();
                string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                if (!string.IsNullOrEmpty(local)) dirs.Add(Path.Combine(local, AppPaths.ProductName));
                if (!string.IsNullOrEmpty(roaming)) dirs.Add(Path.Combine(roaming, AppPaths.ProductName));
                for (int i = 0; i < dirs.Count; i++)
                {
                    try
                    {
                        if (Directory.Exists(dirs[i])) DeletePath(dirs[i]);
                    }
                    catch
                    {
                    }
                }
            }
            catch
            {
            }
        }

        private static int DeletePath(string path)
        {
            if (string.IsNullOrEmpty(path)) return 0;

            try
            {
                if (File.Exists(path))
                {
                    TryClearReadOnly(path);
                    File.Delete(path);
                    return 0;
                }
            }
            catch
            {
                return 1;
            }

            try
            {
                if (!Directory.Exists(path)) return 0;

                FileAttributes attrs = File.GetAttributes(path);
                if ((attrs & FileAttributes.ReparsePoint) != 0)
                {
                    Directory.Delete(path, false);
                    return 0;
                }

                int failures = 0;
                string[] files = Directory.GetFiles(path);
                for (int i = 0; i < files.Length; i++)
                {
                    try
                    {
                        TryClearReadOnly(files[i]);
                        File.Delete(files[i]);
                    }
                    catch
                    {
                        failures++;
                    }
                }

                string[] dirs = Directory.GetDirectories(path);
                for (int i = 0; i < dirs.Length; i++)
                    failures += DeletePath(dirs[i]);

                try
                {
                    Directory.Delete(path, false);
                }
                catch
                {
                    failures++;
                }
                return failures;
            }
            catch
            {
                return 1;
            }
        }

        private static void TryClearReadOnly(string path)
        {
            try
            {
                FileAttributes attrs = File.GetAttributes(path);
                if ((attrs & FileAttributes.ReadOnly) != 0)
                    File.SetAttributes(path, attrs & ~FileAttributes.ReadOnly);
            }
            catch
            {
            }
        }

        private static bool PathsEqual(string a, string b)
        {
            try
            {
                return string.Equals(
                    Path.GetFullPath(a).TrimEnd('\\'),
                    Path.GetFullPath(b).TrimEnd('\\'),
                    StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        // ------------------------------------------------------------------
        // Archivos del programa y accesos directos
        // ------------------------------------------------------------------

        private static void ScheduleAppCleanup(
            UninstallOptions options, UninstallReport report,
            Action<LogLevel, string> log, bool test)
        {
            if (test)
            {
                report.AddWarning("Modo de prueba: no se eliminan los archivos del programa.");
                return;
            }
            if (IsDevelopmentTree())
            {
                report.AddWarning("Se detectó una carpeta de desarrollo; no se eliminan los archivos " +
                    "del programa para no borrar el proyecto. Elimina ClamGuard.exe manualmente.");
                return;
            }

            string exe = AppPaths.ExePath;
            string appDir = AppPaths.AppDir;
            if (string.IsNullOrEmpty(exe) || string.IsNullOrEmpty(appDir) || !Directory.Exists(appDir))
            {
                report.AddWarning("No se pudo determinar la carpeta del programa.");
                return;
            }

            DeleteShortcuts(report);

            // Archivos que no están en uso se pueden borrar ahora.
            string[] names = new string[]
            {
                "ClamGuard.exe.config",
                "ClamGuard.exe.manifest",
                "ClamGuard.pdb",
                "README.md"
            };
            for (int i = 0; i < names.Length; i++)
            {
                try
                {
                    string file = Path.Combine(appDir, names[i]);
                    if (File.Exists(file)) File.Delete(file);
                }
                catch
                {
                }
            }
            try
            {
                string[] zips = Directory.GetFiles(appDir, "ClamGuard-*-win.zip");
                for (int i = 0; i < zips.Length; i++)
                {
                    try { File.Delete(zips[i]); } catch { }
                }
            }
            catch
            {
            }

            if (!SchedulePowershellCleanup(appDir, exe, options, report))
            {
                report.AddWarning("No se pudo programar la eliminación de ClamGuard.exe. " +
                    "Borra el archivo manualmente después de cerrar la aplicación.");
                return;
            }

            report.AppFilesScheduled = true;
            report.AddDone("Los archivos del programa se eliminarán al cerrar ClamGuard.");
            Emit(log, LogLevel.Info, "Limpieza final de archivos programada.");
        }

        private static void DeleteShortcuts(UninstallReport report)
        {
            List<string> shortcuts = new List<string>();
            AddShortcut(shortcuts, Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms));
            AddShortcut(shortcuts, Environment.GetFolderPath(Environment.SpecialFolder.Programs));
            AddShortcut(shortcuts, Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
            AddShortcut(shortcuts, Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory));

            int removed = 0;
            for (int i = 0; i < shortcuts.Count; i++)
            {
                try
                {
                    if (File.Exists(shortcuts[i]))
                    {
                        File.Delete(shortcuts[i]);
                        removed++;
                    }
                }
                catch
                {
                }
            }
            if (removed > 0) report.AddDone("Accesos directos eliminados.");
        }

        private static void AddShortcut(List<string> list, string folder)
        {
            if (string.IsNullOrEmpty(folder)) return;
            try
            {
                string path = Path.Combine(folder, AppPaths.ProductName + ".lnk");
                if (!AppPaths.ContainsPath(list, path)) list.Add(path);
            }
            catch
            {
            }
        }

        private static bool SchedulePowershellCleanup(
            string appDir, string exe, UninstallOptions options, UninstallReport report)
        {
            string scriptPath = null;
            try
            {
                scriptPath = Path.Combine(Path.GetTempPath(),
                    "ClamGuard-uninstall-" + Guid.NewGuid().ToString("N") + ".ps1");

                StringBuilder sb = new StringBuilder();
                sb.AppendLine("$ErrorActionPreference = 'SilentlyContinue'");
                sb.AppendLine("$targetPid = " +
                    Process.GetCurrentProcess().Id.ToString(CultureInfo.InvariantCulture));
                sb.AppendLine("for ($i = 0; $i -lt 240; $i++) {");
                sb.AppendLine("  if (-not (Get-Process -Id $targetPid -ErrorAction SilentlyContinue)) { break }");
                sb.AppendLine("  Start-Sleep -Milliseconds 500");
                sb.AppendLine("}");
                sb.AppendLine("Start-Sleep -Milliseconds 800");
                sb.AppendLine("$app = " + PsQuote(appDir));
                sb.AppendLine("$exe = " + PsQuote(exe));
                sb.AppendLine("$names = @('ClamGuard.exe.config','ClamGuard.exe.manifest','ClamGuard.pdb','README.md')");
                sb.AppendLine("foreach ($n in $names) { Remove-Item -LiteralPath (Join-Path $app $n) -Force -ErrorAction SilentlyContinue }");
                sb.AppendLine("Get-ChildItem -LiteralPath $app -Filter 'ClamGuard-*-win.zip' -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue");
                sb.AppendLine("Remove-Item -LiteralPath $exe -Force -ErrorAction SilentlyContinue");

                if (options.RemoveData || options.RemoveQuarantine)
                {
                    sb.AppendLine("$data = " + PsQuote(AppPaths.DataDir));
                    sb.AppendLine("$quarantine = " + PsQuote(AppPaths.QuarantineDir));
                    if (options.RemoveData && options.RemoveQuarantine)
                    {
                        sb.AppendLine("if (Test-Path -LiteralPath $data) { Remove-Item -LiteralPath $data -Recurse -Force -ErrorAction SilentlyContinue }");
                    }
                    else if (options.RemoveData)
                    {
                        sb.AppendLine("if (Test-Path -LiteralPath $data) {");
                        sb.AppendLine("  Get-ChildItem -LiteralPath $data -Force -ErrorAction SilentlyContinue | Where-Object { $_.FullName -ne $quarantine } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue");
                        sb.AppendLine("}");
                    }
                    else
                    {
                        sb.AppendLine("if (Test-Path -LiteralPath $quarantine) { Remove-Item -LiteralPath $quarantine -Recurse -Force -ErrorAction SilentlyContinue }");
                        sb.AppendLine("if (Test-Path -LiteralPath $data) {");
                        sb.AppendLine("  $left = Get-ChildItem -LiteralPath $data -Force -ErrorAction SilentlyContinue");
                        sb.AppendLine("  if (-not $left) { Remove-Item -LiteralPath $data -Force -ErrorAction SilentlyContinue }");
                        sb.AppendLine("}");
                    }
                }

                List<string> extras = new List<string>();
                AddExtraFolder(extras, Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
                AddExtraFolder(extras, Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
                if (extras.Count > 0)
                {
                    sb.Append("$extra = @(");
                    for (int i = 0; i < extras.Count; i++)
                    {
                        if (i > 0) sb.Append(", ");
                        sb.Append(PsQuote(extras[i]));
                    }
                    sb.AppendLine(")");
                    sb.AppendLine("foreach ($p in $extra) { if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue } }");
                }

                sb.AppendLine("if (Test-Path -LiteralPath $app) {");
                sb.AppendLine("  $left = Get-ChildItem -LiteralPath $app -Force -ErrorAction SilentlyContinue");
                sb.AppendLine("  if (-not $left) { Remove-Item -LiteralPath $app -Force -ErrorAction SilentlyContinue }");
                sb.AppendLine("}");
                sb.AppendLine("Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue");

                File.WriteAllText(scriptPath, sb.ToString(), new UTF8Encoding(false));

                ProcessStartInfo info = new ProcessStartInfo();
                info.FileName = Defender.PowerShellPath();
                info.Arguments = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File " +
                    Cmd.Quote(scriptPath);
                info.UseShellExecute = false;
                info.CreateNoWindow = true;
                info.WindowStyle = ProcessWindowStyle.Hidden;
                info.WorkingDirectory = Path.GetTempPath();
                Process.Start(info);
                return true;
            }
            catch (Exception ex)
            {
                report.AddWarning("No se pudo programar la limpieza final: " + ex.Message);
                try { if (scriptPath != null && File.Exists(scriptPath)) File.Delete(scriptPath); } catch { }
                return false;
            }
        }

        private static void AddExtraFolder(List<string> list, string parent)
        {
            if (string.IsNullOrEmpty(parent)) return;
            try
            {
                string path = Path.Combine(parent, AppPaths.ProductName);
                if (!AppPaths.ContainsPath(list, path)) list.Add(path);
            }
            catch
            {
            }
        }

        // ------------------------------------------------------------------
        // Utilidades
        // ------------------------------------------------------------------

        private static string PsQuote(string value)
        {
            return "'" + (value ?? string.Empty).Replace("'", "''") + "'";
        }

        private static void Report(
            IProgress<UninstallProgress> progress, string stage, int percent, bool indeterminate)
        {
            if (progress == null) return;
            UninstallProgress value = new UninstallProgress();
            value.Stage = stage;
            value.Percent = percent;
            value.Indeterminate = indeterminate;
            try { progress.Report(value); } catch { }
        }

        private static void Emit(Action<LogLevel, string> log, LogLevel level, string message)
        {
            try
            {
                if (log != null) log(level, message);
                else AppLog.Write(level, message);
            }
            catch
            {
            }
        }
    }
}
