using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Threading;

namespace ClamGuard
{
    /// <summary>
    /// Estado de Windows Defender tal como lo ve ClamGuard.
    /// </summary>
    public sealed class DefenderStatus
    {
        public bool Available;
        public bool Present;
        public bool RealTimeEnabled;
        public bool AntivirusEnabled;
        public bool TamperProtected;
        public string Error = string.Empty;
    }

    /// <summary>
    /// Marca que indica que ClamGuard pausó Windows Defender y debe reactivarlo.
    /// </summary>
    [DataContract]
    public sealed class DefenderMarker
    {
        [DataMember(Order = 1)] public bool PausedByUs;
        [DataMember(Order = 2)] public bool RealTimeWasEnabled;
        [DataMember(Order = 3)] public string SinceUtc;
        [DataMember(Order = 4)] public string Detail;
    }

    /// <summary>
    /// Convivencia con Windows Defender. ClamGuard añade exclusiones para sus
    /// propias carpetas y, si el usuario lo permite, pausa la protección en
    /// tiempo real mientras el servicio residente está activo. Al detener el
    /// residente se restaura el estado anterior.
    ///
    /// Todo se hace con cmdlets de PowerShell (Get-MpComputerStatus,
    /// Set-MpPreference y Add-MpPreference). Si la protección contra
    /// alteraciones (Tamper Protection) impide el cambio, se informa y se
    /// mantienen las exclusiones, sin bloquear el residente.
    /// </summary>
    public static class Defender
    {
        private static readonly object Sync = new object();

        public static string PowerShellPath()
        {
            try
            {
                string windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                if (!string.IsNullOrEmpty(windir))
                {
                    string path = Path.Combine(windir, @"System32\WindowsPowerShell\v1.0\powershell.exe");
                    if (File.Exists(path)) return path;
                }
            }
            catch
            {
            }
            return "powershell.exe";
        }

        public static DefenderStatus Query()
        {
            DefenderStatus status = new DefenderStatus();
            string script =
                "$ErrorActionPreference = 'Stop'\r\n" +
                "try {\r\n" +
                "  if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {\r\n" +
                "    'AVAILABLE=False'\r\n" +
                "    'PRESENT=False'\r\n" +
                "    exit 0\r\n" +
                "  }\r\n" +
                "  $s = Get-MpComputerStatus -ErrorAction Stop\r\n" +
                "  'AVAILABLE=True'\r\n" +
                "  'PRESENT=True'\r\n" +
                "  'REALTIME=' + [bool]$s.RealTimeProtectionEnabled\r\n" +
                "  'ANTIVIRUS=' + [bool]$s.AntivirusEnabled\r\n" +
                "  'TAMPER=' + [bool]$s.IsTamperProtected\r\n" +
                "} catch {\r\n" +
                "  'AVAILABLE=True'\r\n" +
                "  'PRESENT=False'\r\n" +
                "  'ERROR=' + ($_.Exception.Message -replace \"`r|`n\", ' ')\r\n" +
                "}\r\n";

            string output;
            string error;
            int code;
            RunScript(script, out output, out error, out code);
            status.Available = ParseBool(output, "AVAILABLE");
            status.Present = ParseBool(output, "PRESENT");
            status.RealTimeEnabled = ParseBool(output, "REALTIME");
            status.AntivirusEnabled = ParseBool(output, "ANTIVIRUS");
            status.TamperProtected = ParseBool(output, "TAMPER");
            status.Error = ParseText(output, "ERROR");
            if (string.IsNullOrEmpty(status.Error) && code != 0) status.Error = (error ?? string.Empty).Trim();
            return status;
        }

        public static string Describe(DefenderStatus status)
        {
            if (status == null) return "sin datos";
            if (!status.Available)
            {
                if (!string.IsNullOrEmpty(status.Error))
                {
                    string detail = status.Error.Trim();
                    if (detail.Length > 140) detail = detail.Substring(0, 140) + "…";
                    return "no disponible (" + detail + ")";
                }
                return "no disponible en este equipo";
            }
            if (!status.Present)
            {
                if (!string.IsNullOrEmpty(status.Error))
                {
                    string detail = status.Error.Trim();
                    if (detail.Length > 140) detail = detail.Substring(0, 140) + "…";
                    return "no se pudo consultar (" + detail + ")";
                }
                return "no se pudo consultar (¿otro antivirus lo sustituye?)";
            }
            string text = status.RealTimeEnabled
                ? "protección en tiempo real activa"
                : "protección en tiempo real desactivada";
            if (status.TamperProtected) text += " · protección contra alteraciones activa";
            return text;
        }

        /// <summary>
        /// Prepara la convivencia antes de arrancar el residente: añade
        /// exclusiones y, si la configuración lo permite, pausa la protección
        /// en tiempo real de Defender. Nunca lanza excepciones.
        /// </summary>
        public static bool Prepare(AppSettings settings, Action<LogLevel, string> log)
        {
            lock (Sync)
            {
                bool pause = settings == null || settings.PauseDefender;
                AddExclusions(settings, log);

                DefenderMarker existing = LoadMarker();
                DefenderStatus status = Query();
                if (!status.Available || !status.Present)
                {
                    Emit(log, LogLevel.Info, "Windows Defender: " + Describe(status) + ". No es necesario pausarlo.");
                    // No se toca una marca previa: si Defender no se puede
                    // consultar, se intentará restaurar más adelante.
                    return true;
                }

                if (!pause)
                {
                    Emit(log, LogLevel.Info, "Windows Defender: " + Describe(status) +
                        ". La pausa automática está desactivada en la configuración.");
                    if (existing != null && existing.PausedByUs) Restore(log);
                    else DeleteMarker();
                    return true;
                }

                if (!status.RealTimeEnabled)
                {
                    if (existing != null && existing.PausedByUs && existing.RealTimeWasEnabled)
                    {
                        Emit(log, LogLevel.Info,
                            "Windows Defender continúa en pausa por ClamGuard; se reactivará al detener el residente.");
                    }
                    else
                    {
                        DeleteMarker();
                        Emit(log, LogLevel.Info, "Windows Defender ya tiene la protección en tiempo real desactivada.");
                    }
                    return true;
                }

                bool set = SetRealTime(true);
                if (set && WaitForRealTime(false, 4))
                {
                    SaveMarker(true, true, "Pausado por ClamGuard.");
                    Emit(log, LogLevel.Ok,
                        "Windows Defender en pausa mientras la protección residente esté activa. " +
                        "Se reactivará al detener el residente.");
                    return true;
                }

                DeleteMarker();
                string hint = status.TamperProtected
                    ? " La protección contra alteraciones de Windows Defender puede impedirlo."
                    : string.Empty;
                Emit(log, LogLevel.Warn,
                    "No se pudo pausar Windows Defender." + hint +
                    " ClamGuard funcionará con exclusiones para sus carpetas; puede haber análisis duplicados.");
                return false;
            }
        }

        /// <summary>
        /// Reactiva Windows Defender si ClamGuard lo había pausado. Se llama al
        /// detener o desinstalar el residente y al arrancar la interfaz para
        /// recuperar un estado huérfano. Nunca lanza excepciones.
        /// </summary>
        public static bool Restore(Action<LogLevel, string> log)
        {
            lock (Sync)
            {
                DefenderMarker marker = LoadMarker();
                if (marker == null) return true;

                if (!marker.PausedByUs || !marker.RealTimeWasEnabled)
                {
                    DeleteMarker();
                    return true;
                }

                bool set = SetRealTime(false);
                if (set && WaitForRealTime(true, 4))
                {
                    DeleteMarker();
                    Emit(log, LogLevel.Ok, "Windows Defender reactivado al detener la protección residente.");
                    return true;
                }

                Emit(log, LogLevel.Warn,
                    "No se pudo reactivar Windows Defender automáticamente. " +
                    "Abre Seguridad de Windows y activa la protección en tiempo real.");
                return false;
            }
        }

        /// <summary>
        /// Si existe una marca de pausa pero el servicio residente no está en
        /// marcha (por ejemplo, tras un cierre inesperado), reactiva Defender.
        /// </summary>
        public static void RecoverIfNeeded(Action<LogLevel, string> log)
        {
            try
            {
                if (!File.Exists(AppPaths.DefenderStateFile)) return;
                if (ResidentService.IsRunning()) return;
                Restore(log);
            }
            catch (Exception ex)
            {
                AppLog.Warn("Recuperación de Windows Defender: " + ex.Message);
            }
        }

        public static bool HasPendingRestore()
        {
            try { return File.Exists(AppPaths.DefenderStateFile); }
            catch { return false; }
        }

        /// <summary>
        /// Comprueba periódicamente que Defender sigue en pausa mientras el
        /// residente está activo. Windows puede reactivar su protección en
        /// tiempo real al no reconocer a ClamGuard como antivirus registrado.
        /// </summary>
        public static void Enforce(AppSettings settings, Action<LogLevel, string> log)
        {
            lock (Sync)
            {
                DefenderMarker marker = LoadMarker();
                if (marker == null || !marker.PausedByUs || !marker.RealTimeWasEnabled) return;

                DefenderStatus status = Query();
                if (!status.Present || !status.RealTimeEnabled) return;

                if (SetRealTime(true) && WaitForRealTime(false, 3))
                {
                    Emit(log, LogLevel.Warn,
                        "Windows Defender reactivó su protección en tiempo real; ClamGuard la pausa de nuevo.");
                }
                else
                {
                    Emit(log, LogLevel.Warn,
                        "Windows Defender volvió a activar la protección en tiempo real y no se pudo pausar. " +
                        "Puede haber análisis duplicados.");
                }
            }
        }

        // ------------------------------------------------------------------
        // Exclusiones y preferencias
        // ------------------------------------------------------------------

        private static void AddExclusions(AppSettings settings, Action<LogLevel, string> log)
        {
            try
            {
                List<string> paths = CollectExclusionPaths(settings, true);
                if (paths.Count == 0) return;

                StringBuilder script = new StringBuilder();
                script.AppendLine("$ErrorActionPreference = 'Stop'");
                script.Append("$paths = @(");
                for (int i = 0; i < paths.Count; i++)
                {
                    if (i > 0) script.Append(", ");
                    script.Append(PsQuote(paths[i]));
                }
                script.AppendLine(")");
                script.AppendLine("try {");
                script.AppendLine("  Add-MpPreference -ExclusionPath $paths -ErrorAction Stop");
                script.AppendLine("  'EXCLUSIONS=OK'");
                script.AppendLine("} catch {");
                script.AppendLine("  'EXCLUSIONS=ERR ' + ($_.Exception.Message -replace \"`r|`n\", ' ')");
                script.AppendLine("}");

                string output;
                string error;
                int code;
                RunScript(script.ToString(), out output, out error, out code);
                string result = ParseText(output, "EXCLUSIONS");
                if (string.Equals(result, "OK", StringComparison.OrdinalIgnoreCase))
                {
                    Emit(log, LogLevel.Info,
                        "Windows Defender: exclusiones añadidas para las carpetas de ClamGuard y ClamAV.");
                }
                else if (!string.IsNullOrEmpty(result))
                {
                    Emit(log, LogLevel.Info, "Windows Defender no aceptó las exclusiones: " + result);
                }
            }
            catch (Exception ex)
            {
                Emit(log, LogLevel.Info, "No se pudieron añadir exclusiones a Windows Defender: " + ex.Message);
            }
        }

        /// <summary>
        /// Retira las exclusiones que ClamGuard añadió a Windows Defender. Se
        /// usa al desinstalar para no dejar rastros. Nunca lanza excepciones.
        /// </summary>
        public static bool RemoveExclusions(AppSettings settings, bool includeEngineDir, Action<LogLevel, string> log)
        {
            try
            {
                List<string> paths = CollectExclusionPaths(settings, includeEngineDir);
                if (paths.Count == 0) return true;

                StringBuilder script = new StringBuilder();
                script.AppendLine("$ErrorActionPreference = 'Stop'");
                script.Append("$paths = @(");
                for (int i = 0; i < paths.Count; i++)
                {
                    if (i > 0) script.Append(", ");
                    script.Append(PsQuote(paths[i]));
                }
                script.AppendLine(")");
                script.AppendLine("try {");
                script.AppendLine("  Remove-MpPreference -ExclusionPath $paths -ErrorAction Stop");
                script.AppendLine("  'EXCLUSIONS=OK'");
                script.AppendLine("} catch {");
                script.AppendLine("  'EXCLUSIONS=ERR ' + ($_.Exception.Message -replace \"`r|`n\", ' ')");
                script.AppendLine("}");

                string output;
                string error;
                int code;
                RunScript(script.ToString(), out output, out error, out code);
                string result = ParseText(output, "EXCLUSIONS");
                if (string.Equals(result, "OK", StringComparison.OrdinalIgnoreCase))
                {
                    Emit(log, LogLevel.Info, "Windows Defender: exclusiones de ClamGuard retiradas.");
                    return true;
                }
                if (!string.IsNullOrEmpty(result))
                {
                    Emit(log, LogLevel.Warn, "Windows Defender no retiró las exclusiones: " + result);
                }
                return false;
            }
            catch (Exception ex)
            {
                Emit(log, LogLevel.Warn, "No se pudieron retirar las exclusiones de Windows Defender: " + ex.Message);
                return false;
            }
        }

        private static List<string> CollectExclusionPaths(AppSettings settings, bool includeEngineDir)
        {
            List<string> paths = new List<string>();
            AddDirectory(paths, AppPaths.DataDir);
            if (includeEngineDir)
                AddDirectory(paths, AppPaths.FindClamAvDirectory(settings == null ? null : settings.ClamAvDirectory));
            AddDirectory(paths, AppPaths.AppDir);
            return paths;
        }

        private static void AddDirectory(List<string> list, string path)
        {
            if (string.IsNullOrEmpty(path)) return;
            try
            {
                string full = Path.GetFullPath(path).TrimEnd('\\');
                if (!Directory.Exists(full)) return;
                if (!AppPaths.ContainsPath(list, full)) list.Add(full);
            }
            catch
            {
            }
        }

        private static bool SetRealTime(bool disable)
        {
            string script =
                "$ErrorActionPreference = 'Stop'\r\n" +
                "try {\r\n" +
                "  Set-MpPreference -DisableRealtimeMonitoring $" + (disable ? "true" : "false") + " -ErrorAction Stop\r\n" +
                "  'SET=OK'\r\n" +
                "} catch {\r\n" +
                "  'SET=ERR ' + ($_.Exception.Message -replace \"`r|`n\", ' ')\r\n" +
                "}\r\n";
            string output;
            string error;
            int code;
            RunScript(script, out output, out error, out code);
            if (code != 0) return false;
            return string.Equals(ParseText(output, "SET"), "OK", StringComparison.OrdinalIgnoreCase);
        }

        private static bool WaitForRealTime(bool expected, int attempts)
        {
            for (int i = 0; i < attempts; i++)
            {
                DefenderStatus status = Query();
                if (status.Present && status.RealTimeEnabled == expected) return true;
                Thread.Sleep(400);
            }
            return false;
        }

        private static string PsQuote(string value)
        {
            return "'" + (value ?? string.Empty).Replace("'", "''") + "'";
        }

        // ------------------------------------------------------------------
        // Ejecución de PowerShell y lectura de resultados
        // ------------------------------------------------------------------

        private static bool RunScript(string script, out string output, out string error, out int exitCode)
        {
            output = string.Empty;
            error = string.Empty;
            exitCode = -1;
            string file = null;
            try
            {
                AppPaths.EnsureLayout();
                file = Path.Combine(AppPaths.TempDir, "defender-" + Guid.NewGuid().ToString("N") + ".ps1");
                File.WriteAllText(file, script, new UTF8Encoding(false));
                string arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File " + Cmd.Quote(file);
                exitCode = Proc.RunHidden(PowerShellPath(), arguments, 45000, out output, out error);
                return exitCode == 0;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
            finally
            {
                try { if (file != null && File.Exists(file)) File.Delete(file); } catch { }
            }
        }

        private static bool ParseBool(string output, string key)
        {
            string value = ParseText(output, key);
            bool parsed;
            if (bool.TryParse(value, out parsed)) return parsed;
            return false;
        }

        private static string ParseText(string output, string key)
        {
            if (string.IsNullOrEmpty(output)) return string.Empty;
            string[] lines = output.Replace("\r", string.Empty).Split('\n');
            string prefix = key + "=";
            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i].Trim();
                if (line.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    return line.Substring(prefix.Length).Trim();
            }
            return string.Empty;
        }

        // ------------------------------------------------------------------
        // Marca persistente
        // ------------------------------------------------------------------

        private static void SaveMarker(bool pausedByUs, bool wasEnabled, string detail)
        {
            try
            {
                DefenderMarker marker = new DefenderMarker();
                marker.PausedByUs = pausedByUs;
                marker.RealTimeWasEnabled = wasEnabled;
                marker.SinceUtc = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
                marker.Detail = detail;
                JsonStore.Save(AppPaths.DefenderStateFile, marker);
            }
            catch (Exception ex)
            {
                AppLog.Warn("No se pudo guardar el estado de Windows Defender: " + ex.Message);
            }
        }

        private static DefenderMarker LoadMarker()
        {
            try
            {
                if (!File.Exists(AppPaths.DefenderStateFile)) return null;
                using (FileStream fs = File.OpenRead(AppPaths.DefenderStateFile))
                {
                    DataContractJsonSerializer ser = new DataContractJsonSerializer(typeof(DefenderMarker));
                    return ser.ReadObject(fs) as DefenderMarker;
                }
            }
            catch
            {
                return null;
            }
        }

        private static void DeleteMarker()
        {
            try { if (File.Exists(AppPaths.DefenderStateFile)) File.Delete(AppPaths.DefenderStateFile); } catch { }
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
