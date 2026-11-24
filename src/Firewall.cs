using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace ClamGuard
{
    public static class Firewall
    {
        public static bool IsElevated { get { return Elevation.IsElevated; } }
        public static bool RunNetsh(string arguments, out string output, out string error)
        {
            output = string.Empty;
            error = string.Empty;
            try
            {
                string cmdArgs = "/c chcp 65001 >nul & netsh " + arguments;
                ProcessResult r = Proc.Run("cmd.exe", cmdArgs, null, 60000, System.Threading.CancellationToken.None);
                output = r.Output;
                error = r.Error;
                return r.ExitCode == 0;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        /// <summary>Copia de la política guardada al entrar en "bloquear todo".</summary>
        public static string BackupPath
        {
            get { return Path.Combine(AppPaths.DataDir, "firewall-antes-de-bloquear.wfw"); }
        }

        /// <summary>
        /// Si hay copia de "bloquear todo", la importa (vuelven las reglas y su estado
        /// tal como estaban) y la borra. Sin copia no toca nada.
        /// </summary>
        private static bool RestoreBackupIfAny(out string error)
        {
            error = string.Empty;
            string backup = BackupPath;
            if (!File.Exists(backup)) return true;
            string o, e;
            if (!RunNetsh("advfirewall import \"" + backup + "\"", out o, out e))
            {
                error = "No se pudo restaurar la copia del cortafuegos (" + backup + "). " + e;
                return false;
            }
            try { File.Delete(backup); } catch { }
            return true;
        }

        public static string GetStatus()
        {
            string output, error;
            if (RunNetsh("advfirewall show allprofiles", out output, out error))
                return output;
            return "Error: " + error;
        }

        public static bool SetMode(string mode, out string error)
        {
            error = string.Empty;
            if (!Elevation.IsElevated)
            {
                error = "Se necesitan permisos de administrador para cambiar el cortafuegos.";
                return false;
            }
            if (mode == "allowall")
            {
                string o, e;
                if (!RestoreBackupIfAny(out error)) return false;
                if (!RunNetsh("advfirewall set allprofiles state off", out o, out e)) { error = e; return false; }
                return true;
            }
            if (mode == "blockall")
            {
                string o, e;
                // Guardar la política actual, con el estado de cada regla, una sola vez:
                // al salir de este modo se vuelve exactamente a ella.
                if (!File.Exists(BackupPath))
                {
                    if (!RunNetsh("advfirewall export \"" + BackupPath + "\"", out o, out e))
                    {
                        error = "No se pudo guardar una copia del cortafuegos antes de bloquear; no se ha cambiado nada. " + e;
                        return false;
                    }
                }
                if (!RunNetsh("advfirewall set allprofiles state on", out o, out e)) { error = e; return false; }
                if (!RunNetsh("advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound", out o, out e)) { error = e; return false; }
                // Deshabilitar reglas existentes para que el bloqueo sea efectivo (estilo TinyWall)
                RunNetsh("advfirewall firewall set rule all new enable=no", out o, out e);
                return true;
            }
            // active (default): block inbound, allow outbound
            {
                string o, e;
                // Volver a las reglas que había antes de "bloquear todo". No se usa
                // "set rule all new enable=yes": habilitaría también las reglas que
                // Windows trae deshabilitadas (compartir archivos, administración remota...).
                if (!RestoreBackupIfAny(out error)) return false;
                if (!RunNetsh("advfirewall set allprofiles state on", out o, out e)) { error = e; return false; }
                if (!RunNetsh("advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound", out o, out e)) { error = e; return false; }
                return true;
            }
        }

        public static bool AddProgram(string name, string path, bool allow, out string error)
        {
            error = string.Empty;
            string action = allow ? "allow" : "block";
            string args = "advfirewall firewall add rule name=\"" + name + "\" dir=in action=" + action + " program=\"" + path + "\" enable=yes";
            string o, e;
            if (!RunNetsh(args, out o, out e)) { error = e; return false; }
            string argsOut = "advfirewall firewall add rule name=\"" + name + " (salida)\" dir=out action=" + action + " program=\"" + path + "\" enable=yes";
            RunNetsh(argsOut, out o, out e);
            return true;
        }

        public static bool RemoveProgram(string name, out string error)
        {
            error = string.Empty;
            string o, e;
            RunNetsh("advfirewall firewall delete rule name=\"" + name + "\"", out o, out e);
            RunNetsh("advfirewall firewall delete rule name=\"" + name + " (salida)\"", out o, out e);
            return true;
        }

        public static bool AddPort(string name, int port, string protocol, bool allow, out string error)
        {
            error = string.Empty;
            string action = allow ? "allow" : "block";
            string proto = protocol.ToUpperInvariant();
            string args = "advfirewall firewall add rule name=\"" + name + "\" dir=in action=" + action + " protocol=" + proto + " localport=" + port + " enable=yes";
            string o, e;
            if (!RunNetsh(args, out o, out e)) { error = e; return false; }
            string argsOut = "advfirewall firewall add rule name=\"" + name + " (salida)\" dir=out action=" + action + " protocol=" + proto + " localport=" + port + " enable=yes";
            RunNetsh(argsOut, out o, out e);
            return true;
        }

        public static bool RemovePort(string name, out string error)
        {
            error = string.Empty;
            string o, e;
            RunNetsh("advfirewall firewall delete rule name=\"" + name + "\"", out o, out e);
            RunNetsh("advfirewall firewall delete rule name=\"" + name + " (salida)\"", out o, out e);
            return true;
        }

        public static List<string> ListRules()
        {
            List<string> result = new List<string>();
            string o, e;
            if (RunNetsh("advfirewall firewall show rule name=all", out o, out e))
            {
                string[] lines = o.Split(new string[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
                for (int i = 0; i < lines.Length; i++)
                {
                    string line = lines[i].Trim();
                    if (line.IndexOf("Nombre de regla", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        line.IndexOf("Rule Name", StringComparison.OrdinalIgnoreCase) >= 0)
                        result.Add(line);
                }
            }
            return result;
        }
    }
}
