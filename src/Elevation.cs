using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Security.Principal;

namespace ClamGuard
{
    /// <summary>
    /// Control de elevación (UAC). Instalar ClamAV, escribir en ProgramData o
    /// registrar el servicio residente exige permisos de administrador.
    /// </summary>
    public static class Elevation
    {
        /// <summary>Variable de entorno para pruebas automatizadas sin UAC.</summary>
        public const string DisableVariable = "CLAMGUARD_NO_ELEVATE";

        /// <summary>Argumento equivalente a la variable anterior.</summary>
        public const string DisableSwitch = "--no-elevate";

        /// <summary>Marca interna para evitar bucles de elevación.</summary>
        public const string RetrySwitch = "--elevated";

        public static bool IsElevated
        {
            get
            {
                try
                {
                    using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                    {
                        WindowsPrincipal principal = new WindowsPrincipal(identity);
                        return principal.IsInRole(WindowsBuiltInRole.Administrator);
                    }
                }
                catch
                {
                    return false;
                }
            }
        }

        /// <summary>
        /// Indica si se debe omitir la solicitud de UAC (solo para pruebas).
        /// </summary>
        public static bool IsDisabled(string[] args)
        {
            string value = null;
            try { value = Environment.GetEnvironmentVariable(DisableVariable); } catch { }
            if (!string.IsNullOrEmpty(value) &&
                (value == "1" || string.Equals(value, "true", StringComparison.OrdinalIgnoreCase)))
                return true;

            if (args != null)
            {
                for (int i = 0; i < args.Length; i++)
                {
                    if (string.Equals(args[i], DisableSwitch, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Indica si este proceso ya fue relanzado por nosotros para pedir UAC.
        /// Si tras el relanzamiento sigue sin privilegios, no se vuelve a intentar.
        /// </summary>
        public static bool IsRetry(string[] args)
        {
            if (args == null) return false;
            for (int i = 0; i < args.Length; i++)
            {
                if (string.Equals(args[i], RetrySwitch, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        public static string ExecutablePath()
        {
            try
            {
                Assembly assembly = Assembly.GetEntryAssembly();
                if (assembly != null && !string.IsNullOrEmpty(assembly.Location))
                    return assembly.Location;
            }
            catch
            {
            }
            try
            {
                return Process.GetCurrentProcess().MainModule.FileName;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Inicia de nuevo ClamGuard solicitando elevación (verbo "runas").
        /// Devuelve true si el proceso elevado se inició. Si el usuario canceló
        /// el aviso de UAC, <paramref name="canceled"/> queda en true.
        /// </summary>
        public static bool RelaunchElevated(string[] args, out bool canceled)
        {
            canceled = false;
            string exe = ExecutablePath();
            if (string.IsNullOrEmpty(exe)) return false;

            try
            {
                ProcessStartInfo info = new ProcessStartInfo();
                info.FileName = exe;
                info.Arguments = BuildArguments(args);
                info.UseShellExecute = true;
                info.Verb = "runas";
                info.WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory;
                Process.Start(info);
                return true;
            }
            catch (Win32Exception ex)
            {
                // 1223 = ERROR_CANCELLED: el usuario rechazó el aviso de UAC.
                if (ex.NativeErrorCode == 1223) canceled = true;
                return false;
            }
            catch
            {
                return false;
            }
        }

        private static string BuildArguments(string[] args)
        {
            List<string> forwarded = new List<string>();
            if (args != null)
            {
                for (int i = 0; i < args.Length; i++)
                {
                    if (string.Equals(args[i], DisableSwitch, StringComparison.OrdinalIgnoreCase)) continue;
                    if (string.Equals(args[i], RetrySwitch, StringComparison.OrdinalIgnoreCase)) continue;
                    forwarded.Add(args[i]);
                }
            }
            forwarded.Add(RetrySwitch);

            System.Text.StringBuilder sb = new System.Text.StringBuilder();
            for (int i = 0; i < forwarded.Count; i++)
            {
                if (i > 0) sb.Append(' ');
                sb.Append(Cmd.Quote(forwarded[i]));
            }
            return sb.ToString();
        }
    }
}
