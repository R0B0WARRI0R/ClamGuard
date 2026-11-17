using System;
using System.Net;
using System.ServiceProcess;
using System.Threading;
using System.Windows.Forms;

namespace ClamGuard
{
    internal static class Program
    {
        [STAThread]
        private static void Main(string[] args)
        {
            try
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            }
            catch
            {
            }

            bool serviceMode = false;
            bool uninstallMode = false;
            if (args != null)
            {
                for (int i = 0; i < args.Length; i++)
                {
                    if (string.Equals(args[i], "--service", StringComparison.OrdinalIgnoreCase))
                        serviceMode = true;
                    if (string.Equals(args[i], "--uninstall", StringComparison.OrdinalIgnoreCase))
                        uninstallMode = true;
                }
            }

            if (serviceMode)
            {
                AppLog.Init("resident");
                ServiceBase.Run(new ServiceBase[] { new ClamGuardService() });
                return;
            }

            // Instalar ClamAV, escribir en ProgramData y registrar el servicio
            // residente requieren privilegios. El manifiesto ya lo solicita,
            // pero se comprueba también en tiempo de ejecución para que el
            // aviso de UAC aparezca en cualquier compilación o al reiniciar.
            if (!Elevation.IsElevated && !Elevation.IsDisabled(args))
            {
                if (!Elevation.IsRetry(args))
                {
                    bool canceled;
                    if (Elevation.RelaunchElevated(args, out canceled)) return;
                    if (canceled)
                    {
                        MessageBox.Show(
                            "ClamGuard no puede continuar sin permisos de administrador.\n\n" +
                            "Para instalar ClamAV y activar la protección residente, vuelve a abrir " +
                            "ClamGuard y acepta el aviso de Control de cuentas de usuario (UAC).",
                            "ClamGuard", MessageBoxButtons.OK, MessageBoxIcon.Information);
                        return;
                    }
                }

                MessageBox.Show(
                    "ClamGuard necesita permisos de administrador para instalar ClamAV y " +
                    "proteger el equipo.\n\nCierra esta ventana y ejecuta ClamGuard de nuevo " +
                    "aceptando el aviso de Control de cuentas de usuario (UAC).",
                    "ClamGuard", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ThreadException += delegate(object sender, ThreadExceptionEventArgs e)
            {
                HandleFatal(e.Exception);
            };
            AppDomain.CurrentDomain.UnhandledException += delegate(object sender, UnhandledExceptionEventArgs e)
            {
                Exception ex = e.ExceptionObject as Exception;
                AppLog.Error("Excepción no controlada: " + (ex == null ? "desconocida" : ex.ToString()));
            };

            bool created;
            using (Mutex mutex = new Mutex(true, @"Local\ClamGuardGui", out created))
            {
                if (!created)
                {
                    MessageBox.Show(
                        uninstallMode
                            ? "ClamGuard ya está abierto.\n\nUsa el enlace «Desinstalar» de la ventana abierta " +
                              "o el menú del icono de la bandeja para desinstalarlo por completo."
                            : "ClamGuard ya está abierto.",
                        "ClamGuard", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }

                try
                {
                    AppPaths.EnsureLayout();
                    AppLog.Init("clamguard");
                    Application.Run(new MainForm(uninstallMode));
                }
                catch (Exception ex)
                {
                    HandleFatal(ex);
                }
                finally
                {
                    try { mutex.ReleaseMutex(); } catch { }
                }
            }
        }

        private static void HandleFatal(Exception ex)
        {
            try { AppLog.Error("Error fatal: " + ex); } catch { }
            try
            {
                MessageBox.Show(
                    "ClamGuard encontró un error inesperado:\n\n" + (ex == null ? "Error desconocido" : ex.Message) +
                    "\n\nSe guardaron detalles en el registro de ClamGuard.",
                    "ClamGuard", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            catch
            {
            }
        }
    }
}
