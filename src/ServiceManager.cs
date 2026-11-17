using System;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using System.Threading;
using Microsoft.Win32;

namespace ClamGuard
{
    public enum ResidentState
    {
        NotInstalled,
        Stopped,
        StartPending,
        StopPending,
        Running,
        Paused,
        Unknown
    }

    public static class ResidentService
    {
        private static string ScExe
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "sc.exe"); }
        }

        public static bool IsInstalled()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\" + AppPaths.ServiceName))
                {
                    return key != null;
                }
            }
            catch
            {
                return false;
            }
        }

        public static ResidentState GetState()
        {
            if (!IsInstalled()) return ResidentState.NotInstalled;
            ServiceController controller = null;
            try
            {
                controller = new ServiceController(AppPaths.ServiceName);
                ServiceControllerStatus status = controller.Status;
                switch (status)
                {
                    case ServiceControllerStatus.Running: return ResidentState.Running;
                    case ServiceControllerStatus.Stopped: return ResidentState.Stopped;
                    case ServiceControllerStatus.StartPending: return ResidentState.StartPending;
                    case ServiceControllerStatus.StopPending: return ResidentState.StopPending;
                    case ServiceControllerStatus.Paused: return ResidentState.Paused;
                    default: return ResidentState.Unknown;
                }
            }
            catch
            {
                return ResidentState.Unknown;
            }
            finally
            {
                if (controller != null) controller.Dispose();
            }
        }

        public static bool IsRunning()
        {
            return GetState() == ResidentState.Running;
        }

        public static string DescribeState(ResidentState state)
        {
            switch (state)
            {
                case ResidentState.Running: return "activa";
                case ResidentState.Stopped: return "detenida";
                case ResidentState.StartPending: return "iniciando";
                case ResidentState.StopPending: return "deteniendo";
                case ResidentState.Paused: return "en pausa";
                case ResidentState.NotInstalled: return "no instalada";
                default: return "estado desconocido";
            }
        }

        public static bool Install(out string error)
        {
            error = string.Empty;
            try
            {
                if (!IsAdministrator())
                {
                    error = "Se necesitan permisos de administrador para instalar el servicio.";
                    return false;
                }
                if (!AppPaths.IsValidClamAvDir(AppPaths.FindClamAvDirectory(AppSettings.Load().ClamAvDirectory), true))
                {
                    error = "ClamAV no está instalado o falta clamd.exe.";
                    return false;
                }
                if (IsInstalled())
                {
                    return Start(out error);
                }

                string exe = AppPaths.ExePath;
                if (!File.Exists(exe))
                {
                    error = "No se encontró el ejecutable de ClamGuard.";
                    return false;
                }

                string binPath = "\"\\\"" + exe + "\\\" --service\"";
                string arguments = "create " + AppPaths.ServiceName +
                    " binPath= " + binPath +
                    " start= auto DisplayName= \"" + AppPaths.ServiceDisplayName + "\" obj= LocalSystem";
                int code = RunSc(arguments, out error);
                if (code != 0)
                {
                    error = "No se pudo crear el servicio (sc=" + code + "). " + error;
                    return false;
                }

                RunSc("description " + AppPaths.ServiceName +
                    " \"Proteccion residente de ClamAV (analisis al crear o modificar archivos)\"", out error);
                RunSc("failure " + AppPaths.ServiceName +
                    " reset= 86400 actions= restart/60000/restart/60000/restart/60000", out error);
                RunSc("config " + AppPaths.ServiceName + " start= auto", out error);

                AppLog.Ok("Servicio residente creado.");
                return Start(out error);
            }
            catch (Exception ex)
            {
                error = "Error al instalar el residente: " + ex.Message;
                AppLog.Error(error);
                return false;
            }
        }

        public static bool Start(out string error)
        {
            error = string.Empty;
            ServiceController controller = null;
            try
            {
                if (!IsInstalled())
                {
                    error = "El servicio residente no está instalado.";
                    return false;
                }
                controller = new ServiceController(AppPaths.ServiceName);
                if (controller.Status == ServiceControllerStatus.Running) return true;
                if (controller.Status == ServiceControllerStatus.StartPending)
                {
                    controller.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                    return true;
                }
                controller.Start();
                controller.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                AppLog.Ok("Servicio residente iniciado.");
                return true;
            }
            catch (Exception ex)
            {
                error = "No se pudo iniciar el residente: " + ex.Message;
                AppLog.Error(error);
                return false;
            }
            finally
            {
                if (controller != null) controller.Dispose();
            }
        }

        public static bool Stop(out string error)
        {
            error = string.Empty;
            ServiceController controller = null;
            try
            {
                if (!IsInstalled())
                {
                    Defender.Restore(null);
                    return true;
                }
                controller = new ServiceController(AppPaths.ServiceName);
                if (controller.Status == ServiceControllerStatus.Stopped)
                {
                    Defender.Restore(null);
                    return true;
                }
                if (controller.Status != ServiceControllerStatus.StopPending)
                    controller.Stop();
                controller.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(45));
                AppLog.Ok("Servicio residente detenido.");
                Defender.Restore(null);
                return true;
            }
            catch (Exception ex)
            {
                error = "No se pudo detener el residente: " + ex.Message;
                AppLog.Error(error);
                return false;
            }
            finally
            {
                if (controller != null) controller.Dispose();
            }
        }

        public static bool Uninstall(out string error)
        {
            error = string.Empty;
            try
            {
                if (!IsInstalled()) return true;
                if (!Stop(out error)) return false;
                int code = RunSc("delete " + AppPaths.ServiceName, out error);
                if (code != 0)
                {
                    error = "No se pudo eliminar el servicio (sc=" + code + "). " + error;
                    return false;
                }
                for (int i = 0; i < 20 && IsInstalled(); i++) Thread.Sleep(250);
                AppLog.Ok("Servicio residente desinstalado.");
                return true;
            }
            catch (Exception ex)
            {
                error = "Error al desinstalar el residente: " + ex.Message;
                AppLog.Error(error);
                return false;
            }
        }

        public static bool Restart(out string error)
        {
            if (!Stop(out error)) return false;
            return Start(out error);
        }

        private static int RunSc(string arguments, out string error)
        {
            string output;
            string err;
            int code = Proc.RunHidden(ScExe, arguments, 30000, out output, out err);
            error = (err + " " + output).Trim();
            return code;
        }

        public static bool IsAdministrator()
        {
            try
            {
                System.Security.Principal.WindowsPrincipal principal =
                    new System.Security.Principal.WindowsPrincipal(
                        System.Security.Principal.WindowsIdentity.GetCurrent());
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }
    }
}
