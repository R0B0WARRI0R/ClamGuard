using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace ClamGuard
{
    public sealed class EngineInfo
    {
        public string Version = string.Empty;
        public string SignatureVersion = string.Empty;
        public string SignatureDateText = string.Empty;
        public DateTime? SignatureDate;

        public bool HasSignatureInfo
        {
            get { return !string.IsNullOrEmpty(SignatureVersion); }
        }
    }

    public sealed class SignatureInfo
    {
        public DateTime? Date;
        public string FileName = string.Empty;
        public long TotalBytes;

        public string DateText
        {
            get { return Date.HasValue ? Date.Value.ToString("dd/MM/yyyy") : "sin firmas"; }
        }
    }

    public sealed class UpdateResult
    {
        public bool Success;
        public bool Updated;
        public bool Canceled;
        public bool Busy;
        public string Message = string.Empty;
        public string Output = string.Empty;
        public int ExitCode;
        public SignatureInfo Signatures;
    }

    public sealed class ClamdScanResult
    {
        public bool Clean;
        public bool Infected;
        public string Signature = string.Empty;
        public string Raw = string.Empty;
        public string Error = string.Empty;

        public static ClamdScanResult CleanResult()
        {
            ClamdScanResult r = new ClamdScanResult();
            r.Clean = true;
            return r;
        }

        public static ClamdScanResult ErrorResult(string message)
        {
            ClamdScanResult r = new ClamdScanResult();
            r.Error = message;
            return r;
        }
    }

    public static class ClamAv
    {
        public const long MaxResidentFileBytes = 200L * 1024 * 1024;

        public static string GetExe(string dir, string name)
        {
            if (string.IsNullOrEmpty(dir)) return null;
            string path = Path.Combine(dir, name);
            return File.Exists(path) ? path : null;
        }

        public static EngineInfo QueryEngine(AppSettings settings)
        {
            EngineInfo info = new EngineInfo();
            string dir = AppPaths.FindClamAvDirectory(settings == null ? null : settings.ClamAvDirectory);
            string clamscan = GetExe(dir, "clamscan.exe");
            if (clamscan == null) return info;

            ProcessResult result = Proc.Run(clamscan, "--version", dir, 20000, CancellationToken.None);
            string text = (result.Output + "\n" + result.Error).Trim();
            string[] lines = text.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            string versionLine = null;
            for (int i = 0; i < lines.Length; i++)
            {
                if (lines[i].IndexOf("ClamAV", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    versionLine = lines[i].Trim();
                    break;
                }
            }
            if (versionLine == null) return info;

            string[] parts = versionLine.Split('/');
            string first = parts[0].Replace("ClamAV", string.Empty).Trim();
            info.Version = first;
            if (parts.Length > 1) info.SignatureVersion = parts[1].Trim();
            if (parts.Length > 2) info.SignatureDateText = parts[2].Trim();

            if (info.SignatureDateText.Length > 0)
            {
                DateTime parsed;
                if (DateTime.TryParse(info.SignatureDateText,
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AllowWhiteSpaces, out parsed))
                    info.SignatureDate = parsed;
            }
            return info;
        }

        public static SignatureInfo GetSignatureInfo(string databaseDir)
        {
            SignatureInfo info = new SignatureInfo();
            try
            {
                if (!Directory.Exists(databaseDir)) return info;
                string[] files = Directory.GetFiles(databaseDir, "*.c*");
                for (int i = 0; i < files.Length; i++)
                {
                    string name = Path.GetFileName(files[i]).ToLowerInvariant();
                    if (name != "daily.cld" && name != "daily.cvd" && name != "main.cld" &&
                        name != "main.cvd" && name != "bytecode.cvd" && name != "bytecode.cld")
                        continue;
                    FileInfo fi = new FileInfo(files[i]);
                    info.TotalBytes += fi.Length;
                    if (name.StartsWith("daily") || info.Date == null || fi.LastWriteTime > info.Date.Value)
                    {
                        if (name.StartsWith("daily") || info.Date == null)
                        {
                            info.Date = fi.LastWriteTime;
                            info.FileName = fi.Name;
                        }
                    }
                }
            }
            catch
            {
            }
            return info;
        }

        public static bool HasDatabase(string databaseDir)
        {
            try
            {
                if (!Directory.Exists(databaseDir)) return false;
                string[] names = new string[] { "daily.cld", "daily.cvd", "main.cld", "main.cvd" };
                for (int i = 0; i < names.Length; i++)
                {
                    FileInfo fi = new FileInfo(Path.Combine(databaseDir, names[i]));
                    if (fi.Exists && fi.Length > 1024) return true;
                }
            }
            catch
            {
            }
            return false;
        }

        public static string FormatBytes(long bytes)
        {
            if (bytes <= 0) return "0 B";
            string[] units = new string[] { "B", "KB", "MB", "GB" };
            double value = bytes;
            int unit = 0;
            while (value >= 1024 && unit < units.Length - 1)
            {
                value /= 1024;
                unit++;
            }
            return string.Format(System.Globalization.CultureInfo.InvariantCulture,
                value >= 10 ? "{0:0} {1}" : "{0:0.0} {1}", value, units[unit]);
        }

        public static void WriteConfigs(AppSettings settings)
        {
            if (settings == null) settings = AppSettings.Load();
            AppPaths.EnsureLayout();

            string db = AppPaths.DatabaseDir.Replace('\\', '/');
            string logs = AppPaths.LogsDir.Replace('\\', '/');
            string tmp = AppPaths.TempDir.Replace('\\', '/');

            StringBuilder fresh = new StringBuilder();
            fresh.AppendLine("# Generado automáticamente por ClamGuard. No editar a mano.");
            fresh.AppendLine("DatabaseDirectory \"" + db + "\"");
            fresh.AppendLine("UpdateLogFile \"" + logs + "/freshclam.log\"");
            fresh.AppendLine("LogTime yes");
            fresh.AppendLine("LogFileMaxSize 5M");
            fresh.AppendLine("DatabaseMirror database.clamav.net");
            fresh.AppendLine("ConnectTimeout 30");
            fresh.AppendLine("ReceiveTimeout 120");
            fresh.AppendLine("Checks 4");

            StringBuilder clamd = new StringBuilder();
            clamd.AppendLine("# Generado automáticamente por ClamGuard. No editar a mano.");
            clamd.AppendLine("DatabaseDirectory \"" + db + "\"");
            clamd.AppendLine("TemporaryDirectory \"" + tmp + "\"");
            clamd.AppendLine("Foreground yes");
            clamd.AppendLine("LogFile \"" + logs + "/clamd.log\"");
            clamd.AppendLine("LogTime yes");
            clamd.AppendLine("LogFileMaxSize 10M");
            clamd.AppendLine("LogRotate yes");
            clamd.AppendLine("TCPSocket " + settings.ClamdPort.ToString(System.Globalization.CultureInfo.InvariantCulture));
            clamd.AppendLine("TCPAddr 127.0.0.1");
            clamd.AppendLine("MaxThreads 4");
            clamd.AppendLine("MaxConnectionQueueLength 20");
            clamd.AppendLine("StreamMaxLength 200M");
            clamd.AppendLine("MaxScanSize 400M");
            clamd.AppendLine("MaxFileSize 200M");
            clamd.AppendLine("MaxRecursion 12");
            clamd.AppendLine("ReadTimeout 300");
            clamd.AppendLine("CommandReadTimeout 30");
            clamd.AppendLine("SelfCheck 1800");
            clamd.AppendLine("AlertExceedsMax yes");

            WriteIfChanged(AppPaths.FreshclamConf, fresh.ToString());
            WriteIfChanged(AppPaths.ClamdConf, clamd.ToString());
        }

        private static void WriteIfChanged(string path, string content)
        {
            try
            {
                if (File.Exists(path))
                {
                    string current = File.ReadAllText(path, Encoding.UTF8);
                    if (string.Equals(current, content, StringComparison.Ordinal)) return;
                }
                File.WriteAllText(path, content, new UTF8Encoding(false));
            }
            catch (Exception ex)
            {
                AppLog.Error("No se pudo escribir " + path + ": " + ex.Message);
            }
        }

        public static bool Ping(int port, int timeoutMs)
        {
            string response = SendCommand("zPING\0", port, timeoutMs);
            return response != null && response.Trim().Equals("PONG", StringComparison.OrdinalIgnoreCase);
        }

        public static bool WaitForClamd(int port, int timeoutMs, CancellationToken token)
        {
            Stopwatch watch = Stopwatch.StartNew();
            while (watch.ElapsedMilliseconds < timeoutMs)
            {
                if (token.IsCancellationRequested) return false;
                if (Ping(port, 1500)) return true;
                Thread.Sleep(700);
            }
            return false;
        }

        public static string SendCommand(string command, int port, int timeoutMs)
        {
            try
            {
                using (TcpClient client = new TcpClient())
                {
                    IAsyncResult ar = client.BeginConnect(IPAddress.Loopback, port, null, null);
                    if (!ar.AsyncWaitHandle.WaitOne(timeoutMs)) return null;
                    client.EndConnect(ar);

                    using (NetworkStream stream = client.GetStream())
                    {
                        stream.ReadTimeout = timeoutMs;
                        stream.WriteTimeout = timeoutMs;
                        byte[] data = Encoding.ASCII.GetBytes(command);
                        stream.Write(data, 0, data.Length);
                        stream.Flush();

                        MemoryStream response = new MemoryStream();
                        byte[] buffer = new byte[1024];
                        int total = 0;
                        while (total < 128 * 1024)
                        {
                            int read;
                            try { read = stream.Read(buffer, 0, buffer.Length); }
                            catch (IOException) { break; }
                            if (read <= 0) break;
                            response.Write(buffer, 0, read);
                            total += read;
                            bool terminated = false;
                            for (int i = 0; i < read; i++)
                            {
                                if (buffer[i] == 0) { terminated = true; break; }
                            }
                            if (terminated) break;
                        }
                        string text = Encoding.UTF8.GetString(response.ToArray());
                        return text.Replace("\0", string.Empty).Trim();
                    }
                }
            }
            catch
            {
                return null;
            }
        }

        public static bool ReloadClamd(int port, int timeoutMs)
        {
            try
            {
                string response = SendCommand("zRELOAD\0", port, 5000);
                if (response == null) return false;
                AppLog.Info("clamd: recarga de firmas solicitada (" + response + ").");
                return WaitForClamd(port, timeoutMs, CancellationToken.None);
            }
            catch (Exception ex)
            {
                AppLog.Warn("No se pudo recargar clamd: " + ex.Message);
                return false;
            }
        }

        public static void ShutdownClamd(int port)
        {
            try { SendCommand("zSHUTDOWN\0", port, 3000); } catch { }
        }

        public static ClamdScanResult ScanStream(string filePath, int port, int timeoutMs)
        {
            try
            {
                using (TcpClient client = new TcpClient())
                {
                    IAsyncResult ar = client.BeginConnect(IPAddress.Loopback, port, null, null);
                    if (!ar.AsyncWaitHandle.WaitOne(Math.Min(timeoutMs, 10000))) return ClamdScanResult.ErrorResult("clamd no responde");
                    client.EndConnect(ar);

                    using (NetworkStream stream = client.GetStream())
                    {
                        stream.ReadTimeout = timeoutMs;
                        stream.WriteTimeout = timeoutMs;
                        byte[] command = Encoding.ASCII.GetBytes("zINSTREAM\0");
                        stream.Write(command, 0, command.Length);

                        using (FileStream file = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                            FileShare.ReadWrite | FileShare.Delete))
                        {
                            byte[] buffer = new byte[32768];
                            byte[] length = new byte[4];
                            int read;
                            while ((read = file.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                length[0] = (byte)((read >> 24) & 0xff);
                                length[1] = (byte)((read >> 16) & 0xff);
                                length[2] = (byte)((read >> 8) & 0xff);
                                length[3] = (byte)(read & 0xff);
                                stream.Write(length, 0, 4);
                                stream.Write(buffer, 0, read);
                            }
                        }
                        stream.Write(new byte[4], 0, 4);
                        stream.Flush();

                        MemoryStream response = new MemoryStream();
                        byte[] reply = new byte[1024];
                        int total = 0;
                        while (total < 64 * 1024)
                        {
                            int read;
                            try { read = stream.Read(reply, 0, reply.Length); }
                            catch (IOException) { break; }
                            if (read <= 0) break;
                            response.Write(reply, 0, read);
                            total += read;
                            bool terminated = false;
                            for (int i = 0; i < read; i++)
                            {
                                if (reply[i] == 0) { terminated = true; break; }
                            }
                            if (terminated) break;
                        }
                        string text = Encoding.UTF8.GetString(response.ToArray()).Replace("\0", string.Empty).Trim();
                        ClamdScanResult result = new ClamdScanResult();
                        result.Raw = text;
                        int found = text.LastIndexOf(" FOUND", StringComparison.OrdinalIgnoreCase);
                        if (found >= 0)
                        {
                            result.Infected = true;
                            int colon = text.LastIndexOf(':', found);
                            if (colon >= 0) result.Signature = text.Substring(colon + 1, found - colon - 1).Trim();
                            else result.Signature = text.Substring(0, found).Trim();
                            return result;
                        }
                        if (text.EndsWith("OK", StringComparison.OrdinalIgnoreCase))
                        {
                            result.Clean = true;
                            return result;
                        }
                        result.Error = text.Length == 0 ? "respuesta vacía de clamd" : text;
                        return result;
                    }
                }
            }
            catch (Exception ex)
            {
                return ClamdScanResult.ErrorResult(ex.Message);
            }
        }

        public static UpdateResult RunFreshclam(
            AppSettings settings,
            CancellationToken token,
            Action<string> log)
        {
            UpdateResult result = new UpdateResult();
            string dir = AppPaths.FindClamAvDirectory(settings.ClamAvDirectory);
            string freshclam = GetExe(dir, "freshclam.exe");
            if (freshclam == null)
            {
                result.Message = "No se encontró freshclam.exe. Instala ClamAV primero.";
                return result;
            }

            WriteConfigs(settings);

            Mutex mutex = null;
            bool locked = false;
            try
            {
                try
                {
                    mutex = new Mutex(false, @"Global\ClamGuardFreshclam");
                    locked = mutex.WaitOne(0);
                }
                catch
                {
                    locked = true;
                }
                if (!locked)
                {
                    result.Busy = true;
                    result.Message = "Ya hay una actualización de firmas en curso.";
                    return result;
                }

                AppLog.Info("freshclam: iniciando comprobación de firmas.");
                Dictionary<string, string> env = new Dictionary<string, string>();
                env["TMP"] = AppPaths.TempDir;
                env["TEMP"] = AppPaths.TempDir;

                string arguments = "--config-file=" + Cmd.Quote(AppPaths.FreshclamConf);
                ProcessResult proc = Proc.RunStreaming(freshclam, arguments, dir, 45 * 60 * 1000,
                    token, delegate(string line, bool isError)
                    {
                        if (log != null && line != null)
                        {
                            string clean = line.Trim();
                            if (clean.Length > 0 && clean.Length < 500) log(clean);
                        }
                    }, env);

                result.ExitCode = proc.ExitCode;
                result.Output = proc.Output + Environment.NewLine + proc.Error;
                result.Canceled = proc.Canceled;

                if (proc.Canceled)
                {
                    result.Message = "Actualización cancelada.";
                    return result;
                }
                if (proc.TimedOut)
                {
                    result.Message = "La actualización agotó el tiempo de espera.";
                    return result;
                }

                string all = result.Output ?? string.Empty;
                bool updated = all.IndexOf(" updated (version", StringComparison.OrdinalIgnoreCase) >= 0
                    || all.IndexOf("Database updated", StringComparison.OrdinalIgnoreCase) >= 0;
                bool upToDate = all.IndexOf("is up to date", StringComparison.OrdinalIgnoreCase) >= 0;
                bool success = proc.ExitCode == 0 || updated || upToDate;

                result.Success = success;
                result.Updated = updated;
                result.Signatures = GetSignatureInfo(AppPaths.DatabaseDir);

                if (success)
                {
                    if (updated)
                        result.Message = "Firmas actualizadas correctamente.";
                    else if (upToDate)
                        result.Message = "Las firmas ya estaban actualizadas.";
                    else
                        result.Message = "Comprobación de firmas completada.";
                }
                else
                {
                    result.Message = "No se pudieron actualizar las firmas (código " + proc.ExitCode + ").";
                }

                StateStore.Mutate(delegate(AppState state)
                {
                    state.LastUpdateUtc = AppState.ToUtc(DateTime.UtcNow);
                    state.LastUpdateMessage = result.Message;
                    state.LastUpdateOk = result.Success;
                });

                if (result.Success)
                {
                    AppLog.Ok("freshclam: " + result.Message);
                    if (Ping(settings.ClamdPort, 1200))
                    {
                        if (ReloadClamd(settings.ClamdPort, 60000))
                            AppLog.Info("clamd ha recargado la base de firmas.");
                        else
                            AppLog.Warn("clamd no confirmó la recarga de firmas.");
                    }
                }
                else
                {
                    AppLog.Error("freshclam: " + result.Message);
                }
                return result;
            }
            catch (Exception ex)
            {
                result.Message = "Error al ejecutar freshclam: " + ex.Message;
                AppLog.Error(result.Message);
                return result;
            }
            finally
            {
                if (locked && mutex != null)
                {
                    try { mutex.ReleaseMutex(); } catch { }
                }
                if (mutex != null) mutex.Dispose();
            }
        }
    }
}
