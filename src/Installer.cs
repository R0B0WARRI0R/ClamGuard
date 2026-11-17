using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace ClamGuard
{
    public sealed class InstallProgress
    {
        public string Stage = string.Empty;
        public int Percent;
        public bool Indeterminate;
        public long BytesReceived;
        public long BytesTotal;
    }

    public sealed class InstallResult
    {
        public bool Success;
        public bool Canceled;
        public bool SignaturesReady;
        public string Message = string.Empty;
        public string ClamAvDirectory = string.Empty;
    }

    [DataContract]
    public sealed class GitHubRelease
    {
        [DataMember(Name = "tag_name")] public string TagName;
        [DataMember(Name = "assets")] public List<GitHubAsset> Assets;
    }

    [DataContract]
    public sealed class GitHubAsset
    {
        [DataMember(Name = "name")] public string Name;
        [DataMember(Name = "browser_download_url")] public string DownloadUrl;
        [DataMember(Name = "digest")] public string Digest;
        [DataMember(Name = "size")] public long Size;
    }

    public static class ClamInstaller
    {
        private const string ApiUrl = "https://api.github.com/repos/Cisco-Talos/clamav/releases/latest";
        private const string FallbackUrlX64 = "https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.5.4/clamav-1.5.4.win.x64.msi";
        private const string FallbackShaX64 = "a025fa23a4b9d64fce448d5a211afcf30dc26ba6528186e6223d1b945f9d95d6";
        private const long RequiredFreeSpace = 2L * 1024 * 1024 * 1024;

        public static InstallResult Install(
            AppSettings settings,
            IProgress<InstallProgress> progress,
            CancellationToken token,
            Action<LogLevel, string> log)
        {
            InstallResult result = new InstallResult();
            try
            {
                AppPaths.EnsureLayout();
                if (!ResidentService.IsAdministrator())
                {
                    result.Message = "La instalación de ClamAV necesita permisos de administrador. " +
                        "Cierra ClamGuard y vuelve a abrirlo aceptando el aviso de UAC.";
                    return result;
                }

                string existing = AppPaths.FindClamAvDirectory(settings.ClamAvDirectory);
                if (existing != null && AppPaths.IsValidClamAvDir(existing, false))
                {
                    settings.ClamAvDirectory = existing;
                    settings.Save();
                    ClamAv.WriteConfigs(settings);
                    Log(log, LogLevel.Info, "ClamAV ya está instalado en " + existing + ".");
                    result.ClamAvDirectory = existing;
                    result.Success = true;
                    if (!ClamAv.HasDatabase(AppPaths.DatabaseDir))
                    {
                        Report(progress, "Descargando firmas de virus...", 80, true);
                        UpdateResult update = ClamAv.RunFreshclam(settings, token, delegate(string line)
                        {
                            Log(log, LogLevel.Info, "freshclam: " + line);
                        });
                        result.SignaturesReady = ClamAv.HasDatabase(AppPaths.DatabaseDir);
                        result.Message = update.Message;
                        result.Canceled = update.Canceled;
                        if (!result.SignaturesReady)
                            result.Message = "ClamAV está instalado, pero faltan las firmas. " + update.Message;
                    }
                    else
                    {
                        result.SignaturesReady = true;
                        result.Message = "ClamAV ya está instalado.";
                    }
                    Report(progress, "Listo.", 100, false);
                    return result;
                }

                Report(progress, "Consultando la última versión de ClamAV...", 3, true);
                GitHubAsset asset = FindWindowsAsset(log);
                if (asset == null)
                {
                    result.Message = "No se pudo localizar el instalador oficial de ClamAV para este equipo.";
                    return result;
                }

                long free = AppPaths.GetFreeSpace(AppPaths.DownloadsDir);
                if (free > 0 && free < RequiredFreeSpace)
                {
                    result.Message = "No hay espacio libre suficiente (se necesitan unos 2 GB).";
                    return result;
                }

                string fileName = Path.GetFileName(new Uri(asset.DownloadUrl).AbsolutePath);
                if (string.IsNullOrEmpty(fileName)) fileName = "clamav-setup.msi";
                string msiPath = Path.Combine(AppPaths.DownloadsDir, fileName);
                string expectedHash = ParseDigest(asset.Digest);

                bool hashOk = false;
                if (File.Exists(msiPath))
                {
                    Log(log, LogLevel.Info, "Comprobando instalador ya descargado...");
                    hashOk = string.Equals(ComputeSha256(msiPath), expectedHash, StringComparison.OrdinalIgnoreCase);
                    if (!hashOk)
                    {
                        Log(log, LogLevel.Warn, "El instalador descargado no coincide; se descargará de nuevo.");
                        try { File.Delete(msiPath); } catch { }
                    }
                }

                if (!hashOk)
                {
                    if (token.IsCancellationRequested) { result.Canceled = true; return result; }
                    Log(log, LogLevel.Info, "Descargando ClamAV desde GitHub: " + asset.DownloadUrl);
                    Report(progress, "Descargando el motor ClamAV (unos 220 MB)...", 5, false);
                    string part = msiPath + ".part";
                    try { if (File.Exists(part)) File.Delete(part); } catch { }
                    Download(asset.DownloadUrl, part, asset.Size, token, delegate(long received, long total)
                    {
                        int percent = 5;
                        if (total > 0) percent = 5 + (int)(received * 50 / total);
                        Report(progress, "Descargando el motor ClamAV...", Math.Min(percent, 55), false, received, total);
                    });
                    File.Move(part, msiPath);
                }

                if (token.IsCancellationRequested) { result.Canceled = true; return result; }

                Report(progress, "Verificando la integridad del instalador...", 58, true);
                string actualHash = ComputeSha256(msiPath);
                if (!string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase))
                {
                    try { File.Delete(msiPath); } catch { }
                    result.Message = "La verificación SHA-256 del instalador falló. Se descartó el archivo.";
                    AppLog.Error(result.Message);
                    return result;
                }
                Log(log, LogLevel.Ok, "SHA-256 del instalador verificado: " + actualHash);

                Report(progress, "Instalando ClamAV (MSI)...", 65, true);
                Log(log, LogLevel.Info, "Ejecutando el instalador oficial de ClamAV en modo silencioso...");
                string msiArgs = "/i " + Cmd.Quote(msiPath) + " /qn /norestart /l*v " + Cmd.Quote(AppPaths.MsiLog);
                ProcessResult msi = Proc.Run("msiexec.exe", msiArgs, AppPaths.DownloadsDir, 20 * 60 * 1000, CancellationToken.None);
                if (msi.ExitCode != 0 && msi.ExitCode != 3010 && msi.ExitCode != 1641)
                {
                    result.Message = "El instalador de ClamAV falló (código " + msi.ExitCode + "). Revisa " + AppPaths.MsiLog;
                    AppLog.Error(result.Message);
                    Log(log, LogLevel.Error, msi.Error);
                    return result;
                }

                string installed = AppPaths.FindClamAvDirectory(null);
                if (installed == null)
                {
                    result.Message = "El instalador terminó, pero no se encontró clamscan.exe. Revisa " + AppPaths.MsiLog;
                    return result;
                }

                settings.ClamAvDirectory = installed;
                settings.Save();
                ClamAv.WriteConfigs(settings);
                result.ClamAvDirectory = installed;
                Log(log, LogLevel.Ok, "ClamAV instalado en " + installed + ".");
                Report(progress, "Descargando firmas de virus (varios minutos)...", 78, true);

                UpdateResult updateResult = ClamAv.RunFreshclam(settings, token, delegate(string line)
                {
                    Log(log, LogLevel.Info, "freshclam: " + line);
                });
                result.SignaturesReady = ClamAv.HasDatabase(AppPaths.DatabaseDir);
                result.Canceled = updateResult.Canceled && !result.SignaturesReady;
                result.Success = true;
                if (result.SignaturesReady)
                {
                    result.Message = "ClamAV y las firmas están listos.";
                    Report(progress, "Instalación completada.", 100, false);
                }
                else
                {
                    result.Message = "ClamAV instalado, pero las firmas aún no están disponibles. " + updateResult.Message;
                    Report(progress, "Instalación completada con avisos.", 100, false);
                }
                return result;
            }
            catch (OperationCanceledException)
            {
                result.Canceled = true;
                result.Message = "Instalación cancelada.";
                return result;
            }
            catch (Exception ex)
            {
                result.Message = "Error durante la instalación: " + ex.Message;
                AppLog.Error(result.Message);
                return result;
            }
        }

        private static GitHubAsset FindWindowsAsset(Action<LogLevel, string> log)
        {
            bool arm64 = IsArm64();
            string suffix = arm64 ? ".win.arm64.msi" : ".win.x64.msi";
            try
            {
                string json = HttpGet(ApiUrl);
                DataContractJsonSerializer ser = new DataContractJsonSerializer(typeof(GitHubRelease));
                using (MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(json)))
                {
                    GitHubRelease release = (GitHubRelease)ser.ReadObject(ms);
                    if (release != null && release.Assets != null)
                    {
                        for (int i = 0; i < release.Assets.Count; i++)
                        {
                            GitHubAsset asset = release.Assets[i];
                            if (asset.Name != null && asset.Name.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                            {
                                Log(log, LogLevel.Info, "Última versión oficial: " + release.TagName);
                                if (!string.IsNullOrEmpty(asset.Digest)) return asset;
                                Log(log, LogLevel.Warn, "GitHub no publicó un hash para el instalador.");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log(log, LogLevel.Warn, "No se pudo consultar GitHub: " + ex.Message);
            }

            if (arm64)
            {
                Log(log, LogLevel.Error, "No se pudo obtener un instalador ARM64 verificado.");
                return null;
            }

            Log(log, LogLevel.Info, "Se usará el instalador de referencia ClamAV 1.5.4 (x64).");
            GitHubAsset fallback = new GitHubAsset();
            fallback.Name = "clamav-1.5.4.win.x64.msi";
            fallback.DownloadUrl = FallbackUrlX64;
            fallback.Digest = "sha256:" + FallbackShaX64;
            fallback.Size = 224457050;
            return fallback;
        }

        private static bool IsArm64()
        {
            string arch = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITEW6432");
            if (string.IsNullOrEmpty(arch)) arch = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
            return arch != null && arch.IndexOf("ARM64", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static string HttpGet(string url)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            using (WebClient client = new WebClient())
            {
                client.Headers.Add("User-Agent", "ClamGuard/" + AppPaths.ProductVersion);
                client.Headers.Add("Accept", "application/vnd.github+json");
                client.Encoding = Encoding.UTF8;
                return client.DownloadString(url);
            }
        }

        private static void Download(string url, string destination, long expectedSize,
            CancellationToken token, Action<long, long> onProgress)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.UserAgent = "ClamGuard/" + AppPaths.ProductVersion;
            request.AllowAutoRedirect = true;
            request.Timeout = 30000;
            request.ReadWriteTimeout = 60000;
            using (WebResponse response = request.GetResponse())
            using (Stream input = response.GetResponseStream())
            using (FileStream output = new FileStream(destination, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                long total = response.ContentLength;
                if (total <= 0) total = expectedSize;
                byte[] buffer = new byte[131072];
                long received = 0;
                DateTime last = DateTime.MinValue;
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    token.ThrowIfCancellationRequested();
                    output.Write(buffer, 0, read);
                    received += read;
                    if (onProgress != null && (DateTime.UtcNow - last).TotalMilliseconds > 300)
                    {
                        last = DateTime.UtcNow;
                        onProgress(received, total);
                    }
                }
                output.Flush();
                if (onProgress != null) onProgress(received, total);
            }
        }

        private static string ParseDigest(string digest)
        {
            if (string.IsNullOrEmpty(digest)) return string.Empty;
            int colon = digest.IndexOf(':');
            return colon >= 0 ? digest.Substring(colon + 1).Trim() : digest.Trim();
        }

        public static string ComputeSha256(string path)
        {
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(fs);
                StringBuilder sb = new StringBuilder(hash.Length * 2);
                for (int i = 0; i < hash.Length; i++) sb.Append(hash[i].ToString("x2"));
                return sb.ToString();
            }
        }

        private static void Report(IProgress<InstallProgress> progress, string stage, int percent, bool indeterminate)
        {
            Report(progress, stage, percent, indeterminate, 0, 0);
        }

        private static void Report(IProgress<InstallProgress> progress, string stage, int percent,
            bool indeterminate, long received, long total)
        {
            if (progress == null) return;
            InstallProgress value = new InstallProgress();
            value.Stage = stage;
            value.Percent = percent;
            value.Indeterminate = indeterminate;
            value.BytesReceived = received;
            value.BytesTotal = total;
            try { progress.Report(value); } catch { }
        }

        private static void Log(Action<LogLevel, string> log, LogLevel level, string message)
        {
            if (log != null) log(level, message);
        }
    }
}
