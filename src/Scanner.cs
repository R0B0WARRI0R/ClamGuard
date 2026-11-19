using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace ClamGuard
{
    public sealed class ScanThreat
    {
        public string Path = string.Empty;
        public string Signature = string.Empty;
    }

    public sealed class ScanProgress
    {
        public string Phase = string.Empty;
        public long Files;
        public long TotalFiles;
        public int Percent;
        public int Threats;
        public string CurrentFile = string.Empty;
        public string Engine = string.Empty;
    }

    public sealed class ScanResult
    {
        public bool Canceled;
        public bool Failed;
        public string Error = string.Empty;
        public string Engine = string.Empty;
        public long FilesScanned;
        public long TotalFiles;
        public long SkippedFiles;
        public long DirectoriesScanned;
        public int Errors;
        public readonly List<ScanThreat> Threats = new List<ScanThreat>();
        public TimeSpan Duration;

        public bool HasThreats { get { return Threats.Count > 0; } }
    }

    public static class Scanner
    {
        private const long MaxFileBytes = 200L * 1024 * 1024;

        public static ScanResult Scan(
            AppSettings settings,
            IList<string> targets,
            CancellationToken token,
            IProgress<ScanProgress> progress,
            Action<LogLevel, string> log)
        {
            ScanResult result = new ScanResult();
            Stopwatch watch = Stopwatch.StartNew();
            string listPath = null;
            try
            {
                if (settings == null) settings = AppSettings.Load();
                string dir = AppPaths.FindClamAvDirectory(settings.ClamAvDirectory);
                if (dir == null)
                {
                    result.Failed = true;
                    result.Error = "ClamAV no está instalado.";
                    return result;
                }

                List<string> validTargets = NormalizeTargets(targets);
                if (validTargets.Count == 0)
                {
                    result.Failed = true;
                    result.Error = "No hay rutas válidas para analizar.";
                    return result;
                }

                if (log != null)
                {
                    log(LogLevel.Info, string.Format("Preparando análisis de {0} ruta(s)...", validTargets.Count));
                }

                FileListResult list = BuildFileList(validTargets, token, progress, log);
                listPath = list.Path;
                result.TotalFiles = list.Total;
                result.SkippedFiles = list.Skipped;

                if (list.Canceled || token.IsCancellationRequested)
                {
                    result.Canceled = true;
                    result.Error = "Análisis cancelado.";
                    if (log != null) log(LogLevel.Warn, result.Error);
                    return result;
                }
                if (list.Total == 0)
                {
                    result.Failed = true;
                    result.Error = "No se encontraron archivos que analizar en las rutas seleccionadas.";
                    if (log != null) log(LogLevel.Warn, result.Error);
                    return result;
                }

                if (log != null)
                {
                    if (list.Skipped > 0)
                        log(LogLevel.Info, string.Format("{0} archivo(s) preparados; {1} omitido(s) por tamaño o acceso.",
                            list.Total, list.Skipped));
                    else
                        log(LogLevel.Info, string.Format("{0} archivo(s) preparados para el análisis.", list.Total));
                }

                bool useDaemon = ClamAv.Ping(settings.ClamdPort, 900) &&
                    File.Exists(Path.Combine(dir, "clamdscan.exe"));

                if (useDaemon)
                {
                    ScanResult daemonResult = RunEngine(settings, dir, true, listPath, list.Total,
                        token, progress, log);
                    if (!daemonResult.Canceled && !daemonResult.Failed &&
                        daemonResult.FilesScanned == 0 && daemonResult.Threats.Count == 0)
                    {
                        if (log != null)
                            log(LogLevel.Warn, "El motor residente no respondió; se usará el análisis local (clamscan).");
                        useDaemon = false;
                    }
                    else
                    {
                        result = daemonResult;
                        result.SkippedFiles = list.Skipped;
                        result.Duration = watch.Elapsed;
                        return result;
                    }
                }

                if (!File.Exists(Path.Combine(dir, "clamscan.exe")))
                {
                    result.Failed = true;
                    result.Error = "No se encontró clamscan.exe. Reinstala ClamAV.";
                    return result;
                }

                result = RunEngine(settings, dir, false, listPath, list.Total, token, progress, log);
                result.SkippedFiles = list.Skipped;
                result.Duration = watch.Elapsed;
                return result;
            }
            catch (Exception ex)
            {
                result.Failed = true;
                result.Error = "Error inesperado durante el análisis: " + ex.Message;
                AppLog.Error(result.Error);
                if (log != null) log(LogLevel.Error, result.Error);
                return result;
            }
            finally
            {
                if (listPath != null)
                {
                    try { if (File.Exists(listPath)) File.Delete(listPath); } catch { }
                }
            }
        }

        private static ScanResult RunEngine(
            AppSettings settings,
            string dir,
            bool useDaemon,
            string listPath,
            long totalFiles,
            CancellationToken token,
            IProgress<ScanProgress> progress,
            Action<LogLevel, string> log)
        {
            ScanResult result = new ScanResult();
            Stopwatch watch = Stopwatch.StartNew();
            StringBuilder arguments = new StringBuilder();
            string exe;
            string engine;

            if (useDaemon)
            {
                exe = Path.Combine(dir, "clamdscan.exe");
                engine = "clamd";
                arguments.Append("--config-file=").Append(Cmd.Quote(AppPaths.ClamdConf));
                arguments.Append(" --stdout --multiscan --file-list=").Append(Cmd.Quote(listPath));
            }
            else
            {
                exe = Path.Combine(dir, "clamscan.exe");
                engine = "clamscan";
                arguments.Append("--stdout --database=").Append(Cmd.Quote(AppPaths.DatabaseDir));
                arguments.Append(" --max-filesize=").Append(settings.MaxScanFileSizeMB).Append("M --max-scansize=").Append(settings.MaxScanFileSizeMB * 2).Append("M --max-recursion=12");
                arguments.Append(" --file-list=").Append(Cmd.Quote(listPath));
            }

            result.Engine = engine;
            if (log != null)
            {
                log(LogLevel.Info, string.Format("Iniciando análisis con {0} ({1} archivo(s))...",
                    useDaemon ? "el motor residente clamd" : "el motor local clamscan", totalFiles));
            }

            ScanState state = new ScanState(result, progress, log, engine, totalFiles);
            state.ReportProgress();
            Dictionary<string, string> env = new Dictionary<string, string>();
            env["TMP"] = AppPaths.TempDir;
            env["TEMP"] = AppPaths.TempDir;

            ProcessResult proc = Proc.RunStreaming(exe, arguments.ToString(), dir, 0, token,
                state.HandleLine, env);
            state.Complete(proc, watch.Elapsed);

            result.Canceled = proc.Canceled;
            result.Duration = watch.Elapsed;

            if (result.Canceled)
            {
                result.Error = "Análisis cancelado.";
                if (log != null) log(LogLevel.Warn, result.Error);
            }
            else if (proc.TimedOut)
            {
                result.Failed = true;
                result.Error = "El análisis agotó el tiempo máximo.";
                if (log != null) log(LogLevel.Error, result.Error);
            }
            else if (proc.ExitCode != 0 && proc.ExitCode != 1)
            {
                if (result.FilesScanned == 0 && result.Threats.Count == 0)
                {
                    result.Failed = true;
                    result.Error = "El motor devolvió un error (código " + proc.ExitCode + "). Revisa el registro.";
                    if (log != null) log(LogLevel.Error, result.Error);
                }
                else if (log != null)
                {
                    log(LogLevel.Warn, "El motor terminó con avisos (código " + proc.ExitCode + ").");
                }
            }

            if (log != null && !result.Failed && !result.Canceled)
            {
                if (result.Threats.Count > 0)
                {
                    log(LogLevel.Warn, string.Format("Análisis finalizado: {0} de {1} archivo(s), {2} amenaza(s), {3} error(es).",
                        result.FilesScanned, totalFiles, result.Threats.Count, result.Errors));
                }
                else
                {
                    log(LogLevel.Ok, string.Format("Análisis finalizado sin amenazas: {0} archivo(s) en {1:0.0} s.",
                        result.FilesScanned, result.Duration.TotalSeconds));
                }
            }
            return result;
        }

        private static List<string> NormalizeTargets(IList<string> targets)
        {
            List<string> valid = new List<string>();
            if (targets == null) return valid;
            for (int i = 0; i < targets.Count; i++)
            {
                string target = targets[i];
                if (string.IsNullOrEmpty(target)) continue;
                try
                {
                    string full = Path.GetFullPath(target.Trim().Trim('"')).TrimEnd('\\');
                    if (Directory.Exists(full) && full.Length == 2 && full[1] == ':')
                        full += "\\";
                    if (!Directory.Exists(full) && !File.Exists(full)) continue;
                    if (IsExcluded(full)) continue;
                    if (!AppPaths.ContainsPath(valid, full)) valid.Add(full);
                }
                catch
                {
                }
            }
            return valid;
        }

        private sealed class FileListResult
        {
            public string Path;
            public long Total;
            public long Skipped;
            public bool Canceled;
        }

        /// <summary>
        /// Recorre las rutas y genera una lista UTF-8 con un archivo por línea.
        /// El listado permite a ClamAV informar del resultado de cada archivo y
        /// calcular un porcentaje real de avance.
        /// </summary>
        private static FileListResult BuildFileList(
            IList<string> targets,
            CancellationToken token,
            IProgress<ScanProgress> progress,
            Action<LogLevel, string> log)
        {
            FileListResult result = new FileListResult();
            AppPaths.EnsureLayout();
            result.Path = Path.Combine(AppPaths.TempDir, "scan-" + Guid.NewGuid().ToString("N") + ".txt");

            long count = 0;
            long skipped = 0;
            Stopwatch watch = Stopwatch.StartNew();
            long lastReport = 0;
            Stack<string> pending = new Stack<string>();

            using (FileStream stream = new FileStream(result.Path, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
            using (StreamWriter writer = new StreamWriter(stream, new UTF8Encoding(false)))
            {
                for (int i = 0; i < targets.Count; i++)
                {
                    string target = targets[i];
                    try
                    {
                        if (File.Exists(target))
                        {
                            FileInfo single = new FileInfo(target);
                            if (ShouldIncludeFile(single))
                            {
                                writer.WriteLine(single.FullName);
                                count++;
                            }
                            else
                            {
                                skipped++;
                            }
                        }
                        else if (Directory.Exists(target))
                        {
                            if (!IsReparsePoint(target)) pending.Push(target);
                        }
                    }
                    catch
                    {
                        skipped++;
                    }
                }

                int visitedDirs = 0;
                while (pending.Count > 0)
                {
                    if (token.IsCancellationRequested)
                    {
                        result.Canceled = true;
                        break;
                    }

                    string current = pending.Pop();
                    visitedDirs++;
                    FileInfo[] files = null;
                    DirectoryInfo[] subdirs = null;
                    try
                    {
                        DirectoryInfo info = new DirectoryInfo(current);
                        files = info.GetFiles();
                        subdirs = info.GetDirectories();
                    }
                    catch
                    {
                        skipped++;
                        continue;
                    }

                    for (int i = 0; i < files.Length; i++)
                    {
                        try
                        {
                            if (ShouldIncludeFile(files[i]))
                            {
                                writer.WriteLine(files[i].FullName);
                                count++;
                            }
                            else
                            {
                                skipped++;
                            }
                        }
                        catch
                        {
                            skipped++;
                        }
                    }

                    for (int i = 0; i < subdirs.Length; i++)
                    {
                        try
                        {
                            if (!IsExcluded(subdirs[i].FullName) && !IsReparsePoint(subdirs[i].FullName))
                                pending.Push(subdirs[i].FullName);
                        }
                        catch
                        {
                        }
                    }

                    if (progress != null && watch.ElapsedMilliseconds - lastReport >= 250)
                    {
                        lastReport = watch.ElapsedMilliseconds;
                        ScanProgress value = new ScanProgress();
                        value.Phase = "Preparando archivos";
                        value.Files = count;
                        value.TotalFiles = 0;
                        value.Percent = 0;
                        value.CurrentFile = current;
                        value.Engine = "preparación";
                        try { progress.Report(value); } catch { }
                    }
                }

                if (!result.Canceled && log != null && visitedDirs > 0)
                {
                    log(LogLevel.Info, string.Format("Se recorrieron {0} carpeta(s).", visitedDirs));
                }
            }

            result.Total = count;
            result.Skipped = skipped;
            return result;
        }

        private static bool ShouldIncludeFile(FileInfo file)
        {
            try
            {
                if (!file.Exists) return false;
                if (IsExcluded(file.FullName)) return false;
                if (file.Length <= 0) return true;
                if (file.Length > MaxFileBytes) return false;
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static bool IsReparsePoint(string path)
        {
            try
            {
                FileAttributes attributes = File.GetAttributes(path);
                return (attributes & FileAttributes.ReparsePoint) == FileAttributes.ReparsePoint;
            }
            catch
            {
                return true;
            }
        }

        private static bool IsExcluded(string path)
        {
            if (string.IsNullOrEmpty(path)) return true;
            if (AppPaths.IsUnder(path, AppPaths.DataDir)) return true;
            if (path.IndexOf(@"\System Volume Information", StringComparison.OrdinalIgnoreCase) >= 0) return true;
            if (path.IndexOf(@"\$Recycle.Bin", StringComparison.OrdinalIgnoreCase) >= 0) return true;
            return false;
        }

        private sealed class ScanState
        {
            private readonly ScanResult _result;
            private readonly IProgress<ScanProgress> _progress;
            private readonly Action<LogLevel, string> _log;
            private readonly string _engine;
            private readonly long _total;
            private readonly object _sync = new object();
            private readonly Stopwatch _progressWatch = Stopwatch.StartNew();
            private long _lastReportMs;
            private long _files;
            private long _directories;
            private int _warningsLogged;
            private string _currentFile = string.Empty;

            public ScanState(ScanResult result, IProgress<ScanProgress> progress,
                Action<LogLevel, string> log, string engine, long total)
            {
                _result = result;
                _progress = progress;
                _log = log;
                _engine = engine;
                _total = total;
            }

            public void HandleLine(string raw, bool isError)
            {
                if (raw == null) return;
                string line = raw.Trim();
                if (line.Length == 0) return;

                bool report = false;
                try
                {
                    lock (_sync)
                    {
                        if (line.EndsWith(" FOUND", StringComparison.OrdinalIgnoreCase))
                        {
                            _files++;
                            int foundIndex = line.Length - 6;
                            int separator = line.LastIndexOf(": ", Math.Max(0, foundIndex - 1), StringComparison.Ordinal);
                            ScanThreat threat = new ScanThreat();
                            if (separator > 0)
                            {
                                threat.Path = line.Substring(0, separator).Trim().Trim('"');
                                threat.Signature = line.Substring(separator + 2,
                                    Math.Max(0, foundIndex - separator - 2)).Trim();
                            }
                            else
                            {
                                threat.Path = line.Substring(0, Math.Max(0, foundIndex)).Trim().Trim('"');
                                threat.Signature = "Desconocido";
                            }
                            _result.Threats.Add(threat);
                            _currentFile = threat.Path;
                            if (_log != null)
                                _log(LogLevel.Threat, "AMENAZA: " + threat.Path + "  [" + threat.Signature + "]");
                        }
                        else if (line.EndsWith(": OK", StringComparison.OrdinalIgnoreCase))
                        {
                            _files++;
                            _currentFile = line.Substring(0, line.Length - 4).Trim().Trim('"');
                        }
                        else if (line.EndsWith(": Empty file", StringComparison.OrdinalIgnoreCase))
                        {
                            _files++;
                            _currentFile = line.Substring(0, line.Length - 13).Trim().Trim('"');
                        }
                        else if (line.StartsWith("Scanned directories:", StringComparison.OrdinalIgnoreCase))
                        {
                            long parsed;
                            if (long.TryParse(ExtractSummary(line), out parsed)) _directories = parsed;
                        }
                        else if (line.StartsWith("Scanned files:", StringComparison.OrdinalIgnoreCase))
                        {
                            long parsed;
                            if (long.TryParse(ExtractSummary(line), out parsed) && parsed > _files) _files = parsed;
                        }
                        else if (line.StartsWith("Infected files:", StringComparison.OrdinalIgnoreCase) ||
                                 line.StartsWith("Known viruses:", StringComparison.OrdinalIgnoreCase) ||
                                 line.StartsWith("Engine version:", StringComparison.OrdinalIgnoreCase) ||
                                 line.StartsWith("Data scanned:", StringComparison.OrdinalIgnoreCase) ||
                                 line.StartsWith("Data read:", StringComparison.OrdinalIgnoreCase) ||
                                 line.StartsWith("Time:", StringComparison.OrdinalIgnoreCase) ||
                                 line.StartsWith("Start Date:", StringComparison.OrdinalIgnoreCase) ||
                                 line.StartsWith("End Date:", StringComparison.OrdinalIgnoreCase) ||
                                 line.IndexOf("LibClamAV", StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                        }
                        else if (line.IndexOf("ERROR", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                 line.IndexOf("WARNING", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                 line.EndsWith("Access denied", StringComparison.OrdinalIgnoreCase) ||
                                 line.EndsWith("Permission denied", StringComparison.OrdinalIgnoreCase))
                        {
                            _result.Errors++;
                            if (_log != null && _warningsLogged < 10)
                            {
                                _log(LogLevel.Warn, line);
                                _warningsLogged++;
                            }
                        }
                        else if (_log != null && _warningsLogged < 3 && line.Length < 300)
                        {
                            _log(LogLevel.Info, line);
                            _warningsLogged++;
                        }

                        if (_progress != null && _progressWatch.ElapsedMilliseconds - _lastReportMs >= 200)
                        {
                            _lastReportMs = _progressWatch.ElapsedMilliseconds;
                            report = true;
                        }
                    }
                }
                catch
                {
                }

                if (report) ReportProgress();
            }

            public void ReportProgress()
            {
                if (_progress == null) return;
                ScanProgress snapshot = new ScanProgress();
                lock (_sync)
                {
                    snapshot.Phase = "Analizando";
                    snapshot.Files = _files;
                    snapshot.TotalFiles = _total;
                    snapshot.Threats = _result.Threats.Count;
                    snapshot.CurrentFile = _currentFile;
                    snapshot.Engine = _engine;
                    snapshot.Percent = _total > 0
                        ? (int)Math.Min(99, _files * 100 / _total)
                        : 0;
                }
                try { _progress.Report(snapshot); } catch { }
            }

            public void Complete(ProcessResult proc, TimeSpan duration)
            {
                ScanProgress snapshot = null;
                lock (_sync)
                {
                    _result.FilesScanned = _files;
                    _result.DirectoriesScanned = _directories;
                    _result.Duration = duration;
                    if (_progress != null)
                    {
                        snapshot = new ScanProgress();
                        snapshot.Phase = proc != null && proc.Canceled ? "Cancelado" : "Completado";
                        snapshot.Files = _files;
                        snapshot.TotalFiles = _total;
                        snapshot.Threats = _result.Threats.Count;
                        snapshot.CurrentFile = _currentFile;
                        snapshot.Engine = _engine;
                        snapshot.Percent = 100;
                    }
                }
                if (snapshot != null)
                {
                    try { _progress.Report(snapshot); } catch { }
                }
            }

            private static string ExtractSummary(string line)
            {
                int colon = line.IndexOf(':');
                return colon >= 0 ? line.Substring(colon + 1).Trim() : line.Trim();
            }
        }

        public static List<string> ExistingQuickTargets(AppSettings settings)
        {
            List<string> result = new List<string>();
            if (settings == null) return result;
            for (int i = 0; i < settings.QuickScanPaths.Count; i++)
            {
                try
                {
                    if (Directory.Exists(settings.QuickScanPaths[i]) || File.Exists(settings.QuickScanPaths[i]))
                    {
                        if (!AppPaths.ContainsPath(result, settings.QuickScanPaths[i]))
                            result.Add(settings.QuickScanPaths[i]);
                    }
                }
                catch
                {
                }
            }
            return result;
        }
    }
}
