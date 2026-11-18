using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Security.Cryptography;

namespace ClamGuard
{
    public sealed class IocIndicator
    {
        public string Type = string.Empty;
        public string Value = string.Empty;
        public string Source = string.Empty;
    }

    public sealed class IocMatch
    {
        public string Type = string.Empty;
        public string Indicator = string.Empty;
        public string Location = string.Empty;
        public string Source = string.Empty;
    }

    public sealed class IocProgress
    {
        public string Stage = string.Empty;
        public int Percent;
        public bool Indeterminate;
        public long Current;
        public long Total;
        public string CurrentItem = string.Empty;
    }

    public static class IocStore
    {
        private static readonly Regex PatternRegex =
            new Regex("\"pattern\"\\s*:\\s*\"([^\"]+)\"", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        private static readonly Regex ConditionRegex =
            new Regex("\\[\\s*([^\\]]+?)\\s*\\]", RegexOptions.Compiled);
        private static readonly Regex CompareRegex =
            new Regex("^\\s*([^:]+):(.+?)\\s*=\\s*'([^']*)'\\s*$", RegexOptions.Compiled);

        public static string IocDir
        {
            get { return Path.Combine(AppPaths.DataDir, "iocs"); }
        }

        public static void EnsureLayout()
        {
            try { AppPaths.EnsureLayout(); } catch { }
            try { if (!Directory.Exists(IocDir)) Directory.CreateDirectory(IocDir); } catch { }
        }

        public static int LocalIndicatorCount()
        {
            int n = 0;
            try
            {
                List<IocIndicator> list = LoadAll();
                n = list.Count;
            }
            catch { }
            return n;
        }

        public static List<IocIndicator> LoadAll()
        {
            List<IocIndicator> result = new List<IocIndicator>();
            EnsureLayout();
            try
            {
                string[] files = Directory.GetFiles(IocDir, "*.stix2");
                for (int i = 0; i < files.Length; i++)
                {
                    try
                    {
                        string json = File.ReadAllText(files[i], Encoding.UTF8);
                        string source = Path.GetFileName(files[i]);
                        List<IocIndicator> parsed = ParseStix2(json, source);
                        result.AddRange(parsed);
                    }
                    catch { }
                }
                string[] jsonFiles = Directory.GetFiles(IocDir, "*.json");
                for (int i = 0; i < jsonFiles.Length; i++)
                {
                    try
                    {
                        string json = File.ReadAllText(jsonFiles[i], Encoding.UTF8);
                        string source = Path.GetFileName(jsonFiles[i]);
                        List<IocIndicator> parsed = ParseStix2(json, source);
                        result.AddRange(parsed);
                    }
                    catch { }
                }
            }
            catch { }
            return result;
        }

        public static List<IocIndicator> ParseStix2(string json, string source)
        {
            List<IocIndicator> result = new List<IocIndicator>();
            if (string.IsNullOrEmpty(json)) return result;

            MatchCollection matches = PatternRegex.Matches(json);
            for (int i = 0; i < matches.Count; i++)
            {
                string pattern = matches[i].Groups[1].Value;
                MatchCollection conds = ConditionRegex.Matches(pattern);
                for (int j = 0; j < conds.Count; j++)
                {
                    string cond = conds[j].Groups[1].Value.Trim();
                    Match m = CompareRegex.Match(cond);
                    if (!m.Success) continue;

                    string left = m.Groups[1].Value.Trim().ToLowerInvariant();
                    string mid = m.Groups[2].Value.Trim().ToLowerInvariant();
                    string value = m.Groups[3].Value;

                    string type = left + ":" + mid;
                    if (type.IndexOf("hashes") >= 0)
                    {
                        type = left + ":hashes." + mid.Replace("'", "").Replace("\"", "").Trim();
                    }

                    if (string.IsNullOrEmpty(value)) continue;
                    IocIndicator ind = new IocIndicator();
                    ind.Type = type;
                    ind.Value = value;
                    ind.Source = source ?? string.Empty;
                    result.Add(ind);
                }
            }
            return result;
        }

        public static List<string> ResolveDownloadUrls()
        {
            List<string> urls = new List<string>();
            try
            {
                using (WebClient wc = new WebClient())
                {
                    wc.Encoding = Encoding.UTF8;
                    string yaml = wc.DownloadString("https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml");
                    Regex blockRegex = new Regex("github:\\s*\\n\\s*owner:\\s*(\\S+)\\s*\\n\\s*repo:\\s*(\\S+)\\s*\\n\\s*branch:\\s*(\\S+)\\s*\\n\\s*path:\\s*(\\S+)", RegexOptions.Compiled);
                    MatchCollection mc = blockRegex.Matches(yaml);
                    for (int i = 0; i < mc.Count; i++)
                    {
                        string owner = mc[i].Groups[1].Value.Trim();
                        string repo = mc[i].Groups[2].Value.Trim();
                        string branch = mc[i].Groups[3].Value.Trim();
                        string path = mc[i].Groups[4].Value.Trim();
                        string url = "https://raw.githubusercontent.com/" + owner + "/" + repo + "/" + branch + "/" + path;
                        if (!urls.Contains(url)) urls.Add(url);
                    }
                }
            }
            catch { }

            string[] extra = new string[]
            {
                "https://raw.githubusercontent.com/Te-k/stalkerware-indicators/master/generated/stalkerware.stix2"
            };
            for (int i = 0; i < extra.Length; i++)
                if (!urls.Contains(extra[i])) urls.Add(extra[i]);

            return urls;
        }

        public static int DownloadAll(IProgress<IocProgress> progress, CancellationToken token, Action<LogLevel, string> log)
        {
            EnsureLayout();
            List<string> urls = ResolveDownloadUrls();
            int downloaded = 0;
            int total = urls.Count;
            for (int i = 0; i < urls.Count; i++)
            {
                if (token.IsCancellationRequested) break;
                Report(progress, "Descargando IOCs (" + (i + 1) + "/" + total + ")...", (int)((double)i / Math.Max(1, total) * 100), true);
                try
                {
                    string url = urls[i];
                    string fileName = Path.GetFileName(new Uri(url).AbsolutePath);
                    if (string.IsNullOrEmpty(fileName)) fileName = "ioc_" + i + ".stix2";
                    if (!fileName.EndsWith(".stix2", StringComparison.OrdinalIgnoreCase) &&
                        !fileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                        fileName += ".stix2";

                    string dest = Path.Combine(IocDir, fileName);
                    if (File.Exists(dest))
                    {
                        try { File.Delete(dest); } catch { }
                    }

                    using (WebClient wc = new WebClient())
                    {
                        wc.DownloadFile(url, dest);
                    }
                    downloaded++;
                    Emit(log, LogLevel.Ok, "IOC descargado: " + fileName);
                }
                catch (Exception ex)
                {
                    Emit(log, LogLevel.Warn, "No se pudo descargar " + urls[i] + ": " + ex.Message);
                }
            }
            Report(progress, "Descarga de IOCs completada.", 100, false);
            return downloaded;
        }

        public static List<IocMatch> Search(
            IProgress<IocProgress> progress,
            CancellationToken token,
            Action<LogLevel, string> log,
            IEnumerable<string> scanPaths)
        {
            List<IocMatch> matches = new List<IocMatch>();
            List<IocIndicator> indicators = LoadAll();
            if (indicators.Count == 0)
            {
                Emit(log, LogLevel.Warn, "No hay IOCs descargados. Actualiza primero la base.");
                return matches;
            }

            Dictionary<string, List<string>> byType = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < indicators.Count; i++)
            {
                IocIndicator ind = indicators[i];
                string key = ind.Type.ToLowerInvariant();
                if (!byType.ContainsKey(key)) byType[key] = new List<string>();
                if (!byType[key].Contains(ind.Value)) byType[key].Add(ind.Value);
            }

            int step = 0;

            step++;
            Report(progress, "Analizando procesos en ejecucion...", step * 25, true);
            try
            {
                Process[] procs = Process.GetProcesses();
                for (int i = 0; i < procs.Length; i++)
                {
                    if (token.IsCancellationRequested) break;
                    Process p = procs[i];
                    try
                    {
                        string name = p.ProcessName;
                        Report(progress, "Analizando procesos en ejecucion...", 25, true, name + " (PID " + p.Id + ")");
                        CheckIndicator(matches, byType, "process:name", name, "Proceso: " + name + " (PID " + p.Id + ")", indicators);
                        try
                        {
                            string path = p.MainModule.FileName;
                            CheckIndicator(matches, byType, "file:path", path, "Proceso: " + name + " -> " + path, indicators);
                            if (File.Exists(path))
                            {
                                string hash = ComputeHash(path, "sha256");
                                if (!string.IsNullOrEmpty(hash))
                                    CheckIndicator(matches, byType, "file:hashes.sha256", hash, "Proceso: " + name + " -> " + path, indicators);
                            }
                        }
                        catch { }
                    }
                    catch { }
                    finally { try { p.Dispose(); } catch { } }
                }
            }
            catch (Exception ex) { Emit(log, LogLevel.Warn, "Error analizando procesos: " + ex.Message); }

            step++;
            Report(progress, "Analizando archivos...", step * 25, true);
            List<string> paths = new List<string>();
            if (scanPaths != null)
            {
                foreach (string p in scanPaths)
                    if (!string.IsNullOrEmpty(p)) paths.Add(p);
            }
            if (paths.Count == 0)
            {
                paths.Add(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
                paths.Add(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
                paths.Add(Path.GetTempPath());
                string startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                if (!string.IsNullOrEmpty(startup)) paths.Add(startup);
            }

            foreach (string root in paths)
            {
                if (token.IsCancellationRequested) break;
                if (string.IsNullOrEmpty(root) || !Directory.Exists(root)) continue;
                try
                {
                    IEnumerable<string> files = SafeEnumerateFiles(root);
                    foreach (string file in files)
                    {
                        if (token.IsCancellationRequested) break;
                        try
                        {
                            Report(progress, "Analizando archivos...", 50, true, file);
                            string name = Path.GetFileName(file);
                            CheckIndicator(matches, byType, "file:name", name, file, indicators);
                            CheckIndicator(matches, byType, "file:path", file, file, indicators);

                            try
                            {
                                FileInfo fi = new FileInfo(file);
                                if (fi.Length <= 25 * 1024 * 1024)
                                {
                                    string sha256 = ComputeHash(file, "sha256");
                                    if (!string.IsNullOrEmpty(sha256))
                                        CheckIndicator(matches, byType, "file:hashes.sha256", sha256, file, indicators);
                                    string md5 = ComputeHash(file, "md5");
                                    if (!string.IsNullOrEmpty(md5))
                                        CheckIndicator(matches, byType, "file:hashes.md5", md5, file, indicators);
                                    string sha1 = ComputeHash(file, "sha1");
                                    if (!string.IsNullOrEmpty(sha1))
                                        CheckIndicator(matches, byType, "file:hashes.sha1", sha1, file, indicators);
                                }
                            }
                            catch { }
                        }
                        catch { }
                    }
                }
                catch (Exception ex) { Emit(log, LogLevel.Warn, "Error analizando " + root + ": " + ex.Message); }
            }

            step++;
            Report(progress, "Analizando dominios y DNS...", step * 25, true);
            try
            {
                string hosts = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
                if (File.Exists(hosts))
                {
                    string content = File.ReadAllText(hosts);
                    foreach (KeyValuePair<string, List<string>> kv in byType)
                    {
                        if (kv.Key == "domain-name:value" || kv.Key == "url:value")
                        {
                            for (int i = 0; i < kv.Value.Count; i++)
                            {
                                if (content.IndexOf(kv.Value[i], StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    IocMatch m = new IocMatch();
                                    m.Type = kv.Key;
                                    m.Indicator = kv.Value[i];
                                    m.Location = hosts;
                                    m.Source = FindSource(indicators, kv.Key, kv.Value[i]);
                                    matches.Add(m);
                                }
                            }
                        }
                    }
                }
            }
            catch { }

            try
            {
                ProcessResult r = Proc.Run("ipconfig.exe", "/displaydns", null, 30000, token);
                if (!string.IsNullOrEmpty(r.Output))
                {
                    foreach (KeyValuePair<string, List<string>> kv in byType)
                    {
                        if (kv.Key == "domain-name:value" || kv.Key == "url:value")
                        {
                            for (int i = 0; i < kv.Value.Count; i++)
                            {
                                if (r.Output.IndexOf(kv.Value[i], StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    IocMatch m = new IocMatch();
                                    m.Type = kv.Key;
                                    m.Indicator = kv.Value[i];
                                    m.Location = "Cache DNS";
                                    m.Source = FindSource(indicators, kv.Key, kv.Value[i]);
                                    matches.Add(m);
                                }
                            }
                        }
                    }
                }
            }
            catch { }

            step++;
            Report(progress, "Analizando el registro de Windows...", step * 25, true);
            try
            {
                string[] regPaths = new string[]
                {
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                    @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
                };
                for (int r = 0; r < regPaths.Length; r++)
                {
                    try
                    {
                        using (Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(regPaths[r]))
                        {
                            if (key == null) continue;
                            string[] names = key.GetValueNames();
                            for (int n = 0; n < names.Length; n++)
                            {
                                string val = key.GetValue(names[n]) as string;
                                if (string.IsNullOrEmpty(val)) continue;
                                foreach (KeyValuePair<string, List<string>> kv in byType)
                                {
                                    for (int i = 0; i < kv.Value.Count; i++)
                                    {
                                        if (val.IndexOf(kv.Value[i], StringComparison.OrdinalIgnoreCase) >= 0 ||
                                            names[n].IndexOf(kv.Value[i], StringComparison.OrdinalIgnoreCase) >= 0)
                                        {
                                            IocMatch m = new IocMatch();
                                            m.Type = kv.Key;
                                            m.Indicator = kv.Value[i];
                                            m.Location = "Registro: " + regPaths[r] + " -> " + names[n];
                                            m.Source = FindSource(indicators, kv.Key, kv.Value[i]);
                                            matches.Add(m);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }

            Report(progress, "Busqueda de IOCs completada.", 100, false);
            Emit(log, LogLevel.Info, "Busqueda de IOCs finalizada: " + matches.Count + " coincidencia(s).");
            return matches;
        }

        private static void CheckIndicator(List<IocMatch> matches, Dictionary<string, List<string>> byType, string type, string value, string location, List<IocIndicator> indicators)
        {
            if (string.IsNullOrEmpty(value)) return;
            if (!byType.ContainsKey(type)) return;
            List<string> list = byType[type];
            for (int i = 0; i < list.Count; i++)
            {
                string ind = list[i];
                bool hit = false;
                if (type.IndexOf("hashes") >= 0)
                {
                    hit = string.Equals(ind, value, StringComparison.OrdinalIgnoreCase);
                }
                else
                {
                    hit = value.IndexOf(ind, StringComparison.OrdinalIgnoreCase) >= 0 ||
                          string.Equals(value, ind, StringComparison.OrdinalIgnoreCase);
                }
                if (hit)
                {
                    IocMatch m = new IocMatch();
                    m.Type = type;
                    m.Indicator = ind;
                    m.Location = location;
                    m.Source = FindSource(indicators, type, ind);
                    matches.Add(m);
                }
            }
        }

        private static string FindSource(List<IocIndicator> indicators, string type, string value)
        {
            for (int i = 0; i < indicators.Count; i++)
            {
                if (string.Equals(indicators[i].Type, type, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(indicators[i].Value, value, StringComparison.OrdinalIgnoreCase))
                    return indicators[i].Source;
            }
            return string.Empty;
        }

        private static IEnumerable<string> SafeEnumerateFiles(string root)
        {
            List<string> result = new List<string>();
            try
            {
                Stack<string> dirs = new Stack<string>();
                dirs.Push(root);
                while (dirs.Count > 0)
                {
                    string current = dirs.Pop();
                    try
                    {
                        string[] files = Directory.GetFiles(current);
                        for (int i = 0; i < files.Length; i++) result.Add(files[i]);
                    }
                    catch { }
                    try
                    {
                        string[] sub = Directory.GetDirectories(current);
                        for (int i = 0; i < sub.Length; i++)
                        {
                            try
                            {
                                FileAttributes attrs = File.GetAttributes(sub[i]);
                                if ((attrs & FileAttributes.ReparsePoint) == 0)
                                    dirs.Push(sub[i]);
                            }
                            catch { }
                        }
                    }
                    catch { }
                }
            }
            catch { }
            return result;
        }

        private static string ComputeHash(string path, string algo)
        {
            try
            {
                using (FileStream fs = File.OpenRead(path))
                {
                    byte[] hash;
                    if (algo == "md5")
                    {
                        using (MD5 md5 = MD5.Create()) hash = md5.ComputeHash(fs);
                    }
                    else if (algo == "sha1")
                    {
                        using (SHA1 sha1 = SHA1.Create()) hash = sha1.ComputeHash(fs);
                    }
                    else
                    {
                        using (SHA256 sha256 = SHA256.Create()) hash = sha256.ComputeHash(fs);
                    }
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < hash.Length; i++) sb.Append(hash[i].ToString("x2"));
                    return sb.ToString();
                }
            }
            catch { return null; }
        }

        private static void Report(IProgress<IocProgress> progress, string stage, int percent, bool indeterminate)
        {
            Report(progress, stage, percent, indeterminate, string.Empty);
        }

        private static void Report(IProgress<IocProgress> progress, string stage, int percent, bool indeterminate, string currentItem)
        {
            if (progress == null) return;
            IocProgress p = new IocProgress();
            p.Stage = stage;
            p.Percent = percent;
            p.Indeterminate = indeterminate;
            p.CurrentItem = currentItem ?? string.Empty;
            try { progress.Report(p); } catch { }
        }

        private static void Emit(Action<LogLevel, string> log, LogLevel level, string message)
        {
            try
            {
                if (log != null) log(level, message);
                else AppLog.Write(level, message);
            }
            catch { }
        }
    }
}
