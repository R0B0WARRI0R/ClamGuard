using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Threading;

namespace ClamGuard
{
    [DataContract]
    public sealed class AppSettings
    {
        [DataMember(Order = 1)] public string ClamAvDirectory;
        [DataMember(Order = 2)] public List<string> MonitorPaths;
        [DataMember(Order = 3)] public List<string> QuickScanPaths;
        [DataMember(Order = 4)] public int UpdateIntervalHours;
        [DataMember(Order = 5)] public bool ScanRemovableDrives;
        [DataMember(Order = 6)] public bool OnAccessEnabled;
        [DataMember(Order = 7)] public string QuarantineAction;
        [DataMember(Order = 8)] public int ClamdPort;
        [DataMember(Order = 9)] public bool PauseDefender;
        [DataMember(Order = 10)] public int MaxScanFileSizeMB;
        [DataMember(Order = 11)] public string Language;

        public AppSettings()
        {
            PauseDefender = true;
            MaxScanFileSizeMB = 200;
            Language = "es-ES";
            Language = "es-ES";
            Normalize();
        }

        [OnDeserializing]
        private void OnDeserializing(StreamingContext context)
        {
            // Los archivos antiguos no contienen PauseDefender...
            PauseDefender = true;
            MaxScanFileSizeMB = 200;
            Language = "es-ES";
        }

        [OnDeserialized]
        private void OnDeserialized(StreamingContext context)
        {
            Normalize();
        }

        public void Normalize()
        {
            string found = AppPaths.FindClamAvDirectory(ClamAvDirectory);
            if (found != null) ClamAvDirectory = found;
            else if (ClamAvDirectory == null) ClamAvDirectory = string.Empty;

            if (MonitorPaths == null || MonitorPaths.Count == 0)
                MonitorPaths = AppPaths.DefaultMonitoredPaths();
            else
                MonitorPaths = CleanPathList(MonitorPaths);

            if (QuickScanPaths == null || QuickScanPaths.Count == 0)
                QuickScanPaths = AppPaths.DefaultQuickScanPaths();
            else
                QuickScanPaths = CleanPathList(QuickScanPaths);

            if (UpdateIntervalHours < 1) UpdateIntervalHours = 4;
            if (UpdateIntervalHours > 168) UpdateIntervalHours = 168;
            if (ClamdPort < 1024 || ClamdPort > 65535) ClamdPort = AppPaths.ClamdPort;
            if (MaxScanFileSizeMB < 1 || MaxScanFileSizeMB > 4096) MaxScanFileSizeMB = 200;
            if (string.IsNullOrEmpty(Language)) Language = "es-ES";
            if (!string.Equals(Language, "en", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(Language, "es-ES", StringComparison.OrdinalIgnoreCase))
                Language = "es-ES";
            if (!string.Equals(QuarantineAction, "delete", StringComparison.OrdinalIgnoreCase))
                QuarantineAction = "quarantine";
            else
                QuarantineAction = "delete";
        }

        private static List<string> CleanPathList(List<string> input)
        {
            List<string> result = new List<string>();
            for (int i = 0; i < input.Count; i++)
            {
                if (string.IsNullOrEmpty(input[i])) continue;
                string path;
                try
                {
                    path = Path.GetFullPath(input[i].Trim().Trim('"')).TrimEnd('\\');
                }
                catch
                {
                    continue;
                }
                if (!AppPaths.ContainsPath(result, path)) result.Add(path);
            }
            return result;
        }

        public bool IsResidentScanEnabled { get { return OnAccessEnabled; } }
        public bool IsDeletePolicy { get { return string.Equals(QuarantineAction, "delete", StringComparison.OrdinalIgnoreCase); } }

        public static AppSettings Load()
        {
            try
            {
                if (File.Exists(AppPaths.SettingsFile))
                {
                    using (FileStream fs = File.OpenRead(AppPaths.SettingsFile))
                    {
                        DataContractJsonSerializer ser = new DataContractJsonSerializer(typeof(AppSettings));
                        AppSettings settings = (AppSettings)ser.ReadObject(fs);
                        if (settings != null)
                        {
                            settings.Normalize();
                            return settings;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                AppLog.Warn("No se pudo leer la configuración; se usan valores por defecto: " + ex.Message);
            }
            AppSettings defaults = new AppSettings();
            defaults.Normalize();
            return defaults;
        }

        public void Save()
        {
            JsonStore.Save(AppPaths.SettingsFile, this);
        }
    }

    [DataContract]
    public sealed class AppState
    {
        [DataMember(Order = 1)] public string LastUpdateUtc;
        [DataMember(Order = 2)] public string LastUpdateMessage;
        [DataMember(Order = 3)] public bool LastUpdateOk;
        [DataMember(Order = 4)] public string LastThreatUtc;
        [DataMember(Order = 5)] public string LastThreatName;
        [DataMember(Order = 6)] public string LastThreatPath;
        [DataMember(Order = 7)] public string LastScanUtc;
        [DataMember(Order = 8)] public long LastScanFiles;
        [DataMember(Order = 9)] public int LastScanThreats;

        public static DateTime? ParseUtc(string value)
        {
            if (string.IsNullOrEmpty(value)) return null;
            DateTime parsed;
            if (DateTime.TryParse(value, System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.RoundtripKind, out parsed))
                return parsed.ToUniversalTime();
            return null;
        }

        public static string ToUtc(DateTime value)
        {
            return value.ToUniversalTime().ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        }
    }

    public static class StateStore
    {
        private const string MutexName = @"Global\ClamGuardStateLock";

        public static AppState Load()
        {
            try
            {
                if (File.Exists(AppPaths.StateFile))
                {
                    using (FileStream fs = File.OpenRead(AppPaths.StateFile))
                    {
                        DataContractJsonSerializer ser = new DataContractJsonSerializer(typeof(AppState));
                        AppState state = (AppState)ser.ReadObject(fs);
                        if (state != null) return state;
                    }
                }
            }
            catch
            {
            }
            return new AppState();
        }

        public static void Mutate(Action<AppState> action)
        {
            if (action == null) return;
            Mutex mutex = null;
            bool locked = false;
            try
            {
                try
                {
                    mutex = new Mutex(false, MutexName);
                    try { locked = mutex.WaitOne(TimeSpan.FromSeconds(3)); }
                    catch (AbandonedMutexException) { locked = true; }
                }
                catch
                {
                    locked = true;
                }

                AppState state = Load();
                action(state);
                JsonStore.Save(AppPaths.StateFile, state);
            }
            catch (Exception ex)
            {
                AppLog.Warn("No se pudo guardar el estado: " + ex.Message);
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

        public static void RecordThreat(string path, string signature)
        {
            Mutate(delegate(AppState s)
            {
                s.LastThreatUtc = AppState.ToUtc(DateTime.UtcNow);
                s.LastThreatName = signature;
                s.LastThreatPath = path;
            });
        }
    }

    public static class JsonStore
    {
        public static void Save<T>(string path, T value)
        {
            try
            {
                string dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                string tmp = path + ".tmp";
                using (FileStream fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
                using (System.Xml.XmlDictionaryWriter writer = System.Runtime.Serialization.Json.JsonReaderWriterFactory.CreateJsonWriter(
                    fs, new UTF8Encoding(false), true, true, "  "))
                {
                    DataContractJsonSerializer ser = new DataContractJsonSerializer(typeof(T));
                    ser.WriteObject(writer, value);
                    writer.Flush();
                }
                if (File.Exists(path))
                {
                    try
                    {
                        File.Replace(tmp, path, null);
                    }
                    catch
                    {
                        File.Copy(tmp, path, true);
                        File.Delete(tmp);
                    }
                }
                else
                {
                    File.Move(tmp, path);
                }
            }
            catch (Exception ex)
            {
                AppLog.Warn("No se pudo escribir " + path + ": " + ex.Message);
            }
        }
    }
}
