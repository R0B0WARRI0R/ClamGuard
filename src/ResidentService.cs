using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using System.Text;
using System.Threading;

namespace ClamGuard
{
    /// <summary>
    /// Servicio residente de ClamGuard. Mantiene clamd en ejecución, vigila las
    /// carpetas configuradas, analiza archivos nuevos o modificados, revisa
    /// unidades extraíbles y actualiza las firmas periódicamente.
    /// </summary>
    public sealed class ClamGuardService : ServiceBase
    {
        private CancellationTokenSource _stop;
        private AppSettings _settings;
        private ClamdHost _clamd;
        private FileMonitor _monitor;
        private RemovableDriveWatcher _usb;
        private UpdaterLoop _updater;
        private Thread _supervisor;
        private readonly object _settingsSync = new object();
        private DateTime _settingsWriteUtc = DateTime.MinValue;

        public ClamGuardService()
        {
            ServiceName = AppPaths.ServiceName;
            CanStop = true;
            CanShutdown = true;
            CanHandlePowerEvent = true;
            AutoLog = false;
        }

        public AppSettings CurrentSettings
        {
            get { lock (_settingsSync) { return _settings; } }
        }

        protected override void OnStart(string[] args)
        {
            AppLog.Init("resident");
            AppLog.Info("Servicio residente iniciando (versión " + AppPaths.ProductVersion + ").");

            _stop = new CancellationTokenSource();
            _settings = AppSettings.Load();
            try
            {
                AppPaths.EnsureLayout();
                ClamAv.WriteConfigs(_settings);
                if (File.Exists(AppPaths.SettingsFile))
                    _settingsWriteUtc = File.GetLastWriteTimeUtc(AppPaths.SettingsFile);
            }
            catch (Exception ex)
            {
                AppLog.Warn("Preparación inicial: " + ex.Message);
            }

            _clamd = new ClamdHost(delegate { return CurrentSettings; }, _stop.Token);
            _monitor = new FileMonitor(delegate { return CurrentSettings; }, _clamd, _stop.Token);
            _usb = new RemovableDriveWatcher(delegate { return CurrentSettings; }, _stop.Token);
            _updater = new UpdaterLoop(delegate { return CurrentSettings; }, _stop.Token);

            // Convivencia con Windows Defender: exclusiones y pausa temporal de
            // la protección en tiempo real mientras el residente esté activo.
            try
            {
                Defender.Prepare(_settings, null);
            }
            catch (Exception ex)
            {
                AppLog.Warn("Preparación de Windows Defender: " + ex.Message);
            }

            _supervisor = new Thread(Supervise);
            _supervisor.IsBackground = true;
            _supervisor.Name = "ClamGuard supervisor";
            _supervisor.Start();

            _updater.Start();
            _usb.Start();

            AppLog.Ok("Servicio residente en marcha.");
        }

        private void Supervise()
        {
            CancellationToken token = _stop.Token;
            bool started = false;
            int defenderTicks = 0;
            while (!token.IsCancellationRequested)
            {
                try
                {
                    bool running = _clamd.EnsureRunning();
                    if (running && !started)
                    {
                        started = true;
                        if (CurrentSettings.OnAccessEnabled)
                            _monitor.Start();
                        else
                            AppLog.Info("La protección al acceder está desactivada en la configuración.");
                    }
                    else if (!running && started)
                    {
                        started = false;
                        AppLog.Warn("clamd no está disponible; se reintentará automáticamente.");
                    }

                    ReloadSettingsIfChanged();

                    // Cada ~10 minutos se comprueba que Defender siga en pausa.
                    defenderTicks++;
                    if (defenderTicks >= 30)
                    {
                        defenderTicks = 0;
                        try
                        {
                            Defender.Enforce(CurrentSettings, null);
                        }
                        catch (Exception ex)
                        {
                            AppLog.Warn("Comprobación de Windows Defender: " + ex.Message);
                        }
                    }

                    AppSettings settings = CurrentSettings;
                    if (settings.OnAccessEnabled)
                    {
                        if (!_monitor.IsRunning && running) _monitor.Start();
                        _monitor.UpdatePaths(settings.MonitorPaths);
                    }
                    else if (_monitor.IsRunning)
                    {
                        _monitor.Stop();
                        AppLog.Info("Protección al acceder detenida por configuración.");
                    }
                }
                catch (Exception ex)
                {
                    AppLog.Error("Supervisor: " + ex.Message);
                }

                if (token.WaitHandle.WaitOne(TimeSpan.FromSeconds(20))) break;
            }

            AppLog.Info("Supervisor detenido.");
        }

        private void ReloadSettingsIfChanged()
        {
            try
            {
                if (!File.Exists(AppPaths.SettingsFile)) return;
                DateTime write = File.GetLastWriteTimeUtc(AppPaths.SettingsFile);
                if (write == _settingsWriteUtc) return;

                AppSettings fresh = AppSettings.Load();
                AppSettings previous = _settings;
                bool portChanged = previous == null || fresh.ClamdPort != previous.ClamdPort;
                bool defenderChanged = previous == null || fresh.PauseDefender != previous.PauseDefender;
                lock (_settingsSync) { _settings = fresh; }
                _settingsWriteUtc = write;
                ClamAv.WriteConfigs(fresh);

                if (portChanged && _clamd != null)
                {
                    AppLog.Info("El puerto de clamd cambió; se reinicia el motor.");
                    _clamd.Restart();
                }
                if (defenderChanged && _stop != null && !_stop.IsCancellationRequested)
                {
                    AppLog.Info("La configuración de Windows Defender cambió; se aplica.");
                    Defender.Prepare(fresh, null);
                }
                AppLog.Info("Configuración recargada.");
            }
            catch (Exception ex)
            {
                AppLog.Warn("No se pudo recargar la configuración: " + ex.Message);
            }
        }

        protected override void OnStop()
        {
            AppLog.Info("Servicio residente deteniéndose...");
            try
            {
                if (_stop != null) _stop.Cancel();
                if (_monitor != null) _monitor.Stop();
                if (_usb != null) _usb.Stop();
                if (_updater != null) _updater.Stop();
                if (_clamd != null) _clamd.Stop();
                if (_supervisor != null) _supervisor.Join(TimeSpan.FromSeconds(15));
            }
            catch (Exception ex)
            {
                AppLog.Warn("Al detener: " + ex.Message);
            }
            finally
            {
                // Al dejar de estar residente se reactiva Windows Defender.
                try
                {
                    Defender.Restore(null);
                }
                catch (Exception ex)
                {
                    AppLog.Warn("Restauración de Windows Defender: " + ex.Message);
                }
                try { if (_stop != null) _stop.Dispose(); } catch { }
                _stop = null;
            }
            AppLog.Ok("Servicio residente detenido.");
        }

        protected override void OnShutdown()
        {
            OnStop();
            base.OnShutdown();
        }

        protected override bool OnPowerEvent(PowerBroadcastStatus powerStatus)
        {
            if (powerStatus == PowerBroadcastStatus.ResumeSuspend)
            {
                AppLog.Info("Equipo reanudado; comprobando el motor residente.");
                try
                {
                    if (_clamd != null) _clamd.EnsureRunning();
                }
                catch
                {
                }
            }
            return base.OnPowerEvent(powerStatus);
        }
    }

    /// <summary>
    /// Controla el proceso clamd.exe propiedad del servicio.
    /// </summary>
    public sealed class ClamdHost
    {
        private readonly Func<AppSettings> _settings;
        private readonly CancellationToken _token;
        private readonly object _sync = new object();
        private Process _process;
        private bool _owned;
        private DateTime _lastFailure = DateTime.MinValue;
        private bool _reportedExternal;

        public ClamdHost(Func<AppSettings> settings, CancellationToken token)
        {
            _settings = settings;
            _token = token;
        }

        public bool EnsureRunning()
        {
            lock (_sync)
            {
                int port = _settings().ClamdPort;
                if (ClamAv.Ping(port, 800))
                {
                    if (!_owned && !_reportedExternal)
                    {
                        AppLog.Info("Se usará la instancia de clamd que ya está en el puerto " + port + ".");
                        _reportedExternal = true;
                    }
                    return true;
                }

                if (_process != null)
                {
                    try
                    {
                        if (_process.HasExited)
                        {
                            AppLog.Warn("clamd terminó (código " + _process.ExitCode + ").");
                            DisposeProcess();
                        }
                    }
                    catch
                    {
                        DisposeProcess();
                    }
                }

                if (DateTime.UtcNow - _lastFailure < TimeSpan.FromSeconds(30)) return false;

                AppSettings settings = _settings();
                string dir = AppPaths.FindClamAvDirectory(settings.ClamAvDirectory);
                string clamd = ClamAv.GetExe(dir, "clamd.exe");
                if (clamd == null)
                {
                    AppLog.Warn("No se encontró clamd.exe; el residente esperará a que ClamAV esté instalado.");
                    _lastFailure = DateTime.UtcNow;
                    return false;
                }

                AppPaths.EnsureLayout();
                ClamAv.WriteConfigs(settings);
                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo();
                    psi.FileName = clamd;
                    psi.Arguments = "--config-file=" + Cmd.Quote(AppPaths.ClamdConf);
                    psi.WorkingDirectory = dir;
                    psi.UseShellExecute = false;
                    psi.CreateNoWindow = true;
                    psi.WindowStyle = ProcessWindowStyle.Hidden;
                    psi.EnvironmentVariables["TMP"] = AppPaths.TempDir;
                    psi.EnvironmentVariables["TEMP"] = AppPaths.TempDir;

                    Process process = new Process();
                    process.StartInfo = psi;
                    process.EnableRaisingEvents = false;
                    if (!process.Start())
                    {
                        AppLog.Error("No se pudo iniciar clamd.exe.");
                        _lastFailure = DateTime.UtcNow;
                        return false;
                    }
                    _process = process;
                    _owned = true;
                    AppLog.Info("clamd iniciado (PID " + SafePid(process) + "); cargando firmas...");
                }
                catch (Exception ex)
                {
                    AppLog.Error("No se pudo iniciar clamd: " + ex.Message);
                    _lastFailure = DateTime.UtcNow;
                    return false;
                }

                AppLog.Info("Esperando a que clamd cargue la base de firmas...");
                if (ClamAv.WaitForClamd(port, 180000, _token))
                {
                    AppLog.Ok("clamd listo en el puerto " + port + ".");
                    _reportedExternal = false;
                    return true;
                }

                AppLog.Error("clamd no respondió en el tiempo esperado. " + LastLogHint());
                _lastFailure = DateTime.UtcNow;
                Stop();
                return false;
            }
        }

        public void Restart()
        {
            Stop();
            _lastFailure = DateTime.MinValue;
            EnsureRunning();
        }

        public void Stop()
        {
            lock (_sync)
            {
                int port = _settings().ClamdPort;
                if (_owned && ClamAv.Ping(port, 700))
                {
                    AppLog.Info("Deteniendo clamd...");
                    ClamAv.ShutdownClamd(port);
                    try
                    {
                        if (_process != null) _process.WaitForExit(20000);
                    }
                    catch
                    {
                    }
                }
                if (_process != null)
                {
                    try
                    {
                        if (!_process.HasExited) _process.Kill();
                    }
                    catch
                    {
                    }
                }
                DisposeProcess();
            }
        }

        private void DisposeProcess()
        {
            try { if (_process != null) _process.Dispose(); } catch { }
            _process = null;
            _owned = false;
        }

        private static int SafePid(Process process)
        {
            try { return process.Id; } catch { return 0; }
        }

        private static string LastLogHint()
        {
            try
            {
                if (!File.Exists(AppPaths.ClamdLog)) return string.Empty;
                string[] lines = File.ReadAllLines(AppPaths.ClamdLog);
                StringBuilder sb = new StringBuilder("Últimas líneas de clamd.log: ");
                int start = Math.Max(0, lines.Length - 4);
                for (int i = start; i < lines.Length; i++)
                {
                    if (i > start) sb.Append(" | ");
                    sb.Append(lines[i].Trim());
                }
                return sb.ToString();
            }
            catch
            {
                return string.Empty;
            }
        }
    }

    /// <summary>
    /// Vigila las carpetas configuradas y analiza los archivos nuevos o modificados.
    /// Los eventos se agrupan para esperar a que el archivo termine de escribirse.
    /// </summary>
    public sealed class FileMonitor
    {
        private const long MaxFileBytes = ClamAv.MaxResidentFileBytes;
        private const int QuietMilliseconds = 1500;
        private const int MaxPendingMilliseconds = 30000;

        private readonly Func<AppSettings> _settings;
        private readonly ClamdHost _clamd;
        private readonly CancellationToken _token;
        private readonly object _sync = new object();
        private readonly Dictionary<string, PendingFile> _pending =
            new Dictionary<string, PendingFile>(StringComparer.OrdinalIgnoreCase);
        private readonly List<FileSystemWatcher> _watchers = new List<FileSystemWatcher>();
        private readonly AutoResetEvent _wake = new AutoResetEvent(false);
        private Thread _worker;
        private string _pathsSignature = string.Empty;
        private volatile bool _running;

        public FileMonitor(Func<AppSettings> settings, ClamdHost clamd, CancellationToken token)
        {
            _settings = settings;
            _clamd = clamd;
            _token = token;
        }

        public bool IsRunning { get { return _running; } }

        public void Start()
        {
            if (_running) return;
            _running = true;
            _worker = new Thread(Work);
            _worker.IsBackground = true;
            _worker.Name = "ClamGuard file monitor";
            _worker.Start();
            UpdatePaths(_settings().MonitorPaths, true);
            AppLog.Ok("Protección al acceder activa.");
        }

        public void Stop()
        {
            _running = false;
            _wake.Set();
            lock (_sync)
            {
                DisposeWatchers();
                _pending.Clear();
            }
            if (_worker != null)
            {
                try { _worker.Join(TimeSpan.FromSeconds(5)); } catch { }
                _worker = null;
            }
        }

        public void UpdatePaths(List<string> paths)
        {
            UpdatePaths(paths, false);
        }

        private void UpdatePaths(List<string> paths, bool force)
        {
            if (!_running) return;
            if (paths == null) paths = new List<string>();

            List<string> valid = new List<string>();
            for (int i = 0; i < paths.Count; i++)
            {
                try
                {
                    if (Directory.Exists(paths[i]) && !AppPaths.IsUnder(paths[i], AppPaths.DataDir))
                    {
                        string full = Path.GetFullPath(paths[i]).TrimEnd('\\');
                        if (!AppPaths.ContainsPath(valid, full)) valid.Add(full);
                    }
                }
                catch
                {
                }
            }
            valid.Sort(StringComparer.OrdinalIgnoreCase);
            string signature = string.Join("|", valid.ToArray()).ToLowerInvariant();

            lock (_sync)
            {
                if (!force && string.Equals(signature, _pathsSignature, StringComparison.Ordinal)) return;
                _pathsSignature = signature;
                DisposeWatchers();
                for (int i = 0; i < valid.Count; i++)
                {
                    try
                    {
                        FileSystemWatcher watcher = new FileSystemWatcher(valid[i]);
                        watcher.IncludeSubdirectories = true;
                        watcher.InternalBufferSize = 64 * 1024;
                        watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName |
                            NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime;
                        watcher.Created += OnCreatedOrChanged;
                        watcher.Changed += OnCreatedOrChanged;
                        watcher.Renamed += OnRenamed;
                        watcher.Error += OnWatcherError;
                        watcher.EnableRaisingEvents = true;
                        _watchers.Add(watcher);
                    }
                    catch (Exception ex)
                    {
                        AppLog.Warn("No se pudo vigilar " + valid[i] + ": " + ex.Message);
                    }
                }
            }

            if (valid.Count > 0)
                AppLog.Info("Vigilando " + valid.Count + " carpeta(s) en tiempo real.");
            else
                AppLog.Warn("No hay carpetas válidas que vigilar.");
        }

        private void DisposeWatchers()
        {
            for (int i = 0; i < _watchers.Count; i++)
            {
                try
                {
                    _watchers[i].EnableRaisingEvents = false;
                    _watchers[i].Created -= OnCreatedOrChanged;
                    _watchers[i].Changed -= OnCreatedOrChanged;
                    _watchers[i].Renamed -= OnRenamed;
                    _watchers[i].Error -= OnWatcherError;
                    _watchers[i].Dispose();
                }
                catch
                {
                }
            }
            _watchers.Clear();
        }

        private void OnCreatedOrChanged(object sender, FileSystemEventArgs e)
        {
            Enqueue(e.FullPath);
        }

        private void OnRenamed(object sender, RenamedEventArgs e)
        {
            Enqueue(e.FullPath);
        }

        private void OnWatcherError(object sender, ErrorEventArgs e)
        {
            Exception ex = e.GetException();
            AppLog.Warn("Aviso del vigilante de archivos: " + (ex == null ? "desconocido" : ex.Message));
        }

        private void Enqueue(string path)
        {
            if (!_running || string.IsNullOrEmpty(path)) return;
            try
            {
                if (AppPaths.IsUnder(path, AppPaths.DataDir)) return;
                if (path.IndexOf(@"\System Volume Information", StringComparison.OrdinalIgnoreCase) >= 0) return;
                if (path.IndexOf(@"\$Recycle.Bin", StringComparison.OrdinalIgnoreCase) >= 0) return;
                if (Directory.Exists(path) && !File.Exists(path)) return;
                if (!File.Exists(path)) return;

                DateTime now = DateTime.UtcNow;
                lock (_sync)
                {
                    PendingFile entry;
                    if (!_pending.TryGetValue(path, out entry))
                    {
                        if (_pending.Count > 4000) _pending.Clear();
                        entry = new PendingFile();
                        entry.FirstUtc = now;
                        _pending[path] = entry;
                    }
                    entry.LastUtc = now;
                }
                _wake.Set();
            }
            catch
            {
            }
        }

        private void Work()
        {
            while (_running && !_token.IsCancellationRequested)
            {
                List<string> ready = new List<string>();
                try
                {
                    DateTime now = DateTime.UtcNow;
                    lock (_sync)
                    {
                        List<string> remove = new List<string>();
                        foreach (KeyValuePair<string, PendingFile> pair in _pending)
                        {
                            double quiet = (now - pair.Value.LastUtc).TotalMilliseconds;
                            double age = (now - pair.Value.FirstUtc).TotalMilliseconds;
                            if (quiet >= QuietMilliseconds || age >= MaxPendingMilliseconds)
                            {
                                remove.Add(pair.Key);
                                ready.Add(pair.Key);
                            }
                        }
                        for (int i = 0; i < remove.Count; i++) _pending.Remove(remove[i]);
                    }
                }
                catch (Exception ex)
                {
                    AppLog.Warn("Cola de análisis: " + ex.Message);
                }

                for (int i = 0; i < ready.Count; i++)
                {
                    if (!_running || _token.IsCancellationRequested) break;
                    ScanFile(ready[i]);
                }

                _wake.WaitOne(350);
            }
        }

        private void ScanFile(string path)
        {
            try
            {
                FileInfo info = new FileInfo(path);
                if (!info.Exists) return;
                if (info.Length <= 0) return;
                if (info.Length > MaxFileBytes)
                {
                    AppLog.Warn("Omitido por tamaño (> 200 MB): " + path);
                    return;
                }

                AppSettings settings = _settings();
                ClamdScanResult scan = ClamAv.ScanStream(path, settings.ClamdPort, 180000);
                if (scan.Infected)
                {
                    AppLog.Threat("AMENAZA: " + path + "  [" + scan.Signature + "]");
                    StateStore.RecordThreat(path, scan.Signature);
                    ThreatActions.Apply(settings, path, scan.Signature, AppLog.Write);
                }
                else if (!scan.Clean)
                {
                    AppLog.Warn("No se pudo analizar " + path + ": " + scan.Error);
                    if (!ClamAv.Ping(settings.ClamdPort, 800)) _clamd.EnsureRunning();
                }
            }
            catch (Exception ex)
            {
                AppLog.Warn("Error analizando " + path + ": " + ex.Message);
            }
        }

        private sealed class PendingFile
        {
            public DateTime FirstUtc;
            public DateTime LastUtc;
        }
    }

    /// <summary>
    /// Aplica la política configurada ante una amenaza detectada.
    /// </summary>
    public static class ThreatActions
    {
        public static void Apply(AppSettings settings, string path, string signature,
            Action<LogLevel, string> log)
        {
            if (settings == null) settings = AppSettings.Load();
            if (settings.IsDeletePolicy)
            {
                bool scheduled;
                string error;
                bool deleted = QuarantineStore.DeleteFilePermanently(path, out scheduled, out error);
                if (deleted)
                {
                    string message = scheduled
                        ? "El archivo está en uso; se eliminará al reiniciar: " + path
                        : "Archivo eliminado: " + path;
                    if (log != null) log(scheduled ? LogLevel.Warn : LogLevel.Ok, message);
                }
                else if (log != null)
                {
                    log(LogLevel.Error, "No se pudo eliminar " + path + ": " + error);
                }
                return;
            }

            QuarantineResult result = QuarantineStore.QuarantineFile(path, signature);
            if (log != null)
            {
                if (result.Success)
                    log(LogLevel.Ok, "Puesto en cuarentena: " + path);
                else
                    log(LogLevel.Error, "No se pudo poner en cuarentena " + path + ": " + result.Error);
            }
        }
    }

    /// <summary>
    /// Detecta unidades extraíbles nuevas y las analiza por completo.
    /// </summary>
    public sealed class RemovableDriveWatcher
    {
        private readonly Func<AppSettings> _settings;
        private readonly CancellationToken _token;
        private readonly HashSet<string> _known = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly object _sync = new object();
        private Thread _thread;
        private volatile bool _running;

        public RemovableDriveWatcher(Func<AppSettings> settings, CancellationToken token)
        {
            _settings = settings;
            _token = token;
        }

        public void Start()
        {
            if (_running) return;
            _running = true;
            _thread = new Thread(Work);
            _thread.IsBackground = true;
            _thread.Name = "ClamGuard removable drives";
            _thread.Start();
        }

        public void Stop()
        {
            _running = false;
            if (_thread != null)
            {
                try { _thread.Join(TimeSpan.FromSeconds(3)); } catch { }
                _thread = null;
            }
        }

        private void Work()
        {
            while (_running && !_token.IsCancellationRequested)
            {
                try
                {
                    if (_settings().ScanRemovableDrives) CheckDrives();
                }
                catch (Exception ex)
                {
                    AppLog.Warn("Unidades extraíbles: " + ex.Message);
                }
                if (_token.WaitHandle.WaitOne(TimeSpan.FromSeconds(15))) break;
            }
        }

        private void CheckDrives()
        {
            DriveInfo[] drives = DriveInfo.GetDrives();
            for (int i = 0; i < drives.Length; i++)
            {
                DriveInfo drive = drives[i];
                try
                {
                    if (drive.DriveType != DriveType.Removable || !drive.IsReady) continue;
                    string root = drive.RootDirectory.FullName;
                    bool isNew;
                    lock (_sync)
                    {
                        isNew = _known.Add(root);
                    }
                    if (isNew) ScanDrive(drive);
                }
                catch
                {
                }
            }
        }

        private void ScanDrive(DriveInfo drive)
        {
            string root = drive.RootDirectory.FullName;
            string label = string.IsNullOrEmpty(drive.VolumeLabel) ? root : drive.VolumeLabel + " (" + root + ")";
            AppLog.Info("Unidad extraíble detectada: " + label + ". Iniciando análisis...");

            Thread worker = new Thread(delegate()
            {
                try
                {
                    AppSettings settings = _settings();
                    List<string> targets = new List<string>();
                    targets.Add(root);
                    ScanResult result = Scanner.Scan(settings, targets, _token, null,
                        delegate(LogLevel level, string message)
                        {
                            if (level == LogLevel.Warn || level == LogLevel.Error || level == LogLevel.Threat)
                                AppLog.Write(level, message);
                        });

                    if (result.Canceled)
                    {
                        AppLog.Warn("Análisis de " + label + " cancelado.");
                        return;
                    }
                    if (result.Failed)
                    {
                        AppLog.Error("Análisis de " + label + " falló: " + result.Error);
                        return;
                    }
                    if (result.Threats.Count == 0)
                    {
                        AppLog.Ok("Unidad " + label + " limpia (" + result.FilesScanned + " archivo(s)).");
                        return;
                    }

                    AppLog.Threat("Unidad " + label + ": " + result.Threats.Count + " amenaza(s).");
                    for (int i = 0; i < result.Threats.Count; i++)
                    {
                        ScanThreat threat = result.Threats[i];
                        AppLog.Threat("AMENAZA: " + threat.Path + "  [" + threat.Signature + "]");
                        StateStore.RecordThreat(threat.Path, threat.Signature);
                        ThreatActions.Apply(settings, threat.Path, threat.Signature, AppLog.Write);
                    }
                }
                catch (Exception ex)
                {
                    AppLog.Error("Análisis de unidad extraíble: " + ex.Message);
                }
            });
            worker.IsBackground = true;
            worker.Name = "ClamGuard USB scan";
            worker.Start();
        }
    }

    /// <summary>
    /// Actualiza las firmas según el intervalo configurado.
    /// </summary>
    public sealed class UpdaterLoop
    {
        private readonly Func<AppSettings> _settings;
        private readonly CancellationToken _token;
        private Thread _thread;
        private volatile bool _running;

        public UpdaterLoop(Func<AppSettings> settings, CancellationToken token)
        {
            _settings = settings;
            _token = token;
        }

        public void Start()
        {
            if (_running) return;
            _running = true;
            _thread = new Thread(Work);
            _thread.IsBackground = true;
            _thread.Name = "ClamGuard updater";
            _thread.Start();
        }

        public void Stop()
        {
            _running = false;
            if (_thread != null)
            {
                try { _thread.Join(TimeSpan.FromSeconds(5)); } catch { }
                _thread = null;
            }
        }

        private void Work()
        {
            // Primera comprobación poco después de arrancar.
            if (_token.WaitHandle.WaitOne(TimeSpan.FromSeconds(90))) return;

            while (_running && !_token.IsCancellationRequested)
            {
                bool success = true;
                try
                {
                    AppSettings settings = _settings();
                    DateTime? last = AppState.ParseUtc(StateStore.Load().LastUpdateUtc);
                    TimeSpan interval = TimeSpan.FromHours(Math.Max(1, settings.UpdateIntervalHours));
                    bool due = !last.HasValue || DateTime.UtcNow - last.Value >= interval;

                    if (due)
                    {
                        AppLog.Info("Comprobando actualizaciones de firmas...");
                        UpdateResult update = ClamAv.RunFreshclam(settings, _token, delegate(string line)
                        {
                            AppLog.Info("freshclam: " + line);
                        });
                        success = update.Success;
                        if (update.Success) AppLog.Ok("Actualización: " + update.Message);
                        else if (!update.Canceled) AppLog.Warn("Actualización: " + update.Message);
                    }
                }
                catch (Exception ex)
                {
                    success = false;
                    AppLog.Warn("Actualizador: " + ex.Message);
                }

                TimeSpan delay;
                if (!success) delay = TimeSpan.FromMinutes(30);
                else
                {
                    int hours = 4;
                    try { hours = Math.Max(1, _settings().UpdateIntervalHours); } catch { }
                    delay = TimeSpan.FromHours(1);
                    TimeSpan interval = TimeSpan.FromHours(hours);
                    if (interval < delay) delay = interval;
                }
                if (_token.WaitHandle.WaitOne(delay)) break;
            }
        }
    }
}
