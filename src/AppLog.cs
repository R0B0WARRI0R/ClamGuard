using System;
using System.IO;
using System.Text;

namespace ClamGuard
{
    public enum LogLevel
    {
        Info,
        Ok,
        Warn,
        Error,
        Threat
    }

    /// <summary>
    /// Registro en disco con rotación sencilla. Nunca lanza excepciones.
    /// </summary>
    public static class AppLog
    {
        private static readonly object Sync = new object();
        private static string _file;

        public static void Init(string component)
        {
            try
            {
                AppPaths.EnsureLayout();
                _file = Path.Combine(AppPaths.LogsDir, component + ".log");
            }
            catch
            {
                _file = null;
            }
        }

        public static void Info(string message) { Write(LogLevel.Info, message); }
        public static void Ok(string message) { Write(LogLevel.Ok, message); }
        public static void Warn(string message) { Write(LogLevel.Warn, message); }
        public static void Error(string message) { Write(LogLevel.Error, message); }
        public static void Threat(string message) { Write(LogLevel.Threat, message); }

        public static void Write(LogLevel level, string message)
        {
            if (message == null) message = string.Empty;
            string tag;
            switch (level)
            {
                case LogLevel.Ok: tag = "OK"; break;
                case LogLevel.Warn: tag = "AVISO"; break;
                case LogLevel.Error: tag = "ERROR"; break;
                case LogLevel.Threat: tag = "AMENAZA"; break;
                default: tag = "INFO"; break;
            }

            string line = string.Format("{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}\r\n",
                DateTime.Now, tag, Sanitize(message));

            lock (Sync)
            {
                if (_file == null) return;
                try
                {
                    FileInfo fi = new FileInfo(_file);
                    if (fi.Exists && fi.Length > 5 * 1024 * 1024)
                    {
                        string old = _file + ".1";
                        try { if (File.Exists(old)) File.Delete(old); } catch { }
                        try { File.Move(_file, old); } catch { }
                    }
                    File.AppendAllText(_file, line, new UTF8Encoding(false));
                }
                catch
                {
                    // El registro nunca debe tumbar la aplicación.
                }
            }
        }

        public static string Sanitize(string text)
        {
            if (text == null) return string.Empty;
            text = text.Replace("\r", " ").Replace("\n", " ").Replace("\0", " ");
            if (text.Length > 4000) text = text.Substring(0, 4000) + "...";
            return text.Trim();
        }
    }
}
