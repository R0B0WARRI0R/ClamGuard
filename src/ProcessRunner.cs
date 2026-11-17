using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace ClamGuard
{
    public sealed class ProcessResult
    {
        public int ExitCode;
        public string Output = string.Empty;
        public string Error = string.Empty;
        public bool TimedOut;
        public bool Canceled;
        public TimeSpan Duration;
    }

    public static class Cmd
    {
        /// <summary>
        /// Cita un argumento según las reglas de CommandLineToArgvW (Windows).
        /// </summary>
        public static string Quote(string value)
        {
            if (value == null) value = string.Empty;
            StringBuilder sb = new StringBuilder();
            sb.Append('"');
            int backslashes = 0;
            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                if (c == '\\')
                {
                    backslashes++;
                }
                else if (c == '"')
                {
                    sb.Append('\\', backslashes * 2 + 1);
                    sb.Append('"');
                    backslashes = 0;
                }
                else
                {
                    if (backslashes > 0) sb.Append('\\', backslashes);
                    backslashes = 0;
                    sb.Append(c);
                }
            }
            if (backslashes > 0) sb.Append('\\', backslashes * 2);
            sb.Append('"');
            return sb.ToString();
        }
    }

    public static class Proc
    {
        private const int MaxTailLines = 200;
        private const int MaxLineBytes = 8192;

        public static ProcessResult Run(
            string exe,
            string arguments,
            string workingDirectory,
            int timeoutMs,
            CancellationToken token)
        {
            return RunStreaming(exe, arguments, workingDirectory, timeoutMs, token, null, null);
        }

        /// <summary>
        /// Ejecuta un proceso sin ventana y captura la salida línea a línea.
        /// Se consideran fin de línea tanto LF como CR (freshclam usa CR para el progreso).
        /// </summary>
        public static ProcessResult RunStreaming(
            string exe,
            string arguments,
            string workingDirectory,
            int timeoutMs,
            CancellationToken token,
            Action<string, bool> onLine,
            IDictionary<string, string> environment)
        {
            ProcessResult result = new ProcessResult();
            Stopwatch watch = Stopwatch.StartNew();
            List<string> output = new List<string>();
            List<string> errors = new List<string>();
            object sync = new object();

            Process process = new Process();
            Thread outThread = null;
            Thread errThread = null;
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = exe;
                psi.Arguments = arguments;
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                if (!string.IsNullOrEmpty(workingDirectory)) psi.WorkingDirectory = workingDirectory;
                if (environment != null)
                {
                    foreach (KeyValuePair<string, string> pair in environment)
                        psi.EnvironmentVariables[pair.Key] = pair.Value;
                }

                process.StartInfo = psi;
                if (!process.Start())
                    throw new InvalidOperationException("No se pudo iniciar " + exe);

                outThread = new Thread(delegate()
                {
                    ReadLines(process.StandardOutput.BaseStream, false, onLine, output, sync);
                });
                outThread.IsBackground = true;
                outThread.Start();

                errThread = new Thread(delegate()
                {
                    ReadLines(process.StandardError.BaseStream, true, onLine, errors, sync);
                });
                errThread.IsBackground = true;
                errThread.Start();

                while (!process.WaitForExit(200))
                {
                    if (token.IsCancellationRequested)
                    {
                        result.Canceled = true;
                        Kill(process);
                        break;
                    }
                    if (timeoutMs > 0 && watch.ElapsedMilliseconds > timeoutMs)
                    {
                        result.TimedOut = true;
                        Kill(process);
                        break;
                    }
                }

                try { process.WaitForExit(); } catch { }
                try { result.ExitCode = process.ExitCode; } catch { result.ExitCode = -1; }
            }
            catch (Exception ex)
            {
                result.ExitCode = -1;
                lock (sync)
                {
                    if (errors.Count >= MaxTailLines) errors.RemoveAt(0);
                    errors.Add(ex.Message);
                }
                if (onLine != null)
                {
                    try { onLine(ex.Message, true); } catch { }
                }
            }
            finally
            {
                if (outThread != null) { try { outThread.Join(4000); } catch { } }
                if (errThread != null) { try { errThread.Join(4000); } catch { } }
                try { process.Dispose(); } catch { }
            }

            result.Duration = watch.Elapsed;
            lock (sync)
            {
                result.Output = string.Join(Environment.NewLine, output.ToArray());
                result.Error = string.Join(Environment.NewLine, errors.ToArray());
            }
            return result;
        }

        private static void ReadLines(Stream stream, bool isError, Action<string, bool> onLine,
            List<string> tail, object sync)
        {
            try
            {
                byte[] buffer = new byte[4096];
                MemoryStream pending = new MemoryStream();
                while (true)
                {
                    int read = stream.Read(buffer, 0, buffer.Length);
                    if (read <= 0) break;
                    for (int i = 0; i < read; i++)
                    {
                        byte value = buffer[i];
                        if (value == (byte)'\n' || value == (byte)'\r')
                        {
                            if (pending.Length > 0)
                            {
                                Emit(pending, isError, onLine, tail, sync);
                                pending.SetLength(0);
                            }
                        }
                        else
                        {
                            pending.WriteByte(value);
                            if (pending.Length >= MaxLineBytes)
                            {
                                Emit(pending, isError, onLine, tail, sync);
                                pending.SetLength(0);
                            }
                        }
                    }
                }
                if (pending.Length > 0) Emit(pending, isError, onLine, tail, sync);
            }
            catch
            {
            }
        }

        private static void Emit(MemoryStream pending, bool isError, Action<string, bool> onLine,
            List<string> tail, object sync)
        {
            string text = Encoding.UTF8.GetString(pending.GetBuffer(), 0, (int)pending.Length);
            text = text.TrimEnd();
            if (text.Length > 2000) text = text.Substring(0, 2000) + "...";
            lock (sync)
            {
                if (tail.Count >= MaxTailLines) tail.RemoveAt(0);
                tail.Add(text);
            }
            if (onLine != null)
            {
                try { onLine(text, isError); } catch { }
            }
        }

        public static void Kill(Process process)
        {
            try
            {
                if (process != null && !process.HasExited) process.Kill();
            }
            catch
            {
            }
            try
            {
                if (process != null) process.WaitForExit(5000);
            }
            catch
            {
            }
        }

        public static int RunHidden(string exe, string arguments, int timeoutMs, out string output, out string error)
        {
            ProcessResult result = Run(exe, arguments, null, timeoutMs, CancellationToken.None);
            output = result.Output;
            error = result.Error;
            return result.ExitCode;
        }
    }
}
