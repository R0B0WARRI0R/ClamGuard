using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace ClamGuard
{
    [DataContract]
    public sealed class QuarantineEntry
    {
        [DataMember(Order = 1)] public string Id;
        [DataMember(Order = 2)] public string OriginalPath;
        [DataMember(Order = 3)] public string ThreatName;
        [DataMember(Order = 4)] public long Size;
        [DataMember(Order = 5)] public string Sha256;
        [DataMember(Order = 6)] public string QuarantinedUtc;

        public DateTime QuarantinedLocal
        {
            get
            {
                DateTime? value = AppState.ParseUtc(QuarantinedUtc);
                return value.HasValue ? value.Value.ToLocalTime() : DateTime.MinValue;
            }
        }

        public string DateText
        {
            get { return QuarantinedLocal == DateTime.MinValue ? "-" : QuarantinedLocal.ToString("dd/MM/yyyy HH:mm"); }
        }

        public string SizeText { get { return ClamAv.FormatBytes(Size); } }
    }

    public sealed class QuarantineResult
    {
        public bool Success;
        public bool OriginalDeleted;
        public bool DeleteScheduled;
        public string Error = string.Empty;
        public QuarantineEntry Entry;
    }

    public static class QuarantineStore
    {
        private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("ClamGuard.Quarantine.Key.v1");
        private static readonly object KeySync = new object();
        private static byte[] _key;
        private const int MagicLength = 4;
        private const int IvLength = 16;
        private const int MacLength = 32;
        private const long MaxQuarantineBytes = 1024L * 1024 * 1024;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool MoveFileEx(string existingFileName, string newFileName, int flags);
        private const int MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;

        public static List<QuarantineEntry> List()
        {
            List<QuarantineEntry> result = new List<QuarantineEntry>();
            try
            {
                AppPaths.EnsureLayout();
                string[] files = Directory.GetFiles(AppPaths.QuarantineDir, "*.json");
                for (int i = 0; i < files.Length; i++)
                {
                    try
                    {
                        using (FileStream fs = File.OpenRead(files[i]))
                        {
                            DataContractJsonSerializer ser = new DataContractJsonSerializer(typeof(QuarantineEntry));
                            QuarantineEntry entry = (QuarantineEntry)ser.ReadObject(fs);
                            if (entry != null && !string.IsNullOrEmpty(entry.Id) &&
                                File.Exists(PayloadPath(entry.Id)))
                                result.Add(entry);
                        }
                    }
                    catch
                    {
                    }
                }
                result.Sort(delegate(QuarantineEntry a, QuarantineEntry b)
                {
                    return b.QuarantinedLocal.CompareTo(a.QuarantinedLocal);
                });
            }
            catch (Exception ex)
            {
                AppLog.Warn("No se pudo leer la cuarentena: " + ex.Message);
            }
            return result;
        }

        public static QuarantineResult QuarantineFile(string filePath, string signature)
        {
            QuarantineResult result = new QuarantineResult();
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            {
                result.Error = "El archivo ya no existe.";
                return result;
            }
            if (AppPaths.IsUnder(filePath, AppPaths.DataDir))
            {
                result.Error = "No se puede poner en cuarentena un archivo interno de ClamGuard.";
                return result;
            }

            Mutex mutex = null;
            bool locked = false;
            string payloadTemp = null;
            string payload = null;
            try
            {
                AppPaths.EnsureLayout();
                mutex = new Mutex(false, @"Global\ClamGuardQuarantine");
                try { locked = mutex.WaitOne(TimeSpan.FromSeconds(30)); }
                catch (AbandonedMutexException) { locked = true; }
                if (!locked) { result.Error = "La cuarentena está ocupada. Inténtalo de nuevo."; return result; }

                FileInfo info = new FileInfo(filePath);
                if (info.Length > MaxQuarantineBytes)
                {
                    result.Error = "El archivo es demasiado grande para la cuarentena (más de 1 GB).";
                    return result;
                }
                long free = AppPaths.GetFreeSpace(AppPaths.QuarantineDir);
                if (free > 0 && free < info.Length + 10L * 1024 * 1024)
                {
                    result.Error = "No hay espacio suficiente en disco para la cuarentena.";
                    return result;
                }

                string id = Guid.NewGuid().ToString("N");
                payload = PayloadPath(id);
                payloadTemp = payload + ".tmp";

                byte[] key = GetKey();
                byte[] iv;
                byte[] hash;
                EncryptFile(filePath, payloadTemp, key, out iv, out hash);

                using (FileStream output = new FileStream(payload, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    output.Write(new byte[] { (byte)'C', (byte)'G', (byte)'Q', (byte)'1' }, 0, MagicLength);
                    output.Write(iv, 0, iv.Length);
                    byte[] mac = ComputeMac(payloadTemp, iv, key);
                    output.Write(mac, 0, mac.Length);
                    using (FileStream encrypted = File.OpenRead(payloadTemp))
                    {
                        byte[] buffer = new byte[65536];
                        int read;
                        while ((read = encrypted.Read(buffer, 0, buffer.Length)) > 0)
                            output.Write(buffer, 0, read);
                    }
                }
                TryDeleteFile(payloadTemp);

                QuarantineEntry entry = new QuarantineEntry();
                entry.Id = id;
                entry.OriginalPath = Path.GetFullPath(filePath);
                entry.ThreatName = string.IsNullOrEmpty(signature) ? "Desconocido" : signature;
                entry.Size = info.Length;
                entry.Sha256 = ToHex(hash);
                entry.QuarantinedUtc = AppState.ToUtc(DateTime.UtcNow);
                JsonStore.Save(EntryPath(id), entry);

                bool deleted = TryDeleteSource(filePath, out result.DeleteScheduled);
                result.OriginalDeleted = deleted;
                result.Entry = entry;
                result.Success = deleted || result.DeleteScheduled;
                if (!result.Success)
                    result.Error = "Se guardó una copia cifrada, pero no se pudo eliminar el original (archivo en uso).";
                else if (!deleted)
                    result.Error = "El original está bloqueado: se eliminará al reiniciar Windows.";

                AppLog.Threat("En cuarentena: " + entry.OriginalPath + " [" + entry.ThreatName + "]");
                StateStore.RecordThreat(entry.OriginalPath, entry.ThreatName);
                return result;
            }
            catch (Exception ex)
            {
                result.Error = "No se pudo mover a cuarentena: " + ex.Message;
                AppLog.Error(result.Error);
                try { if (payload != null && File.Exists(payload)) File.Delete(payload); } catch { }
                try { if (payloadTemp != null && File.Exists(payloadTemp)) File.Delete(payloadTemp); } catch { }
                return result;
            }
            finally
            {
                if (locked && mutex != null) { try { mutex.ReleaseMutex(); } catch { } }
                if (mutex != null) mutex.Dispose();
            }
        }

        public static bool Restore(QuarantineEntry entry, bool overwrite, out string error)
        {
            error = string.Empty;
            if (entry == null) { error = "Entrada no válida."; return false; }
            Mutex mutex = null;
            bool locked = false;
            string temp = null;
            try
            {
                mutex = new Mutex(false, @"Global\ClamGuardQuarantine");
                try { locked = mutex.WaitOne(TimeSpan.FromSeconds(30)); }
                catch (AbandonedMutexException) { locked = true; }
                if (!locked) { error = "La cuarentena está ocupada."; return false; }

                string payload = PayloadPath(entry.Id);
                if (!File.Exists(payload)) { error = "El archivo en cuarentena no existe."; return false; }

                string target = entry.OriginalPath;
                if (string.IsNullOrEmpty(target)) { error = "Ruta original desconocida."; return false; }
                string parent = Path.GetDirectoryName(target);
                if (string.IsNullOrEmpty(parent)) { error = "Ruta de destino no válida."; return false; }
                Directory.CreateDirectory(parent);
                if (File.Exists(target) && !overwrite)
                {
                    error = "Ya existe un archivo en la ruta original.";
                    return false;
                }

                temp = target + ".clamguard-restore-" + Guid.NewGuid().ToString("N");
                string computedHash = DecryptFile(payload, temp, GetKey());
                if (!string.Equals(computedHash, entry.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    error = "La verificación de integridad del archivo falló.";
                    return false;
                }

                if (File.Exists(target))
                {
                    try { File.Delete(target); }
                    catch (Exception ex) { error = "No se pudo sobrescribir el destino: " + ex.Message; return false; }
                }
                File.Move(temp, target);
                temp = null;

                TryDeleteFile(payload);
                TryDeleteFile(EntryPath(entry.Id));
                AppLog.Ok("Restaurado desde cuarentena: " + target);
                return true;
            }
            catch (Exception ex)
            {
                error = "No se pudo restaurar: " + ex.Message;
                AppLog.Error(error);
                return false;
            }
            finally
            {
                if (temp != null) { try { if (File.Exists(temp)) File.Delete(temp); } catch { } }
                if (locked && mutex != null) { try { mutex.ReleaseMutex(); } catch { } }
                if (mutex != null) mutex.Dispose();
            }
        }

        public static bool DeleteEntry(QuarantineEntry entry, out string error)
        {
            error = string.Empty;
            if (entry == null) { error = "Entrada no válida."; return false; }
            Mutex mutex = null;
            bool locked = false;
            try
            {
                mutex = new Mutex(false, @"Global\ClamGuardQuarantine");
                try { locked = mutex.WaitOne(TimeSpan.FromSeconds(30)); }
                catch (AbandonedMutexException) { locked = true; }
                if (!locked) { error = "La cuarentena está ocupada."; return false; }

                TryDeleteFile(PayloadPath(entry.Id));
                TryDeleteFile(EntryPath(entry.Id));
                AppLog.Ok("Eliminado de cuarentena: " + entry.OriginalPath);
                return true;
            }
            catch (Exception ex)
            {
                error = "No se pudo eliminar: " + ex.Message;
                return false;
            }
            finally
            {
                if (locked && mutex != null) { try { mutex.ReleaseMutex(); } catch { } }
                if (mutex != null) mutex.Dispose();
            }
        }

        public static bool DeleteFilePermanently(string path, out bool scheduled, out string error)
        {
            scheduled = false;
            error = string.Empty;
            try
            {
                if (!File.Exists(path))
                {
                    error = "El archivo ya no existe.";
                    return false;
                }
                bool wasScheduled;
                bool ok = TryDeleteSource(path, out wasScheduled);
                scheduled = wasScheduled;
                if (!ok)
                {
                    error = "No se pudo eliminar el archivo (puede estar en uso).";
                    return false;
                }
                AppLog.Ok("Archivo eliminado: " + path);
                return true;
            }
            catch (Exception ex)
            {
                error = "No se pudo eliminar: " + ex.Message;
                return false;
            }
        }

        private static bool TryDeleteSource(string path, out bool scheduled)
        {
            scheduled = false;
            try
            {
                File.Delete(path);
                return true;
            }
            catch
            {
                try
                {
                    if (MoveFileEx(path, null, MOVEFILE_DELAY_UNTIL_REBOOT))
                    {
                        scheduled = true;
                        return true;
                    }
                }
                catch
                {
                }
                return false;
            }
        }

        private static string PayloadPath(string id) { return Path.Combine(AppPaths.QuarantineDir, id + ".qtn"); }
        private static string EntryPath(string id) { return Path.Combine(AppPaths.QuarantineDir, id + ".json"); }

        private static void TryDeleteFile(string path)
        {
            try { if (File.Exists(path)) File.Delete(path); } catch { }
        }

        private static byte[] GetKey()
        {
            lock (KeySync)
            {
                if (_key != null) return _key;
                string keyPath = Path.Combine(AppPaths.QuarantineDir, "quarantine.key");
                try
                {
                    if (File.Exists(keyPath))
                    {
                        byte[] protectedBytes = File.ReadAllBytes(keyPath);
                        _key = ProtectedData.Unprotect(protectedBytes, Entropy, DataProtectionScope.LocalMachine);
                        if (_key != null && _key.Length == 32) return _key;
                    }
                }
                catch (Exception ex)
                {
                    AppLog.Warn("No se pudo leer la clave de cuarentena: " + ex.Message);
                }

                byte[] key = new byte[32];
                using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                    rng.GetBytes(key);
                byte[] protectedKey = ProtectedData.Protect(key, Entropy, DataProtectionScope.LocalMachine);
                File.WriteAllBytes(keyPath, protectedKey);
                _key = key;
                return key;
            }
        }

        private static void EncryptFile(string source, string destination, byte[] key, out byte[] iv, out byte[] hash)
        {
            iv = new byte[IvLength];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                rng.GetBytes(iv);

            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;
                aes.IV = iv;

                using (SHA256 sha = SHA256.Create())
                using (FileStream input = new FileStream(source, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete))
                using (FileStream output = new FileStream(destination, FileMode.Create, FileAccess.Write, FileShare.None))
                using (CryptoStream crypto = new CryptoStream(output, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] buffer = new byte[65536];
                    int read;
                    while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        sha.TransformBlock(buffer, 0, read, null, 0);
                        crypto.Write(buffer, 0, read);
                    }
                    sha.TransformFinalBlock(new byte[0], 0, 0);
                    hash = sha.Hash;
                }
            }
        }

        private static byte[] ComputeMac(string encryptedFile, byte[] iv, byte[] key)
        {
            using (HMACSHA256 hmac = new HMACSHA256(key))
            {
                hmac.TransformBlock(iv, 0, iv.Length, null, 0);
                using (FileStream input = File.OpenRead(encryptedFile))
                {
                    byte[] buffer = new byte[65536];
                    int read;
                    while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                        hmac.TransformBlock(buffer, 0, read, null, 0);
                }
                hmac.TransformFinalBlock(new byte[0], 0, 0);
                return hmac.Hash;
            }
        }

        private static string DecryptFile(string payload, string destination, byte[] key)
        {
            using (FileStream input = new FileStream(payload, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                byte[] header = new byte[MagicLength + IvLength + MacLength];
                if (input.Length < header.Length) throw new InvalidDataException("Archivo de cuarentena truncado.");
                int readHeader = input.Read(header, 0, header.Length);
                if (readHeader != header.Length ||
                    header[0] != 'C' || header[1] != 'G' || header[2] != 'Q' || header[3] != '1')
                    throw new InvalidDataException("Formato de cuarentena desconocido.");

                byte[] iv = new byte[IvLength];
                byte[] expectedMac = new byte[MacLength];
                Array.Copy(header, MagicLength, iv, 0, IvLength);
                Array.Copy(header, MagicLength + IvLength, expectedMac, 0, MacLength);

                using (HMACSHA256 hmac = new HMACSHA256(key))
                {
                    hmac.TransformBlock(iv, 0, iv.Length, null, 0);
                    byte[] buffer = new byte[65536];
                    int read;
                    while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                        hmac.TransformBlock(buffer, 0, read, null, 0);
                    hmac.TransformFinalBlock(new byte[0], 0, 0);
                    if (!FixedTimeEquals(hmac.Hash, expectedMac))
                        throw new CryptographicException("La firma de integridad de la cuarentena no coincide.");
                }

                input.Position = header.Length;
                using (Aes aes = Aes.Create())
                {
                    aes.KeySize = 256;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(key, iv))
                    using (SHA256 sha = SHA256.Create())
                    using (CryptoStream crypto = new CryptoStream(input, decryptor, CryptoStreamMode.Read))
                    using (FileStream output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    {
                        byte[] buffer = new byte[65536];
                        int read;
                        while ((read = crypto.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            sha.TransformBlock(buffer, 0, read, null, 0);
                            output.Write(buffer, 0, read);
                        }
                        sha.TransformFinalBlock(new byte[0], 0, 0);
                        return ToHex(sha.Hash);
                    }
                }
            }
        }

        private static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }

        private static string ToHex(byte[] bytes)
        {
            StringBuilder sb = new StringBuilder(bytes.Length * 2);
            for (int i = 0; i < bytes.Length; i++) sb.Append(bytes[i].ToString("x2"));
            return sb.ToString();
        }
    }
}
