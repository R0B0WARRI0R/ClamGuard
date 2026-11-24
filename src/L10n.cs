using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;

namespace ClamGuard
{
    public static class L10n
    {
        private static Dictionary<string, string> _strings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private static string _language = "es-ES";

        public static string Language { get { return _language; } }

        public static void Load(string language)
        {
            if (string.IsNullOrEmpty(language)) language = "es-ES";
            _language = language;
            _strings.Clear();

            // 1. Intentar recurso embebido
            try
            {
                Assembly asm = Assembly.GetExecutingAssembly();
                string resName = "ClamGuard.lang." + language + ".json";
                using (Stream s = asm.GetManifestResourceStream(resName))
                {
                    if (s != null)
                    {
                        using (StreamReader r = new StreamReader(s, Encoding.UTF8))
                        {
                            ParseJson(r.ReadToEnd());
                            return;
                        }
                    }
                }
            }
            catch { }

            // 2. Fallback: archivo en disco junto al ejecutable
            try
            {
                string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "lang", language + ".json");
                if (File.Exists(path))
                {
                    ParseJson(File.ReadAllText(path, Encoding.UTF8));
                    return;
                }
            }
            catch { }

            // 3. Fallback inglés
            if (language != "en")
                Load("en");
        }

        private static void ParseJson(string json)
        {
            if (string.IsNullOrEmpty(json)) return;
            // Parser mínimo para {"key": "value", ...}
            int i = 0;
            // encontrar objeto
            int start = json.IndexOf('{');
            if (start < 0) return;
            i = start + 1;
            while (i < json.Length)
            {
                // saltar espacios
                while (i < json.Length && (json[i] == ' ' || json[i] == '\r' || json[i] == '\n' || json[i] == '\t' || json[i] == ',')) i++;
                if (i >= json.Length || json[i] == '}') break;
                if (json[i] != '"') { i++; continue; }
                // leer key
                i++;
                StringBuilder key = new StringBuilder();
                while (i < json.Length && json[i] != '"')
                {
                    if (json[i] == '\\' && i + 1 < json.Length) { key.Append(json[i + 1]); i += 2; continue; }
                    key.Append(json[i]); i++;
                }
                i++; // skip closing quote
                // skip colon
                while (i < json.Length && (json[i] == ' ' || json[i] == ':')) i++;
                if (i >= json.Length || json[i] != '"') { i++; continue; }
                i++;
                StringBuilder val = new StringBuilder();
                while (i < json.Length && json[i] != '"')
                {
                    if (json[i] == '\\' && i + 1 < json.Length) { val.Append(json[i + 1]); i += 2; continue; }
                    val.Append(json[i]); i++;
                }
                i++;
                _strings[key.ToString()] = val.ToString();
            }
        }

        public static string T(string key)
        {
            if (string.IsNullOrEmpty(key)) return key;
            string val;
            if (_strings.TryGetValue(key, out val)) return val;
            return key;
        }

        public static string T(string key, params object[] args)
        {
            string val = T(key);
            try { return string.Format(val, args); } catch { return val; }
        }
    }
}
