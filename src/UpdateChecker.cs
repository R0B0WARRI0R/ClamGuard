using System;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace ClamGuard
{
    public sealed class UpdateInfo
    {
        public string Version = string.Empty;
        public string TagName = string.Empty;
        public string DownloadUrl = string.Empty;
        public string ReleaseUrl = string.Empty;
        public string Notes = string.Empty;
    }

    public static class UpdateChecker
    {
        private const string ApiUrl = "https://api.github.com/repos/davidcasascompetenciadigital-prog/ClamGuard/releases/latest";

        public static UpdateInfo Check()
        {
            try
            {
                using (WebClient wc = new WebClient())
                {
                    wc.Headers.Add("User-Agent", "ClamGuard/" + AppPaths.ProductVersion);
                    string json = wc.DownloadString(ApiUrl);

                    UpdateInfo info = new UpdateInfo();
                    info.TagName = ExtractString(json, "tag_name");
                    info.Version = info.TagName.TrimStart('v', 'V');
                    info.ReleaseUrl = ExtractString(json, "html_url");
                    info.Notes = ExtractString(json, "body");

                    // buscar asset .zip o .exe
                    string assetUrl = ExtractAssetUrl(json, ".zip");
                    if (string.IsNullOrEmpty(assetUrl)) assetUrl = ExtractAssetUrl(json, ".exe");
                    info.DownloadUrl = assetUrl;

                    if (string.IsNullOrEmpty(info.Version)) return null;
                    if (!IsNewer(info.Version, AppPaths.ProductVersion)) return null;
                    return info;
                }
            }
            catch
            {
                return null;
            }
        }

        private static string ExtractString(string json, string key)
        {
            if (string.IsNullOrEmpty(json)) return string.Empty;
            Regex r = new Regex("\"" + Regex.Escape(key) + "\"\\s*:\\s*\"((?:\\\\.|[^\"])*)\"", RegexOptions.IgnoreCase);
            Match m = r.Match(json);
            if (!m.Success) return string.Empty;
            return m.Groups[1].Value.Replace("\\n", "\n").Replace("\\r", "").Replace("\\\"", "\"");
        }

        private static string ExtractAssetUrl(string json, string ext)
        {
            // busca "browser_download_url": "..." dentro de assets
            Regex r = new Regex("\"browser_download_url\"\\s*:\\s*\"([^\"]+)\"", RegexOptions.IgnoreCase);
            MatchCollection mc = r.Matches(json);
            for (int i = 0; i < mc.Count; i++)
            {
                string url = mc[i].Groups[1].Value;
                if (url.EndsWith(ext, StringComparison.OrdinalIgnoreCase)) return url;
            }
            return string.Empty;
        }

        private static bool IsNewer(string remote, string current)
        {
            try
            {
                Version vRemote = new Version(Normalize(remote));
                Version vCurrent = new Version(Normalize(current));
                return vRemote > vCurrent;
            }
            catch
            {
                return !string.Equals(remote, current, StringComparison.OrdinalIgnoreCase);
            }
        }

        private static string Normalize(string v)
        {
            if (string.IsNullOrEmpty(v)) return "0.0.0.0";
            // quitar prefijo v
            v = v.Trim().TrimStart('v', 'V');
            // asegurar 4 partes
            string[] parts = v.Split('.');
            if (parts.Length == 1) v += ".0.0.0";
            else if (parts.Length == 2) v += ".0.0";
            else if (parts.Length == 3) v += ".0";
            return v;
        }
    }
}
