using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.Windows.Forms;

namespace ClamGuard
{
    /// <summary>
    /// Paleta, tipografías y utilidades de dibujo de la interfaz.
    /// </summary>
    public static class Theme
    {
        public static readonly Color Background = Color.FromArgb(244, 246, 249);
        public static readonly Color Surface = Color.White;
        public static readonly Color Border = Color.FromArgb(226, 232, 240);
        public static readonly Color BorderStrong = Color.FromArgb(203, 213, 225);

        public static readonly Color TextPrimary = Color.FromArgb(15, 23, 42);
        public static readonly Color TextSecondary = Color.FromArgb(71, 85, 105);
        public static readonly Color TextMuted = Color.FromArgb(148, 163, 184);

        public static readonly Color Accent = Color.FromArgb(37, 99, 235);
        public static readonly Color AccentHover = Color.FromArgb(29, 78, 216);
        public static readonly Color AccentSoft = Color.FromArgb(239, 246, 255);
        public static readonly Color AccentBorder = Color.FromArgb(191, 219, 254);

        public static readonly Color Success = Color.FromArgb(22, 163, 74);
        public static readonly Color SuccessSoft = Color.FromArgb(240, 253, 244);
        public static readonly Color SuccessBorder = Color.FromArgb(187, 247, 208);

        public static readonly Color Warning = Color.FromArgb(180, 83, 9);
        public static readonly Color WarningSoft = Color.FromArgb(255, 251, 235);
        public static readonly Color WarningBorder = Color.FromArgb(253, 230, 138);

        public static readonly Color Danger = Color.FromArgb(220, 38, 38);
        public static readonly Color DangerSoft = Color.FromArgb(254, 242, 242);
        public static readonly Color DangerBorder = Color.FromArgb(254, 202, 202);

        public static readonly Color ConsoleBack = Color.FromArgb(15, 23, 42);
        public static readonly Color ConsoleText = Color.FromArgb(203, 213, 225);

        public const string GlyphScan = "\uE721";
        public const string GlyphShield = "\uEA18";
        public const string GlyphRefresh = "\uE72C";
        public const string GlyphFolder = "\uE8B7";
        public const string GlyphSettings = "\uE713";
        public const string GlyphQuarantine = "\uE74D";
        public const string GlyphWarning = "\uE7BA";
        public const string GlyphInfo = "\uE946";
        public const string GlyphCheck = "\uE73E";
        public const string GlyphDownload = "\uE896";
        public const string GlyphSearch = "\uE721";
        public const string GlyphLock = "\uE72E";
        public const string GlyphChevron = "\uE76C";

        public static Font Ui(float size, FontStyle style)
        {
            return new Font("Segoe UI", size, style, GraphicsUnit.Point);
        }

        public static Font Icon(float size)
        {
            return new Font("Segoe MDL2 Assets", size, FontStyle.Regular, GraphicsUnit.Point);
        }

        public static GraphicsPath RoundedRect(Rectangle bounds, int radius)
        {
            GraphicsPath path = new GraphicsPath();
            int diameter = Math.Max(1, radius * 2);
            if (diameter > bounds.Width) diameter = bounds.Width;
            if (diameter > bounds.Height) diameter = bounds.Height;
            Rectangle arc = new Rectangle(bounds.Location, new Size(diameter, diameter));
            path.AddArc(arc, 180, 90);
            arc.X = bounds.Right - diameter;
            path.AddArc(arc, 270, 90);
            arc.Y = bounds.Bottom - diameter;
            path.AddArc(arc, 0, 90);
            arc.X = bounds.Left;
            path.AddArc(arc, 90, 90);
            path.CloseFigure();
            return path;
        }

        public static void DrawShield(Graphics g, RectangleF rect, Color fill, Color check)
        {
            SmoothingMode old = g.SmoothingMode;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            float w = rect.Width;
            float h = rect.Height;
            float left = rect.Left + w * 0.12f;
            float right = rect.Right - w * 0.12f;
            float top = rect.Top + h * 0.08f;
            float bottom = rect.Bottom - h * 0.06f;
            float midY = rect.Top + h * 0.5f;

            PointF[] points = new PointF[]
            {
                new PointF(rect.Left + w * 0.5f, top),
                new PointF(right, top + h * 0.12f),
                new PointF(right, midY),
                new PointF(rect.Left + w * 0.5f, bottom),
                new PointF(left, midY),
                new PointF(left, top + h * 0.12f)
            };
            using (GraphicsPath path = new GraphicsPath())
            {
                path.AddPolygon(points);
                path.CloseFigure();
                using (SolidBrush brush = new SolidBrush(fill)) g.FillPath(brush, path);
            }

            using (Pen pen = new Pen(check, Math.Max(1.5f, w * 0.075f)))
            {
                pen.StartCap = LineCap.Round;
                pen.EndCap = LineCap.Round;
                pen.LineJoin = LineJoin.Round;
                PointF p1 = new PointF(rect.Left + w * 0.34f, rect.Top + h * 0.52f);
                PointF p2 = new PointF(rect.Left + w * 0.46f, rect.Top + h * 0.64f);
                PointF p3 = new PointF(rect.Left + w * 0.68f, rect.Top + h * 0.38f);
                g.DrawLines(pen, new PointF[] { p1, p2, p3 });
            }
            g.SmoothingMode = old;
        }

        public static string Ellipsize(Graphics g, string text, Font font, int width)
        {
            if (string.IsNullOrEmpty(text)) return string.Empty;
            if (width <= 0) return string.Empty;
            if (TextRenderer.MeasureText(text, font).Width <= width) return text;
            const string suffix = "…";
            int low = 0;
            int high = text.Length;
            while (low < high)
            {
                int mid = (low + high + 1) / 2;
                string candidate = text.Substring(0, mid) + suffix;
                if (TextRenderer.MeasureText(candidate, font).Width <= width) low = mid;
                else high = mid - 1;
            }
            return low <= 0 ? suffix : text.Substring(0, low) + suffix;
        }

        public static void DrawText(Graphics g, string text, Font font, Color color, Rectangle bounds,
            TextFormatFlags flags)
        {
            TextRenderer.DrawText(g, text, font, bounds, color, flags);
        }

        public const TextFormatFlags LeftMiddle =
            TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix |
            TextFormatFlags.EndEllipsis;

        public const TextFormatFlags LeftTop =
            TextFormatFlags.Left | TextFormatFlags.Top | TextFormatFlags.NoPrefix |
            TextFormatFlags.WordBreak;

        public static string FormatDateTime(DateTime value)
        {
            if (value == DateTime.MinValue) return "nunca";
            DateTime local = value.Kind == DateTimeKind.Utc ? value.ToLocalTime() : value;
            return local.ToString("dd/MM/yyyy HH:mm");
        }
    }
}
