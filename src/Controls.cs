using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace ClamGuard
{
    /// <summary>
    /// Tarjeta con esquinas redondeadas, fondo y borde configurables.
    /// </summary>
    public class CardPanel : Panel
    {
        private Color _fill = Theme.Surface;
        private Color _border = Theme.Border;
        private int _radius = 12;
        private bool _drawBorder = true;

        public CardPanel()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer |
                ControlStyles.ResizeRedraw | ControlStyles.UserPaint, true);
            BackColor = Theme.Background;
        }

        public Color FillColor
        {
            get { return _fill; }
            set { _fill = value; Invalidate(); }
        }

        public Color BorderColor
        {
            get { return _border; }
            set { _border = value; Invalidate(); }
        }

        public int CornerRadius
        {
            get { return _radius; }
            set { _radius = value; Invalidate(); }
        }

        public bool DrawBorder
        {
            get { return _drawBorder; }
            set { _drawBorder = value; Invalidate(); }
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(BackColor);
            Rectangle rect = new Rectangle(0, 0, Width - 1, Height - 1);
            if (rect.Width <= 0 || rect.Height <= 0) return;
            using (GraphicsPath path = Theme.RoundedRect(rect, _radius))
            {
                using (SolidBrush brush = new SolidBrush(_fill)) g.FillPath(brush, path);
                if (_drawBorder)
                {
                    using (Pen pen = new Pen(_border)) g.DrawPath(pen, path);
                }
            }
        }
    }

    public enum ButtonStyle
    {
        Primary,
        Secondary,
        Danger,
        Ghost
    }

    /// <summary>
    /// Botón plano con esquinas redondeadas, sin depender del tema del sistema.
    /// </summary>
    public class RoundedButton : Button
    {
        private bool _hover;
        private bool _pressed;
        private ButtonStyle _style = ButtonStyle.Primary;
        private int _radius = 8;
        private Color _fill = Theme.Accent;
        private Color _hoverFill = Theme.AccentHover;
        private Color _textColor = Color.White;
        private Color _borderColor = Color.Transparent;
        private int _borderWidth;

        public RoundedButton()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint |
                ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            FlatStyle = FlatStyle.Flat;
            FlatAppearance.BorderSize = 0;
            UseVisualStyleBackColor = false;
            BackColor = Theme.Surface;
            Font = Theme.Ui(9.5f, FontStyle.Bold);
            Cursor = Cursors.Hand;
            Height = 38;
            TabStop = true;
        }

        public ButtonStyle Style
        {
            get { return _style; }
            set
            {
                _style = value;
                ApplyStyle();
            }
        }

        public Color FillColor
        {
            get { return _fill; }
            set { _fill = value; Invalidate(); }
        }

        public Color HoverFillColor
        {
            get { return _hoverFill; }
            set { _hoverFill = value; Invalidate(); }
        }

        public Color TextColor
        {
            get { return _textColor; }
            set { _textColor = value; Invalidate(); }
        }

        public Color BorderColor
        {
            get { return _borderColor; }
            set { _borderColor = value; Invalidate(); }
        }

        public int BorderWidth
        {
            get { return _borderWidth; }
            set { _borderWidth = value; Invalidate(); }
        }

        public int CornerRadius
        {
            get { return _radius; }
            set { _radius = value; Invalidate(); }
        }

        public void ApplyStyle()
        {
            switch (_style)
            {
                case ButtonStyle.Secondary:
                    _fill = Theme.Surface;
                    _hoverFill = Color.FromArgb(248, 250, 252);
                    _textColor = Theme.TextPrimary;
                    _borderColor = Theme.BorderStrong;
                    _borderWidth = 1;
                    break;
                case ButtonStyle.Danger:
                    _fill = Theme.DangerSoft;
                    _hoverFill = Color.FromArgb(254, 226, 226);
                    _textColor = Theme.Danger;
                    _borderColor = Theme.DangerBorder;
                    _borderWidth = 1;
                    break;
                case ButtonStyle.Ghost:
                    _fill = Color.Transparent;
                    _hoverFill = Color.FromArgb(241, 245, 249);
                    _textColor = Theme.TextSecondary;
                    _borderColor = Color.Transparent;
                    _borderWidth = 0;
                    break;
                default:
                    _fill = Theme.Accent;
                    _hoverFill = Theme.AccentHover;
                    _textColor = Color.White;
                    _borderColor = Color.Transparent;
                    _borderWidth = 0;
                    break;
            }
            Invalidate();
        }

        protected override void OnMouseEnter(EventArgs e)
        {
            _hover = true;
            Invalidate();
            base.OnMouseEnter(e);
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            _hover = false;
            _pressed = false;
            Invalidate();
            base.OnMouseLeave(e);
        }

        protected override void OnMouseDown(MouseEventArgs mevent)
        {
            _pressed = true;
            Invalidate();
            base.OnMouseDown(mevent);
        }

        protected override void OnMouseUp(MouseEventArgs mevent)
        {
            _pressed = false;
            Invalidate();
            base.OnMouseUp(mevent);
        }

        protected override void OnEnabledChanged(EventArgs e)
        {
            Invalidate();
            base.OnEnabledChanged(e);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(BackColor);

            Rectangle rect = new Rectangle(0, 0, Width - 1, Height - 1);
            if (rect.Width <= 0 || rect.Height <= 0) return;

            Color fill;
            Color text;
            Color border;
            if (!Enabled)
            {
                fill = Color.FromArgb(241, 245, 249);
                text = Theme.TextMuted;
                border = Theme.Border;
            }
            else
            {
                fill = _pressed ? ControlPaint.Dark(_hoverFill, 0.04f) : (_hover ? _hoverFill : _fill);
                text = _textColor;
                border = _borderColor;
            }

            using (GraphicsPath path = Theme.RoundedRect(rect, _radius))
            {
                if (fill.A > 0)
                {
                    using (SolidBrush brush = new SolidBrush(fill)) g.FillPath(brush, path);
                }
                if (_borderWidth > 0 && Enabled)
                {
                    using (Pen pen = new Pen(border, _borderWidth)) g.DrawPath(pen, path);
                }
            }

            TextFormatFlags flags = TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter |
                TextFormatFlags.NoPrefix | TextFormatFlags.EndEllipsis;
            Rectangle textRect = new Rectangle(8, 0, Width - 16, Height);
            TextRenderer.DrawText(g, Text, Font, textRect, text, flags);

            if (Focused && ShowFocusCues)
            {
                Rectangle focus = new Rectangle(4, 4, Width - 9, Height - 9);
                ControlPaint.DrawFocusRectangle(g, focus, text, fill);
            }
        }
    }

    /// <summary>
    /// Etiqueta con forma de píldora para estados.
    /// </summary>
    public class StatusPill : Control
    {
        private Color _fill = Theme.SuccessSoft;
        private Color _textColor = Theme.Success;
        private Color _borderColor = Theme.SuccessBorder;

        public StatusPill()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint |
                ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            BackColor = Theme.Surface;
            Font = Theme.Ui(8.25f, FontStyle.Bold);
            Height = 22;
            Width = 90;
            Text = string.Empty;
        }

        public Color FillColor
        {
            get { return _fill; }
            set { _fill = value; Invalidate(); }
        }

        public Color TextColor
        {
            get { return _textColor; }
            set { _textColor = value; Invalidate(); }
        }

        public Color BorderColor
        {
            get { return _borderColor; }
            set { _borderColor = value; Invalidate(); }
        }

        public void SetState(string text, Color fill, Color textColor, Color border)
        {
            Text = text;
            _fill = fill;
            _textColor = textColor;
            _borderColor = border;
            Width = TextRenderer.MeasureText(text, Font).Width + 22;
            Invalidate();
        }

        protected override void OnTextChanged(EventArgs e)
        {
            Width = TextRenderer.MeasureText(Text, Font).Width + 22;
            Invalidate();
            base.OnTextChanged(e);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(BackColor);
            Rectangle rect = new Rectangle(0, 0, Width - 1, Height - 1);
            if (rect.Width <= 0 || rect.Height <= 0) return;
            using (GraphicsPath path = Theme.RoundedRect(rect, Height / 2))
            {
                using (SolidBrush brush = new SolidBrush(_fill)) g.FillPath(brush, path);
                using (Pen pen = new Pen(_borderColor)) g.DrawPath(pen, path);
            }
            TextRenderer.DrawText(g, Text, Font, rect, _textColor,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix);
        }
    }

    /// <summary>
    /// Cuadrado redondeado con un icono de Segoe MDL2 Assets.
    /// </summary>
    public class IconBadge : Control
    {
        private string _glyph = Theme.GlyphShield;
        private Color _badgeColor = Theme.AccentSoft;
        private Color _glyphColor = Theme.Accent;
        private int _radius = 10;

        public IconBadge()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint |
                ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            BackColor = Theme.Surface;
            Size = new Size(40, 40);
        }

        public string Glyph
        {
            get { return _glyph; }
            set { _glyph = value; Invalidate(); }
        }

        public Color BadgeColor
        {
            get { return _badgeColor; }
            set { _badgeColor = value; Invalidate(); }
        }

        public Color GlyphColor
        {
            get { return _glyphColor; }
            set { _glyphColor = value; Invalidate(); }
        }

        public int CornerRadius
        {
            get { return _radius; }
            set { _radius = value; Invalidate(); }
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(BackColor);
            Rectangle rect = new Rectangle(0, 0, Width - 1, Height - 1);
            if (rect.Width <= 0 || rect.Height <= 0) return;
            using (GraphicsPath path = Theme.RoundedRect(rect, _radius))
            using (SolidBrush brush = new SolidBrush(_badgeColor))
                g.FillPath(brush, path);

            float size = Math.Max(9f, Height * 0.44f);
            using (Font font = Theme.Icon(size))
            using (StringFormat format = new StringFormat())
            {
                format.Alignment = StringAlignment.Center;
                format.LineAlignment = StringAlignment.Center;
                using (SolidBrush brush = new SolidBrush(_glyphColor))
                    g.DrawString(_glyph, font, brush, rect, format);
            }
        }
    }

    /// <summary>
    /// Barra de progreso redondeada con modo indeterminado.
    /// </summary>
    public class ProgressBarEx : Control
    {
        private int _value;
        private bool _indeterminate;
        private readonly Timer _timer;
        private int _offset;
        private Color _accent = Theme.Accent;

        public ProgressBarEx()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint |
                ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            BackColor = Theme.Surface;
            Height = 8;
            _timer = new Timer();
            _timer.Interval = 30;
            _timer.Tick += delegate
            {
                _offset = (_offset + 6) % Math.Max(1, Width + 80);
                Invalidate();
            };
        }

        public int Value
        {
            get { return _value; }
            set
            {
                int clamped = Math.Max(0, Math.Min(100, value));
                if (_value == clamped) return;
                _value = clamped;
                Invalidate();
            }
        }

        public bool IsIndeterminate
        {
            get { return _indeterminate; }
            set
            {
                if (_indeterminate == value) return;
                _indeterminate = value;
                if (value) _timer.Start();
                else _timer.Stop();
                Invalidate();
            }
        }

        public Color AccentColor
        {
            get { return _accent; }
            set { _accent = value; Invalidate(); }
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(BackColor);
            Rectangle track = new Rectangle(0, 0, Width - 1, Height - 1);
            if (track.Width <= 0 || track.Height <= 0) return;

            using (GraphicsPath path = Theme.RoundedRect(track, Height / 2))
            using (SolidBrush brush = new SolidBrush(Color.FromArgb(226, 232, 240)))
                g.FillPath(brush, path);

            if (_indeterminate)
            {
                int barWidth = Math.Max(80, Width / 3);
                int x = _offset - barWidth;
                Rectangle fill = new Rectangle(x, 0, barWidth, Height);
                using (GraphicsPath clip = Theme.RoundedRect(track, Height / 2))
                {
                    Region old = g.Clip;
                    g.SetClip(clip);
                    using (LinearGradientBrush brush = new LinearGradientBrush(
                        new Rectangle(fill.Left - 20, 0, fill.Width + 40, Math.Max(1, Height)),
                        Color.Transparent, _accent, LinearGradientMode.Horizontal))
                    {
                        g.FillRectangle(brush, fill);
                    }
                    g.Clip = old;
                }
            }
            else
            {
                if (_value <= 0) return;
                int width = Math.Max(Height, (int)Math.Round(track.Width * (_value / 100.0)));
                Rectangle fill = new Rectangle(0, 0, Math.Min(width, track.Width), Height);
                using (GraphicsPath path = Theme.RoundedRect(fill, Height / 2))
                using (SolidBrush brush = new SolidBrush(_accent))
                    g.FillPath(brush, path);
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _timer.Dispose();
            base.Dispose(disposing);
        }
    }

    /// <summary>
    /// Enlace de texto con estilo uniforme.
    /// </summary>
    public static class Links
    {
        public static LinkLabel Create(string text, LinkLabelLinkClickedEventHandler onClick)
        {
            LinkLabel link = new LinkLabel();
            link.Text = text;
            link.AutoSize = true;
            link.Font = Theme.Ui(9f, FontStyle.Regular);
            link.LinkColor = Theme.Accent;
            link.ActiveLinkColor = Theme.AccentHover;
            link.VisitedLinkColor = Theme.Accent;
            link.LinkBehavior = LinkBehavior.HoverUnderline;
            link.BackColor = Color.Transparent;
            link.Cursor = Cursors.Hand;
            if (onClick != null) link.LinkClicked += onClick;
            return link;
        }
    }
}
