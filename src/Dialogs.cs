using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ClamGuard
{
    /// <summary>
    /// Ventana modal con el progreso de la descarga e instalación de ClamAV.
    /// </summary>
    public sealed class InstallDialog : Form
    {
        private readonly CancellationTokenSource _cts;
        private readonly Progress<InstallProgress> _progress;
        private ProgressBarEx _bar;
        private Label _lblStage;
        private Label _lblBytes;
        private RoundedButton _btnCancel;
        private bool _completed;

        public InstallDialog()
        {
            _cts = new CancellationTokenSource();
            _progress = new Progress<InstallProgress>(OnProgress);
            BuildUi();
        }

        public Progress<InstallProgress> Progress { get { return _progress; } }
        public CancellationToken Token { get { return _cts.Token; } }

        private void BuildUi()
        {
            Text = "Instalar ClamAV";
            ClientSize = new Size(540, 238);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterParent;
            BackColor = Theme.Surface;
            Font = Theme.Ui(9f, FontStyle.Regular);
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96F, 96F);

            IconBadge badge = new IconBadge();
            badge.Glyph = Theme.GlyphDownload;
            badge.BadgeColor = Theme.AccentSoft;
            badge.GlyphColor = Theme.Accent;
            badge.BackColor = Theme.Surface;
            badge.Size = new Size(44, 44);
            badge.Location = new Point(24, 22);
            Controls.Add(badge);

            Label title = new Label();
            title.Text = "Instalando ClamAV";
            title.Font = Theme.Ui(14f, FontStyle.Bold);
            title.ForeColor = Theme.TextPrimary;
            title.BackColor = Theme.Surface;
            title.AutoSize = true;
            title.Location = new Point(82, 20);
            Controls.Add(title);

            Label subtitle = new Label();
            subtitle.Text = "Se descarga el motor oficial de Cisco Talos y las firmas de virus.";
            subtitle.Font = Theme.Ui(8.75f, FontStyle.Regular);
            subtitle.ForeColor = Theme.TextSecondary;
            subtitle.BackColor = Theme.Surface;
            subtitle.AutoSize = true;
            subtitle.Location = new Point(84, 48);
            Controls.Add(subtitle);

            _lblStage = new Label();
            _lblStage.Text = "Preparando…";
            _lblStage.Font = Theme.Ui(9.25f, FontStyle.Bold);
            _lblStage.ForeColor = Theme.TextPrimary;
            _lblStage.BackColor = Theme.Surface;
            _lblStage.AutoSize = false;
            _lblStage.Location = new Point(26, 96);
            _lblStage.Size = new Size(488, 22);
            Controls.Add(_lblStage);

            _bar = new ProgressBarEx();
            _bar.BackColor = Theme.Surface;
            _bar.Location = new Point(26, 124);
            _bar.Size = new Size(488, 8);
            _bar.IsIndeterminate = true;
            Controls.Add(_bar);

            _lblBytes = new Label();
            _lblBytes.Text = string.Empty;
            _lblBytes.Font = Theme.Ui(8.5f, FontStyle.Regular);
            _lblBytes.ForeColor = Theme.TextMuted;
            _lblBytes.BackColor = Theme.Surface;
            _lblBytes.AutoSize = false;
            _lblBytes.Location = new Point(26, 140);
            _lblBytes.Size = new Size(360, 20);
            Controls.Add(_lblBytes);

            _btnCancel = new RoundedButton();
            _btnCancel.Text = "Cancelar";
            _btnCancel.Style = ButtonStyle.Secondary;
            _btnCancel.BackColor = Theme.Surface;
            _btnCancel.Size = new Size(104, 36);
            _btnCancel.Location = new Point(412, 180);
            _btnCancel.Click += delegate
            {
                _btnCancel.Enabled = false;
                _lblStage.Text = "Cancelando…";
                try { _cts.Cancel(); } catch { }
            };
            Controls.Add(_btnCancel);
            CancelButton = null;
        }

        private void OnProgress(InstallProgress value)
        {
            if (value == null || IsDisposed) return;
            if (!string.IsNullOrEmpty(value.Stage)) _lblStage.Text = value.Stage;
            _bar.IsIndeterminate = value.Indeterminate;
            if (!value.Indeterminate) _bar.Value = value.Percent;

            if (value.BytesTotal > 0)
            {
                _lblBytes.Text = string.Format("{0} de {1}  ({2}%)",
                    ClamAv.FormatBytes(value.BytesReceived),
                    ClamAv.FormatBytes(value.BytesTotal),
                    Math.Min(100, (int)(value.BytesReceived * 100 / value.BytesTotal)));
            }
            else
            {
                _lblBytes.Text = string.Empty;
            }
        }

        public void MarkCompleted()
        {
            _completed = true;
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (!_completed)
            {
                try { _cts.Cancel(); } catch { }
                e.Cancel = true;
                _btnCancel.Enabled = false;
                _lblStage.Text = "Cancelando… espera a que termine la operación en curso.";
                return;
            }
            try { _cts.Dispose(); } catch { }
            base.OnFormClosing(e);
        }
    }

    /// <summary>
    /// Diálogo con las amenazas encontradas en un análisis manual.
    /// </summary>
    public sealed class ThreatDialog : Form
    {
        private readonly ScanResult _result;
        private readonly AppSettings _settings;
        private readonly Action<LogLevel, string> _log;
        private ListView _list;

        public ThreatDialog(ScanResult result, AppSettings settings, Action<LogLevel, string> log)
        {
            _result = result;
            _settings = settings;
            _log = log;
            BuildUi();
        }

        private void BuildUi()
        {
            Text = "Amenazas detectadas";
            ClientSize = new Size(840, 500);
            MinimumSize = new Size(700, 420);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = Theme.Surface;
            Font = Theme.Ui(9f, FontStyle.Regular);
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96F, 96F);
            ShowInTaskbar = false;

            IconBadge badge = new IconBadge();
            badge.Glyph = Theme.GlyphWarning;
            badge.BadgeColor = Theme.DangerSoft;
            badge.GlyphColor = Theme.Danger;
            badge.BackColor = Theme.Surface;
            badge.Size = new Size(46, 46);
            badge.Location = new Point(24, 20);
            Controls.Add(badge);

            Label title = new Label();
            title.Text = "Se encontraron " + _result.Threats.Count + " amenaza(s)";
            title.Font = Theme.Ui(14f, FontStyle.Bold);
            title.ForeColor = Theme.TextPrimary;
            title.BackColor = Theme.Surface;
            title.AutoSize = true;
            title.Location = new Point(84, 18);
            Controls.Add(title);

            Label subtitle = new Label();
            subtitle.Text = "Elige cómo tratar los archivos detectados. La cuarentena permite restaurarlos si es un falso positivo.";
            subtitle.Font = Theme.Ui(8.75f, FontStyle.Regular);
            subtitle.ForeColor = Theme.TextSecondary;
            subtitle.BackColor = Theme.Surface;
            subtitle.AutoSize = false;
            subtitle.Location = new Point(86, 46);
            subtitle.Size = new Size(720, 22);
            Controls.Add(subtitle);

            _list = new ListView();
            _list.View = View.Details;
            _list.FullRowSelect = true;
            _list.GridLines = false;
            _list.HideSelection = false;
            _list.BorderStyle = BorderStyle.FixedSingle;
            _list.Font = Theme.Ui(8.75f, FontStyle.Regular);
            _list.BackColor = Color.White;
            _list.ForeColor = Theme.TextPrimary;
            _list.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            _list.Location = new Point(24, 84);
            _list.Size = new Size(792, 320);
            _list.Columns.Add("Archivo", 560);
            _list.Columns.Add("Firma detectada", 210);
            for (int i = 0; i < _result.Threats.Count; i++)
            {
                ScanThreat threat = _result.Threats[i];
                ListViewItem item = new ListViewItem(threat.Path);
                item.SubItems.Add(threat.Signature);
                _list.Items.Add(item);
            }
            Controls.Add(_list);

            Label note = new Label();
            note.Text = "Los archivos en cuarentena se guardan cifrados y no pueden ejecutarse.";
            note.Font = Theme.Ui(8.25f, FontStyle.Regular);
            note.ForeColor = Theme.TextMuted;
            note.BackColor = Theme.Surface;
            note.AutoSize = true;
            note.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
            note.Location = new Point(24, 418);
            Controls.Add(note);

            Panel buttons = new Panel();
            buttons.Dock = DockStyle.Bottom;
            buttons.Height = 64;
            buttons.BackColor = Theme.Surface;
            Controls.Add(buttons);
            buttons.BringToFront();

            RoundedButton close = new RoundedButton();
            close.Text = "Cerrar";
            close.Style = ButtonStyle.Secondary;
            close.BackColor = Theme.Surface;
            close.Size = new Size(96, 36);
            close.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            close.Location = new Point(buttons.Width - 96 - 24, 14);
            close.Click += delegate { Close(); };
            buttons.Controls.Add(close);

            RoundedButton delete = new RoundedButton();
            delete.Text = "Eliminar";
            delete.Style = ButtonStyle.Danger;
            delete.BackColor = Theme.Surface;
            delete.Size = new Size(110, 36);
            delete.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            delete.Location = new Point(close.Left - 110 - 10, 14);
            delete.Click += DeleteAll_Click;
            buttons.Controls.Add(delete);

            RoundedButton quarantine = new RoundedButton();
            quarantine.Text = "Poner en cuarentena";
            quarantine.Style = ButtonStyle.Primary;
            quarantine.BackColor = Theme.Surface;
            quarantine.Size = new Size(176, 36);
            quarantine.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            quarantine.Location = new Point(delete.Left - 176 - 10, 14);
            quarantine.Click += QuarantineAll_Click;
            buttons.Controls.Add(quarantine);

            buttons.Resize += delegate
            {
                close.Left = buttons.Width - close.Width - 24;
                delete.Left = close.Left - delete.Width - 10;
                quarantine.Left = delete.Left - quarantine.Width - 10;
            };
        }

        private void QuarantineAll_Click(object sender, EventArgs e)
        {
            int ok = 0;
            int failed = 0;
            Cursor = Cursors.WaitCursor;
            try
            {
                for (int i = 0; i < _result.Threats.Count; i++)
                {
                    ScanThreat threat = _result.Threats[i];
                    QuarantineResult result = QuarantineStore.QuarantineFile(threat.Path, threat.Signature);
                    if (result.Success)
                    {
                        ok++;
                        if (_log != null) _log(LogLevel.Ok, "En cuarentena: " + threat.Path);
                    }
                    else
                    {
                        failed++;
                        if (_log != null) _log(LogLevel.Error, "No se pudo poner en cuarentena " + threat.Path + ": " + result.Error);
                    }
                }
            }
            finally
            {
                Cursor = Cursors.Default;
            }

            string message = ok + " archivo(s) en cuarentena.";
            if (failed > 0) message += "\n" + failed + " archivo(s) no se pudieron mover. Revisa el registro.";
            MessageBox.Show(this, message, "Cuarentena", MessageBoxButtons.OK,
                failed > 0 ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
            if (failed == 0) DialogResult = DialogResult.OK;
            Close();
        }

        private void DeleteAll_Click(object sender, EventArgs e)
        {
            DialogResult confirm = MessageBox.Show(this,
                "Se eliminarán definitivamente " + _result.Threats.Count + " archivo(s). Esta acción no se puede deshacer.\n\n¿Continuar?",
                "Eliminar amenazas", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
            if (confirm != DialogResult.Yes) return;

            int ok = 0;
            int failed = 0;
            Cursor = Cursors.WaitCursor;
            try
            {
                for (int i = 0; i < _result.Threats.Count; i++)
                {
                    ScanThreat threat = _result.Threats[i];
                    bool scheduled;
                    string error;
                    bool deleted = QuarantineStore.DeleteFilePermanently(threat.Path, out scheduled, out error);
                    if (deleted)
                    {
                        ok++;
                        if (_log != null) _log(LogLevel.Ok, (scheduled ? "Se eliminará al reiniciar: " : "Eliminado: ") + threat.Path);
                    }
                    else
                    {
                        failed++;
                        if (_log != null) _log(LogLevel.Error, "No se pudo eliminar " + threat.Path + ": " + error);
                    }
                }
            }
            finally
            {
                Cursor = Cursors.Default;
            }

            string message = ok + " archivo(s) eliminados.";
            if (failed > 0) message += "\n" + failed + " archivo(s) no se pudieron eliminar. Revisa el registro.";
            MessageBox.Show(this, message, "Eliminar amenazas", MessageBoxButtons.OK,
                failed > 0 ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
            if (failed == 0) DialogResult = DialogResult.OK;
            Close();
        }
    }

    /// <summary>
    /// Gestor de archivos en cuarentena.
    /// </summary>
    public sealed class QuarantineDialog : Form
    {
        private ListView _list;
        private Label _empty;
        private Label _subtitle;

        public QuarantineDialog()
        {
            BuildUi();
            LoadEntries();
        }

        private void BuildUi()
        {
            Text = "Cuarentena";
            ClientSize = new Size(920, 560);
            MinimumSize = new Size(760, 440);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = Theme.Surface;
            Font = Theme.Ui(9f, FontStyle.Regular);
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96F, 96F);
            ShowInTaskbar = false;

            IconBadge badge = new IconBadge();
            badge.Glyph = Theme.GlyphLock;
            badge.BadgeColor = Theme.AccentSoft;
            badge.GlyphColor = Theme.Accent;
            badge.BackColor = Theme.Surface;
            badge.Size = new Size(44, 44);
            badge.Location = new Point(24, 20);
            Controls.Add(badge);

            Label title = new Label();
            title.Text = "Archivos en cuarentena";
            title.Font = Theme.Ui(14f, FontStyle.Bold);
            title.ForeColor = Theme.TextPrimary;
            title.BackColor = Theme.Surface;
            title.AutoSize = true;
            title.Location = new Point(82, 18);
            Controls.Add(title);

            _subtitle = new Label();
            _subtitle.Font = Theme.Ui(8.75f, FontStyle.Regular);
            _subtitle.ForeColor = Theme.TextSecondary;
            _subtitle.BackColor = Theme.Surface;
            _subtitle.AutoSize = true;
            _subtitle.Location = new Point(84, 46);
            Controls.Add(_subtitle);

            _list = new ListView();
            _list.View = View.Details;
            _list.FullRowSelect = true;
            _list.GridLines = false;
            _list.HideSelection = false;
            _list.BorderStyle = BorderStyle.FixedSingle;
            _list.Font = Theme.Ui(8.75f, FontStyle.Regular);
            _list.BackColor = Color.White;
            _list.ForeColor = Theme.TextPrimary;
            _list.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            _list.Location = new Point(24, 82);
            _list.Size = new Size(872, 392);
            _list.Columns.Add("Fecha", 118);
            _list.Columns.Add("Amenaza", 210);
            _list.Columns.Add("Archivo original", 440);
            _list.Columns.Add("Tamaño", 80, HorizontalAlignment.Right);
            Controls.Add(_list);

            _empty = new Label();
            _empty.Text = "No hay archivos en cuarentena.";
            _empty.Font = Theme.Ui(10f, FontStyle.Regular);
            _empty.ForeColor = Theme.TextMuted;
            _empty.BackColor = Color.White;
            _empty.TextAlign = ContentAlignment.MiddleCenter;
            _empty.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            _empty.Location = new Point(25, 83);
            _empty.Size = new Size(870, 390);
            _empty.Visible = false;
            Controls.Add(_empty);
            _empty.BringToFront();

            Panel buttons = new Panel();
            buttons.Dock = DockStyle.Bottom;
            buttons.Height = 64;
            buttons.BackColor = Theme.Surface;
            Controls.Add(buttons);
            buttons.BringToFront();

            RoundedButton close = new RoundedButton();
            close.Text = "Cerrar";
            close.Style = ButtonStyle.Secondary;
            close.BackColor = Theme.Surface;
            close.Size = new Size(96, 36);
            close.Location = new Point(ClientSize.Width - 96 - 24, 14);
            close.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            close.Click += delegate { Close(); };
            buttons.Controls.Add(close);

            RoundedButton restore = new RoundedButton();
            restore.Text = "Restaurar";
            restore.Style = ButtonStyle.Secondary;
            restore.BackColor = Theme.Surface;
            restore.Size = new Size(110, 36);
            restore.Location = new Point(close.Left - 110 - 10, 14);
            restore.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            restore.Click += Restore_Click;
            buttons.Controls.Add(restore);

            RoundedButton delete = new RoundedButton();
            delete.Text = "Eliminar";
            delete.Style = ButtonStyle.Danger;
            delete.BackColor = Theme.Surface;
            delete.Size = new Size(110, 36);
            delete.Location = new Point(restore.Left - 110 - 10, 14);
            delete.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            delete.Click += Delete_Click;
            buttons.Controls.Add(delete);

            RoundedButton refresh = new RoundedButton();
            refresh.Text = "Actualizar";
            refresh.Style = ButtonStyle.Ghost;
            refresh.BackColor = Theme.Surface;
            refresh.Size = new Size(100, 36);
            refresh.Location = new Point(24, 14);
            refresh.Click += delegate { LoadEntries(); };
            buttons.Controls.Add(refresh);

            buttons.Resize += delegate
            {
                close.Left = buttons.Width - close.Width - 24;
                restore.Left = close.Left - restore.Width - 10;
                delete.Left = restore.Left - delete.Width - 10;
            };

            _list.DoubleClick += delegate { Restore_Click(null, EventArgs.Empty); };
        }

        private void LoadEntries()
        {
            List<QuarantineEntry> entries = QuarantineStore.List();
            _list.BeginUpdate();
            try
            {
                _list.Items.Clear();
                for (int i = 0; i < entries.Count; i++)
                {
                    QuarantineEntry entry = entries[i];
                    ListViewItem item = new ListViewItem(entry.DateText);
                    item.SubItems.Add(entry.ThreatName);
                    item.SubItems.Add(entry.OriginalPath);
                    item.SubItems.Add(entry.SizeText);
                    item.Tag = entry;
                    _list.Items.Add(item);
                }
            }
            finally
            {
                _list.EndUpdate();
            }

            _subtitle.Text = entries.Count == 0
                ? "Ningún archivo aislado."
                : entries.Count + " archivo(s) aislado(s). Los archivos están cifrados en disco.";
            _empty.Visible = entries.Count == 0;
        }

        private QuarantineEntry SelectedEntry()
        {
            if (_list.SelectedItems.Count == 0) return null;
            return _list.SelectedItems[0].Tag as QuarantineEntry;
        }

        private void Restore_Click(object sender, EventArgs e)
        {
            QuarantineEntry entry = SelectedEntry();
            if (entry == null)
            {
                MessageBox.Show(this, "Selecciona un archivo de la lista.", "Cuarentena",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            DialogResult confirm = MessageBox.Show(this,
                "Se restaurará el archivo a:\n" + entry.OriginalPath + "\n\n" +
                "Si se trata de un falso positivo, quizá debas excluirlo del análisis. ¿Continuar?",
                "Restaurar archivo", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
            if (confirm != DialogResult.Yes) return;

            string error;
            bool ok = QuarantineStore.Restore(entry, false, out error);
            if (!ok && error.IndexOf("Ya existe", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                DialogResult overwrite = MessageBox.Show(this,
                    "Ya existe un archivo en la ruta original. ¿Sobrescribirlo?",
                    "Restaurar archivo", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
                if (overwrite == DialogResult.Yes)
                    ok = QuarantineStore.Restore(entry, true, out error);
            }

            if (ok)
            {
                MessageBox.Show(this, "Archivo restaurado correctamente.", "Cuarentena",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                LoadEntries();
            }
            else
            {
                MessageBox.Show(this, error, "Restaurar archivo", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void Delete_Click(object sender, EventArgs e)
        {
            QuarantineEntry entry = SelectedEntry();
            if (entry == null)
            {
                MessageBox.Show(this, "Selecciona un archivo de la lista.", "Cuarentena",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            DialogResult confirm = MessageBox.Show(this,
                "Se eliminará permanentemente la copia en cuarentena de:\n" + entry.OriginalPath + "\n\n¿Continuar?",
                "Eliminar de la cuarentena", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
            if (confirm != DialogResult.Yes) return;

            string error;
            if (QuarantineStore.DeleteEntry(entry, out error))
            {
                LoadEntries();
            }
            else
            {
                MessageBox.Show(this, error, "Cuarentena", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }

    /// <summary>
    /// Configuración de ClamGuard.
    /// </summary>
    /// <summary>
    /// Desinstalación completa: programa, servicio, motor ClamAV, datos,
    /// registros y cuarentena.
    /// </summary>
    public sealed class UninstallDialog : Form
    {
        private readonly AppSettings _settings;
        private readonly string _engineDir;
        private readonly string _productCode;
        private CheckBox _chkService;
        private CheckBox _chkEngine;
        private CheckBox _chkData;
        private CheckBox _chkQuarantine;
        private CheckBox _chkAppFiles;
        private Label _lblFootprint;
        private Label _lblStage;
        private ProgressBarEx _bar;
        private RoundedButton _btnCancel;
        private RoundedButton _btnUninstall;
        private bool _engineAvailable;
        private bool _running;
        private bool _completed;

        public UninstallDialog(AppSettings settings)
        {
            _settings = settings == null ? AppSettings.Load() : settings;
            _engineDir = AppPaths.FindClamAvDirectory(_settings.ClamAvDirectory);
            _productCode = Uninstaller.FindClamAvProductCode();
            BuildUi();
        }

        public bool Completed { get { return _completed; } }

        private void BuildUi()
        {
            Text = "Desinstalar ClamGuard";
            ClientSize = new Size(720, 630);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterParent;
            BackColor = Theme.Surface;
            Font = Theme.Ui(9f, FontStyle.Regular);
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96F, 96F);

            IconBadge badge = new IconBadge();
            badge.Glyph = Theme.GlyphWarning;
            badge.BadgeColor = Theme.DangerSoft;
            badge.GlyphColor = Theme.Danger;
            badge.BackColor = Theme.Surface;
            badge.Size = new Size(44, 44);
            badge.Location = new Point(24, 20);
            Controls.Add(badge);

            Label title = new Label();
            title.Text = "Desinstalar ClamGuard";
            title.Font = Theme.Ui(14f, FontStyle.Bold);
            title.ForeColor = Theme.TextPrimary;
            title.BackColor = Theme.Surface;
            title.AutoSize = true;
            title.Location = new Point(82, 16);
            Controls.Add(title);

            Label subtitle = new Label();
            subtitle.Text = "Elimina el programa, el motor ClamAV y los archivos que deja en el equipo.";
            subtitle.Font = Theme.Ui(8.75f, FontStyle.Regular);
            subtitle.ForeColor = Theme.TextSecondary;
            subtitle.BackColor = Theme.Surface;
            subtitle.AutoSize = true;
            subtitle.Location = new Point(84, 44);
            Controls.Add(subtitle);

            CardPanel warning = new CardPanel();
            warning.FillColor = Theme.DangerSoft;
            warning.BorderColor = Theme.DangerBorder;
            warning.BackColor = Theme.Surface;
            warning.CornerRadius = 10;
            warning.Location = new Point(24, 86);
            warning.Size = new Size(672, 82);
            Controls.Add(warning);

            Label warningTitle = new Label();
            warningTitle.Text = "Esta acción no se puede deshacer";
            warningTitle.Font = Theme.Ui(9.5f, FontStyle.Bold);
            warningTitle.ForeColor = Theme.Danger;
            warningTitle.BackColor = Theme.DangerSoft;
            warningTitle.AutoSize = true;
            warningTitle.Location = new Point(16, 12);
            warning.Controls.Add(warningTitle);

            Label warningText = new Label();
            warningText.Text = "La cuarentena puede contener archivos maliciosos. Si necesitas conservarlos, " +
                "restáuralos antes de continuar. La eliminación de la cuarentena es permanente.";
            warningText.Font = Theme.Ui(8.5f, FontStyle.Regular);
            warningText.ForeColor = Theme.TextSecondary;
            warningText.BackColor = Theme.DangerSoft;
            warningText.AutoSize = false;
            warningText.Location = new Point(16, 34);
            warningText.Size = new Size(640, 40);
            warning.Controls.Add(warningText);

            Label section = new Label();
            section.Text = "Qué se eliminará";
            section.Font = Theme.Ui(10f, FontStyle.Bold);
            section.ForeColor = Theme.TextPrimary;
            section.BackColor = Theme.Surface;
            section.AutoSize = true;
            section.Location = new Point(24, 184);
            Controls.Add(section);

            bool serviceInstalled = ResidentService.IsInstalled();
            _chkService = MakeCheck(
                serviceInstalled
                    ? "Servicio residente: detenerlo y quitar el arranque automático (obligatorio)."
                    : "Servicio residente: no está instalado (se omite).",
                212, true);
            _chkService.Checked = true;
            _chkService.Enabled = false;
            Controls.Add(_chkService);

            _engineAvailable = !string.IsNullOrEmpty(_productCode) ||
                !string.IsNullOrEmpty(_engineDir);
            _chkEngine = MakeCheck(
                _engineAvailable
                    ? "Motor ClamAV: desinstalarlo con su instalador oficial (MSI)."
                    : "Motor ClamAV: no se detectó una instalación.",
                240, _engineAvailable);
            Controls.Add(_chkEngine);

            _chkData = MakeCheck(
                "Registros, firmas, configuración, descargas y carpeta de datos.",
                268, true);
            Controls.Add(_chkData);

            int quarantineCount = Uninstaller.QuarantineCount();
            _chkQuarantine = MakeCheck(
                "Cuarentena: " + quarantineCount + " archivo(s) cifrado(s).",
                296, true);
            Controls.Add(_chkQuarantine);

            _chkAppFiles = MakeCheck(
                "Archivos del programa: ClamGuard.exe, README y paquete ZIP.",
                324, true);
            Controls.Add(_chkAppFiles);

            _lblFootprint = new Label();
            _lblFootprint.Font = Theme.Ui(8.5f, FontStyle.Regular);
            _lblFootprint.ForeColor = Theme.TextMuted;
            _lblFootprint.BackColor = Theme.Surface;
            _lblFootprint.AutoSize = false;
            _lblFootprint.Location = new Point(24, 360);
            _lblFootprint.Size = new Size(672, 52);
            Controls.Add(_lblFootprint);
            UpdateFootprint();

            _lblStage = new Label();
            _lblStage.Text = "Preparando…";
            _lblStage.Font = Theme.Ui(9.25f, FontStyle.Bold);
            _lblStage.ForeColor = Theme.TextPrimary;
            _lblStage.BackColor = Theme.Surface;
            _lblStage.AutoSize = false;
            _lblStage.Location = new Point(24, 426);
            _lblStage.Size = new Size(672, 22);
            _lblStage.Visible = false;
            Controls.Add(_lblStage);

            _bar = new ProgressBarEx();
            _bar.BackColor = Theme.Surface;
            _bar.Location = new Point(24, 452);
            _bar.Size = new Size(672, 8);
            _bar.IsIndeterminate = true;
            _bar.Visible = false;
            Controls.Add(_bar);

            Label note = new Label();
            note.Text = "Al continuar se cerrará ClamGuard. Los archivos que estén en uso se " +
                "borrarán mediante un proceso auxiliar después del cierre.";
            note.Font = Theme.Ui(8.5f, FontStyle.Regular);
            note.ForeColor = Theme.TextMuted;
            note.BackColor = Theme.Surface;
            note.AutoSize = false;
            note.Location = new Point(24, 476);
            note.Size = new Size(672, 40);
            Controls.Add(note);

            _btnCancel = new RoundedButton();
            _btnCancel.Text = "Cancelar";
            _btnCancel.Style = ButtonStyle.Secondary;
            _btnCancel.BackColor = Theme.Surface;
            _btnCancel.Size = new Size(104, 38);
            _btnCancel.Location = new Point(424, 552);
            _btnCancel.Click += delegate { Close(); };
            Controls.Add(_btnCancel);

            _btnUninstall = new RoundedButton();
            _btnUninstall.Text = "Desinstalar todo";
            _btnUninstall.Style = ButtonStyle.Danger;
            _btnUninstall.BackColor = Theme.Surface;
            _btnUninstall.Size = new Size(168, 38);
            _btnUninstall.Location = new Point(528, 552);
            _btnUninstall.Click += Uninstall_Click;
            Controls.Add(_btnUninstall);

            CancelButton = _btnCancel;
        }

        private CheckBox MakeCheck(string text, int top, bool enabled)
        {
            CheckBox box = new CheckBox();
            box.Text = text;
            box.Font = Theme.Ui(9f, FontStyle.Regular);
            box.ForeColor = enabled ? Theme.TextPrimary : Theme.TextMuted;
            box.BackColor = Theme.Surface;
            box.AutoSize = false;
            box.Size = new Size(672, 24);
            box.Location = new Point(24, top);
            box.Checked = enabled;
            box.Enabled = enabled;
            return box;
        }

        private void UpdateFootprint()
        {
            long dataSize = Uninstaller.DirectorySize(AppPaths.DataDir);
            long appSize = Uninstaller.EstimateAppSize();
            long engineSize = _engineDir == null ? 0 : Uninstaller.DirectorySize(_engineDir);
            int quarantine = Uninstaller.QuarantineCount();

            string engineText = _engineDir == null
                ? "no detectado"
                : _engineDir + (engineSize > 0 ? " (" + ClamAv.FormatBytes(engineSize) + ")" : string.Empty);

            _lblFootprint.Text =
                "Datos: " + ClamAv.FormatBytes(dataSize) +
                "  ·  Cuarentena: " + quarantine + " archivo(s)" +
                "  ·  Programa: " + ClamAv.FormatBytes(appSize) + Environment.NewLine +
                "Motor: " + engineText;

            if (Uninstaller.IsTestMode)
                _lblFootprint.Text += Environment.NewLine +
                    "Modo de prueba: no se modificarán el servicio, Windows Defender, el motor ni los archivos del programa.";
            else if (Uninstaller.IsDevelopmentTree())
                _lblFootprint.Text += Environment.NewLine +
                    "Carpeta de desarrollo detectada: los archivos del programa no se borrarán automáticamente.";
        }

        private async void Uninstall_Click(object sender, EventArgs e)
        {
            if (_running) return;

            UninstallOptions options = new UninstallOptions();
            options.RemoveService = true;
            options.RemoveEngine = _chkEngine.Checked;
            options.RemoveData = _chkData.Checked;
            options.RemoveQuarantine = _chkQuarantine.Checked;
            options.RemoveAppFiles = _chkAppFiles.Checked;

            string message = "Se eliminarán los elementos seleccionados y ClamGuard se cerrará.\n\n";
            if (options.RemoveQuarantine && Uninstaller.QuarantineCount() > 0)
                message += "La cuarentena contiene archivos cifrados que se borrarán de forma permanente.\n\n";
            if (options.RemoveEngine)
                message += "Si ClamAV ya estaba instalado antes de ClamGuard, también se desinstalará.\n\n";
            message += "¿Deseas continuar?";

            DialogResult confirm = MessageBox.Show(this, message, "Confirmar desinstalación",
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
            if (confirm != DialogResult.Yes) return;

            _running = true;
            SetRunning(true);

            UninstallReport report = null;
            try
            {
                Progress<UninstallProgress> progress = new Progress<UninstallProgress>(OnProgress);
                report = await Task.Run(delegate
                {
                    return Uninstaller.Run(options, _settings, progress, CancellationToken.None,
                        new Action<LogLevel, string>(Log));
                });
            }
            catch (Exception ex)
            {
                report = new UninstallReport();
                report.AddError("Error inesperado: " + ex.Message);
            }

            SetRunning(false);
            _running = false;

            string text = report == null
                ? "No se pudo completar la desinstalación."
                : report.ToMessage();
            MessageBox.Show(this, text,
                report != null && report.Success ? "Desinstalación completada" : "Desinstalación con avisos",
                MessageBoxButtons.OK,
                report != null && report.Success ? MessageBoxIcon.Information : MessageBoxIcon.Warning);

            _completed = report != null && report.Errors.Count == 0;
            DialogResult = _completed ? DialogResult.OK : DialogResult.Cancel;
            Close();
        }

        private void SetRunning(bool running)
        {
            _chkEngine.Enabled = !running && _engineAvailable;
            _chkData.Enabled = !running;
            _chkQuarantine.Enabled = !running;
            _chkAppFiles.Enabled = !running;
            _btnCancel.Enabled = !running;
            _btnUninstall.Enabled = !running;
            _lblStage.Visible = running;
            _bar.Visible = running;
            Cursor = running ? Cursors.WaitCursor : Cursors.Default;
            if (running) _bar.IsIndeterminate = true;
        }

        private void OnProgress(UninstallProgress value)
        {
            if (value == null || IsDisposed) return;
            if (!string.IsNullOrEmpty(value.Stage)) _lblStage.Text = value.Stage;
            _bar.IsIndeterminate = value.Indeterminate;
            if (!value.Indeterminate) _bar.Value = value.Percent;
        }

        private void Log(LogLevel level, string message)
        {
            try { AppLog.Write(level, message); } catch { }
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (_running)
            {
                e.Cancel = true;
                return;
            }
            base.OnFormClosing(e);
        }
    }

    public sealed class SettingsDialog : Form
    {
        private readonly AppSettings _settings;
        private TextBox _txtClamDir;
        private Label _lblEngineInfo;
        private CheckBox _chkOnAccess;
        private CheckBox _chkRemovable;
        private CheckBox _chkPauseDefender;
        private ComboBox _cboAction;
        private NumericUpDown _numInterval;
        private NumericUpDown _numPort;
        private ListBox _lstMonitor;
        private ListBox _lstQuick;
        private Label _lblServiceState;
        private bool _requestUninstall;

        public SettingsDialog(AppSettings settings)
        {
            _settings = settings;
            BuildUi();
        }

        /// <summary>
        /// Indica que el usuario pidió abrir la desinstalación completa. La
        /// ventana principal la muestra al cerrarse este diálogo.
        /// </summary>
        public bool RequestUninstall { get { return _requestUninstall; } }

        private void BuildUi()
        {
            Text = "Configuración de ClamGuard";
            ClientSize = new Size(820, 660);
            MinimumSize = new Size(740, 600);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = Theme.Surface;
            Font = Theme.Ui(9f, FontStyle.Regular);
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96F, 96F);
            ShowInTaskbar = false;

            TabControl tabs = new TabControl();
            tabs.Dock = DockStyle.Fill;
            tabs.Font = Theme.Ui(9f, FontStyle.Regular);
            tabs.Padding = new Point(14, 5);
            Controls.Add(tabs);

            TabPage general = new TabPage("General");
            general.BackColor = Theme.Surface;
            general.Padding = new Padding(18);
            tabs.TabPages.Add(general);
            BuildGeneralTab(general);

            TabPage folders = new TabPage("Carpetas");
            folders.BackColor = Theme.Surface;
            folders.Padding = new Padding(18);
            tabs.TabPages.Add(folders);
            BuildFoldersTab(folders);

            TabPage maintenance = new TabPage("Mantenimiento");
            maintenance.BackColor = Theme.Surface;
            maintenance.Padding = new Padding(18);
            tabs.TabPages.Add(maintenance);
            BuildMaintenanceTab(maintenance);

            Panel bottom = new Panel();
            bottom.Dock = DockStyle.Bottom;
            bottom.Height = 60;
            bottom.BackColor = Theme.Surface;
            Controls.Add(bottom);
            bottom.BringToFront();

            Label hint = new Label();
            hint.Text = "Los cambios se guardan en " + AppPaths.DataDir;
            hint.Font = Theme.Ui(8.25f, FontStyle.Regular);
            hint.ForeColor = Theme.TextMuted;
            hint.BackColor = Theme.Surface;
            hint.AutoSize = true;
            hint.Location = new Point(18, 20);
            bottom.Controls.Add(hint);

            RoundedButton save = new RoundedButton();
            save.Text = "Guardar";
            save.Style = ButtonStyle.Primary;
            save.BackColor = Theme.Surface;
            save.Size = new Size(112, 36);
            save.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            save.Location = new Point(bottom.Width - 112 - 18, 12);
            save.Click += Save_Click;
            bottom.Controls.Add(save);
            AcceptButton = save;

            RoundedButton cancel = new RoundedButton();
            cancel.Text = "Cancelar";
            cancel.Style = ButtonStyle.Secondary;
            cancel.BackColor = Theme.Surface;
            cancel.Size = new Size(112, 36);
            cancel.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            cancel.Location = new Point(save.Left - 112 - 8, 12);
            cancel.Click += delegate { DialogResult = DialogResult.Cancel; Close(); };
            bottom.Controls.Add(cancel);
            CancelButton = cancel;

            bottom.Resize += delegate
            {
                save.Left = bottom.Width - save.Width - 18;
                cancel.Left = save.Left - cancel.Width - 8;
            };
        }

        private void BuildGeneralTab(TabPage page)
        {
            Label motor = SectionLabel("Motor antivirus", 0);
            page.Controls.Add(motor);

            Label motorInfo = new Label();
            motorInfo.Text = "Carpeta donde está instalado ClamAV (clamscan.exe, clamd.exe y freshclam.exe).";
            motorInfo.Font = Theme.Ui(8.5f, FontStyle.Regular);
            motorInfo.ForeColor = Theme.TextSecondary;
            motorInfo.BackColor = Theme.Surface;
            motorInfo.AutoSize = false;
            motorInfo.Location = new Point(0, 26);
            motorInfo.Size = new Size(740, 20);
            page.Controls.Add(motorInfo);

            _txtClamDir = new TextBox();
            _txtClamDir.Text = _settings.ClamAvDirectory;
            _txtClamDir.Font = Theme.Ui(9f, FontStyle.Regular);
            _txtClamDir.Location = new Point(0, 50);
            _txtClamDir.Width = 540;
            page.Controls.Add(_txtClamDir);

            RoundedButton browse = new RoundedButton();
            browse.Text = "Examinar…";
            browse.Style = ButtonStyle.Secondary;
            browse.BackColor = Theme.Surface;
            browse.Size = new Size(96, 30);
            browse.Location = new Point(548, 48);
            browse.Click += delegate
            {
                using (FolderBrowserDialog dialog = new FolderBrowserDialog())
                {
                    dialog.Description = "Carpeta de instalación de ClamAV";
                    dialog.ShowNewFolderButton = false;
                    if (Directory.Exists(_txtClamDir.Text)) dialog.SelectedPath = _txtClamDir.Text;
                    if (dialog.ShowDialog(this) == DialogResult.OK) _txtClamDir.Text = dialog.SelectedPath;
                }
            };
            page.Controls.Add(browse);

            RoundedButton detect = new RoundedButton();
            detect.Text = "Detectar";
            detect.Style = ButtonStyle.Ghost;
            detect.BackColor = Theme.Surface;
            detect.Size = new Size(84, 30);
            detect.Location = new Point(650, 48);
            detect.Click += delegate
            {
                string found = AppPaths.FindClamAvDirectory(null);
                if (found == null)
                {
                    MessageBox.Show(this, "No se encontró ClamAV en las ubicaciones habituales.",
                        "Detectar ClamAV", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    _txtClamDir.Text = found;
                }
            };
            page.Controls.Add(detect);

            _lblEngineInfo = new Label();
            _lblEngineInfo.Font = Theme.Ui(8.5f, FontStyle.Regular);
            _lblEngineInfo.ForeColor = Theme.TextMuted;
            _lblEngineInfo.BackColor = Theme.Surface;
            _lblEngineInfo.AutoSize = false;
            _lblEngineInfo.Location = new Point(0, 84);
            _lblEngineInfo.Size = new Size(740, 20);
            UpdateEngineInfo();
            page.Controls.Add(_lblEngineInfo);

            page.Controls.Add(Divider(118));

            Label protection = SectionLabel("Protección", 140);
            page.Controls.Add(protection);

            _chkOnAccess = new CheckBox();
            _chkOnAccess.Text = "Analizar archivos nuevos o modificados en tiempo real (requiere el residente).";
            _chkOnAccess.Checked = _settings.OnAccessEnabled;
            _chkOnAccess.Font = Theme.Ui(9f, FontStyle.Regular);
            _chkOnAccess.ForeColor = Theme.TextPrimary;
            _chkOnAccess.BackColor = Theme.Surface;
            _chkOnAccess.AutoSize = true;
            _chkOnAccess.Location = new Point(0, 168);
            page.Controls.Add(_chkOnAccess);

            _chkRemovable = new CheckBox();
            _chkRemovable.Text = "Analizar unidades extraíbles (USB) al conectarlas.";
            _chkRemovable.Checked = _settings.ScanRemovableDrives;
            _chkRemovable.Font = Theme.Ui(9f, FontStyle.Regular);
            _chkRemovable.ForeColor = Theme.TextPrimary;
            _chkRemovable.BackColor = Theme.Surface;
            _chkRemovable.AutoSize = true;
            _chkRemovable.Location = new Point(0, 194);
            page.Controls.Add(_chkRemovable);

            _chkPauseDefender = new CheckBox();
            _chkPauseDefender.Text = "Pausar Windows Defender mientras el residente esté activo (se reactiva al detenerlo).";
            _chkPauseDefender.Checked = _settings.PauseDefender;
            _chkPauseDefender.Font = Theme.Ui(9f, FontStyle.Regular);
            _chkPauseDefender.ForeColor = Theme.TextPrimary;
            _chkPauseDefender.BackColor = Theme.Surface;
            _chkPauseDefender.AutoSize = true;
            _chkPauseDefender.Location = new Point(0, 220);
            page.Controls.Add(_chkPauseDefender);

            Label actionLabel = new Label();
            actionLabel.Text = "Cuando se detecte una amenaza:";
            actionLabel.Font = Theme.Ui(9f, FontStyle.Regular);
            actionLabel.ForeColor = Theme.TextPrimary;
            actionLabel.BackColor = Theme.Surface;
            actionLabel.AutoSize = true;
            actionLabel.Location = new Point(0, 258);
            page.Controls.Add(actionLabel);

            _cboAction = new ComboBox();
            _cboAction.DropDownStyle = ComboBoxStyle.DropDownList;
            _cboAction.Font = Theme.Ui(9f, FontStyle.Regular);
            _cboAction.Items.Add("Poner en cuarentena (recomendado)");
            _cboAction.Items.Add("Eliminar permanentemente");
            _cboAction.SelectedIndex = _settings.IsDeletePolicy ? 1 : 0;
            _cboAction.Location = new Point(232, 254);
            _cboAction.Width = 260;
            page.Controls.Add(_cboAction);

            Label intervalLabel = new Label();
            intervalLabel.Text = "Comprobar firmas cada:";
            intervalLabel.Font = Theme.Ui(9f, FontStyle.Regular);
            intervalLabel.ForeColor = Theme.TextPrimary;
            intervalLabel.BackColor = Theme.Surface;
            intervalLabel.AutoSize = true;
            intervalLabel.Location = new Point(0, 298);
            page.Controls.Add(intervalLabel);

            _numInterval = new NumericUpDown();
            _numInterval.Minimum = 1;
            _numInterval.Maximum = 168;
            _numInterval.Value = Math.Max(1, Math.Min(168, _settings.UpdateIntervalHours));
            _numInterval.Font = Theme.Ui(9f, FontStyle.Regular);
            _numInterval.Location = new Point(232, 294);
            _numInterval.Width = 70;
            page.Controls.Add(_numInterval);

            Label hours = new Label();
            hours.Text = "horas";
            hours.Font = Theme.Ui(9f, FontStyle.Regular);
            hours.ForeColor = Theme.TextSecondary;
            hours.BackColor = Theme.Surface;
            hours.AutoSize = true;
            hours.Location = new Point(308, 298);
            page.Controls.Add(hours);

            Label portLabel = new Label();
            portLabel.Text = "Puerto local de clamd:";
            portLabel.Font = Theme.Ui(9f, FontStyle.Regular);
            portLabel.ForeColor = Theme.TextPrimary;
            portLabel.BackColor = Theme.Surface;
            portLabel.AutoSize = true;
            portLabel.Location = new Point(0, 336);
            page.Controls.Add(portLabel);

            _numPort = new NumericUpDown();
            _numPort.Minimum = 1024;
            _numPort.Maximum = 65535;
            _numPort.Value = _settings.ClamdPort;
            _numPort.Font = Theme.Ui(9f, FontStyle.Regular);
            _numPort.Location = new Point(232, 332);
            _numPort.Width = 90;
            page.Controls.Add(_numPort);

            Label note = new Label();
            note.Text = "El servicio residente aplica estos cambios automáticamente en unos segundos.\n" +
                "Si Windows Defender tiene la protección contra alteraciones activa, quizá no se pueda pausar; " +
                "en ese caso ClamGuard solo añade exclusiones para sus carpetas.";
            note.Font = Theme.Ui(8.5f, FontStyle.Regular);
            note.ForeColor = Theme.TextMuted;
            note.BackColor = Theme.Surface;
            note.AutoSize = false;
            note.Location = new Point(0, 382);
            note.Size = new Size(740, 36);
            page.Controls.Add(note);
        }

        private void BuildFoldersTab(TabPage page)
        {
            Label monitorLabel = SectionLabel("Protección residente: carpetas vigiladas", 0);
            page.Controls.Add(monitorLabel);

            Label monitorInfo = new Label();
            monitorInfo.Text = "Los archivos nuevos o modificados en estas carpetas se analizan en segundo plano.";
            monitorInfo.Font = Theme.Ui(8.5f, FontStyle.Regular);
            monitorInfo.ForeColor = Theme.TextSecondary;
            monitorInfo.BackColor = Theme.Surface;
            monitorInfo.AutoSize = false;
            monitorInfo.Location = new Point(0, 26);
            monitorInfo.Size = new Size(740, 20);
            page.Controls.Add(monitorInfo);

            _lstMonitor = new ListBox();
            _lstMonitor.Font = Theme.Ui(8.75f, FontStyle.Regular);
            _lstMonitor.Location = new Point(0, 50);
            _lstMonitor.Size = new Size(620, 150);
            _lstMonitor.HorizontalScrollbar = true;
            _lstMonitor.IntegralHeight = false;
            for (int i = 0; i < _settings.MonitorPaths.Count; i++) _lstMonitor.Items.Add(_settings.MonitorPaths[i]);
            page.Controls.Add(_lstMonitor);

            AddFolderButtons(page, _lstMonitor, 48);

            page.Controls.Add(Divider(224));

            Label quickLabel = SectionLabel("Análisis rápido: carpetas habituales", 244);
            page.Controls.Add(quickLabel);

            Label quickInfo = new Label();
            quickInfo.Text = "Rutas que se analizan al pulsar «Análisis rápido».";
            quickInfo.Font = Theme.Ui(8.5f, FontStyle.Regular);
            quickInfo.ForeColor = Theme.TextSecondary;
            quickInfo.BackColor = Theme.Surface;
            quickInfo.AutoSize = false;
            quickInfo.Location = new Point(0, 270);
            quickInfo.Size = new Size(740, 20);
            page.Controls.Add(quickInfo);

            _lstQuick = new ListBox();
            _lstQuick.Font = Theme.Ui(8.75f, FontStyle.Regular);
            _lstQuick.Location = new Point(0, 294);
            _lstQuick.Size = new Size(620, 130);
            _lstQuick.HorizontalScrollbar = true;
            _lstQuick.IntegralHeight = false;
            for (int i = 0; i < _settings.QuickScanPaths.Count; i++) _lstQuick.Items.Add(_settings.QuickScanPaths[i]);
            page.Controls.Add(_lstQuick);

            AddFolderButtons(page, _lstQuick, 292);

            Label note = new Label();
            note.Text = "Consejo: evita vigilar carpetas con millones de archivos temporales, como la caché de un navegador.";
            note.Font = Theme.Ui(8.25f, FontStyle.Regular);
            note.ForeColor = Theme.TextMuted;
            note.BackColor = Theme.Surface;
            note.AutoSize = true;
            note.Location = new Point(0, 440);
            page.Controls.Add(note);
        }

        private void AddFolderButtons(TabPage page, ListBox list, int top)
        {
            RoundedButton add = new RoundedButton();
            add.Text = "Agregar…";
            add.Style = ButtonStyle.Secondary;
            add.BackColor = Theme.Surface;
            add.Size = new Size(108, 32);
            add.Location = new Point(632, top);
            add.Click += delegate
            {
                using (FolderBrowserDialog dialog = new FolderBrowserDialog())
                {
                    dialog.Description = "Selecciona una carpeta";
                    dialog.ShowNewFolderButton = false;
                    if (dialog.ShowDialog(this) != DialogResult.OK) return;
                    string full;
                    try { full = Path.GetFullPath(dialog.SelectedPath).TrimEnd('\\'); }
                    catch { return; }
                    for (int i = 0; i < list.Items.Count; i++)
                    {
                        if (string.Equals(list.Items[i].ToString(), full, StringComparison.OrdinalIgnoreCase)) return;
                    }
                    list.Items.Add(full);
                }
            };
            page.Controls.Add(add);

            RoundedButton remove = new RoundedButton();
            remove.Text = "Quitar";
            remove.Style = ButtonStyle.Ghost;
            remove.BackColor = Theme.Surface;
            remove.Size = new Size(108, 32);
            remove.Location = new Point(632, top + 40);
            remove.Click += delegate
            {
                if (list.SelectedIndex >= 0) list.Items.RemoveAt(list.SelectedIndex);
            };
            page.Controls.Add(remove);
        }

        private void BuildMaintenanceTab(TabPage page)
        {
            Label serviceLabel = SectionLabel("Servicio residente", 0);
            page.Controls.Add(serviceLabel);

            _lblServiceState = new Label();
            _lblServiceState.Font = Theme.Ui(9f, FontStyle.Regular);
            _lblServiceState.ForeColor = Theme.TextSecondary;
            _lblServiceState.BackColor = Theme.Surface;
            _lblServiceState.AutoSize = false;
            _lblServiceState.Location = new Point(0, 30);
            _lblServiceState.Size = new Size(740, 24);
            page.Controls.Add(_lblServiceState);
            UpdateServiceState();

            RoundedButton start = new RoundedButton();
            start.Text = "Iniciar";
            start.Style = ButtonStyle.Secondary;
            start.BackColor = Theme.Surface;
            start.Size = new Size(100, 34);
            start.Location = new Point(0, 62);
            start.Click += delegate { ServiceAction(true); };
            page.Controls.Add(start);

            RoundedButton stop = new RoundedButton();
            stop.Text = "Detener";
            stop.Style = ButtonStyle.Secondary;
            stop.BackColor = Theme.Surface;
            stop.Size = new Size(100, 34);
            stop.Location = new Point(110, 62);
            stop.Click += delegate { ServiceAction(false); };
            page.Controls.Add(stop);

            RoundedButton refresh = new RoundedButton();
            refresh.Text = "Actualizar estado";
            refresh.Style = ButtonStyle.Ghost;
            refresh.BackColor = Theme.Surface;
            refresh.Size = new Size(132, 34);
            refresh.Location = new Point(220, 62);
            refresh.Click += delegate { UpdateServiceState(); };
            page.Controls.Add(refresh);

            page.Controls.Add(Divider(122));

            Label maintenance = SectionLabel("Datos y registros", 142);
            page.Controls.Add(maintenance);

            RoundedButton logs = new RoundedButton();
            logs.Text = "Abrir registros";
            logs.Style = ButtonStyle.Secondary;
            logs.BackColor = Theme.Surface;
            logs.Size = new Size(140, 34);
            logs.Location = new Point(0, 172);
            logs.Click += delegate { OpenFolder(AppPaths.LogsDir); };
            page.Controls.Add(logs);

            RoundedButton data = new RoundedButton();
            data.Text = "Abrir carpeta de datos";
            data.Style = ButtonStyle.Secondary;
            data.BackColor = Theme.Surface;
            data.Size = new Size(170, 34);
            data.Location = new Point(150, 172);
            data.Click += delegate { OpenFolder(AppPaths.DataDir); };
            page.Controls.Add(data);

            RoundedButton quarantine = new RoundedButton();
            quarantine.Text = "Abrir cuarentena";
            quarantine.Style = ButtonStyle.Secondary;
            quarantine.BackColor = Theme.Surface;
            quarantine.Size = new Size(150, 34);
            quarantine.Location = new Point(330, 172);
            quarantine.Click += delegate { OpenFolder(AppPaths.QuarantineDir); };
            page.Controls.Add(quarantine);

            page.Controls.Add(Divider(230));

            Label danger = SectionLabel("Desinstalación", 250);
            page.Controls.Add(danger);

            Label dangerInfo = new Label();
            dangerInfo.Text = "«Desinstalar servicio residente» solo detiene la protección y quita el arranque automático.\n" +
                "Para borrar también el motor ClamAV, las firmas, los registros, la configuración y la cuarentena, " +
                "usa «Desinstalar ClamGuard por completo…».";
            dangerInfo.Font = Theme.Ui(8.5f, FontStyle.Regular);
            dangerInfo.ForeColor = Theme.TextSecondary;
            dangerInfo.BackColor = Theme.Surface;
            dangerInfo.AutoSize = false;
            dangerInfo.Location = new Point(0, 274);
            dangerInfo.Size = new Size(740, 44);
            page.Controls.Add(dangerInfo);

            RoundedButton uninstall = new RoundedButton();
            uninstall.Text = "Desinstalar servicio residente";
            uninstall.Style = ButtonStyle.Secondary;
            uninstall.BackColor = Theme.Surface;
            uninstall.Size = new Size(220, 36);
            uninstall.Location = new Point(0, 326);
            uninstall.Click += Uninstall_Click;
            page.Controls.Add(uninstall);

            RoundedButton fullUninstall = new RoundedButton();
            fullUninstall.Text = "Desinstalar ClamGuard por completo…";
            fullUninstall.Style = ButtonStyle.Danger;
            fullUninstall.BackColor = Theme.Surface;
            fullUninstall.Size = new Size(300, 36);
            fullUninstall.Location = new Point(232, 326);
            fullUninstall.Click += FullUninstall_Click;
            page.Controls.Add(fullUninstall);

            Label fullUninstallInfo = new Label();
            fullUninstallInfo.Text = "La desinstalación completa elimina el programa, el motor ClamAV, los datos y la cuarentena.";
            fullUninstallInfo.Font = Theme.Ui(8.25f, FontStyle.Regular);
            fullUninstallInfo.ForeColor = Theme.TextMuted;
            fullUninstallInfo.BackColor = Theme.Surface;
            fullUninstallInfo.AutoSize = false;
            fullUninstallInfo.Location = new Point(0, 372);
            fullUninstallInfo.Size = new Size(740, 20);
            page.Controls.Add(fullUninstallInfo);
        }

        private void FullUninstall_Click(object sender, EventArgs e)
        {
            _requestUninstall = true;
            DialogResult = DialogResult.Cancel;
            Close();
        }

        private static Label SectionLabel(string text, int top)
        {
            Label label = new Label();
            label.Text = text;
            label.Font = Theme.Ui(10f, FontStyle.Bold);
            label.ForeColor = Theme.TextPrimary;
            label.BackColor = Theme.Surface;
            label.AutoSize = true;
            label.Location = new Point(0, top);
            return label;
        }

        private static Panel Divider(int top)
        {
            Panel panel = new Panel();
            panel.BackColor = Theme.Border;
            panel.Location = new Point(0, top);
            panel.Size = new Size(740, 1);
            panel.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            return panel;
        }

        private void UpdateEngineInfo()
        {
            string dir = AppPaths.FindClamAvDirectory(_txtClamDir.Text);
            if (dir == null)
            {
                _lblEngineInfo.Text = "No se detecta una instalación válida de ClamAV.";
                _lblEngineInfo.ForeColor = Theme.Warning;
            }
            else
            {
                EngineInfo info = ClamAv.QueryEngine(_settings);
                _lblEngineInfo.Text = "Detectado: " + dir +
                    (string.IsNullOrEmpty(info.Version) ? string.Empty : "  ·  versión " + info.Version);
                _lblEngineInfo.ForeColor = Theme.Success;
            }
        }

        private void UpdateServiceState()
        {
            if (_lblServiceState == null) return;
            ResidentState state = ResidentService.GetState();
            _lblServiceState.Text = "Estado actual: " + ResidentService.DescribeState(state) +
                (state == ResidentState.NotInstalled ? "  ·  se instala desde la ventana principal." : string.Empty);
            _lblServiceState.ForeColor = state == ResidentState.Running ? Theme.Success : Theme.TextSecondary;
        }

        private void ServiceAction(bool start)
        {
            Cursor = Cursors.WaitCursor;
            string error;
            bool ok = start ? ResidentService.Start(out error) : ResidentService.Stop(out error);
            Cursor = Cursors.Default;
            if (!ok && !string.IsNullOrEmpty(error))
                MessageBox.Show(this, error, "Servicio residente", MessageBoxButtons.OK, MessageBoxIcon.Error);
            UpdateServiceState();
        }

        private void Uninstall_Click(object sender, EventArgs e)
        {
            if (ResidentService.GetState() == ResidentState.NotInstalled)
            {
                MessageBox.Show(this, "El servicio residente no está instalado.", "Desinstalar",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            DialogResult confirm = MessageBox.Show(this,
                "Se detendrá y eliminará el servicio residente de ClamGuard.\n\n¿Continuar?",
                "Desinstalar protección residente", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2);
            if (confirm != DialogResult.Yes) return;

            Cursor = Cursors.WaitCursor;
            string error;
            bool ok = ResidentService.Uninstall(out error);
            Cursor = Cursors.Default;
            if (!ok)
                MessageBox.Show(this, error, "Desinstalar", MessageBoxButtons.OK, MessageBoxIcon.Error);
            UpdateServiceState();
        }

        private void OpenFolder(string path)
        {
            try
            {
                Directory.CreateDirectory(path);
                Process.Start("explorer.exe", Cmd.Quote(path));
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Abrir carpeta", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void Save_Click(object sender, EventArgs e)
        {
            string dir = AppPaths.NormalizeDirectory(_txtClamDir.Text);
            if (!string.IsNullOrEmpty(_txtClamDir.Text) && !AppPaths.IsValidClamAvDir(dir, false))
            {
                DialogResult answer = MessageBox.Show(this,
                    "La carpeta indicada no contiene clamscan.exe ni freshclam.exe.\n\n¿Guardar de todos modos?",
                    "Ruta de ClamAV", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
                if (answer != DialogResult.Yes) return;
            }

            if (dir == null) dir = AppPaths.FindClamAvDirectory(null);
            _settings.ClamAvDirectory = dir == null ? string.Empty : dir;

            _settings.MonitorPaths = CollectList(_lstMonitor);
            _settings.QuickScanPaths = CollectList(_lstQuick);
            _settings.OnAccessEnabled = _chkOnAccess.Checked;
            _settings.ScanRemovableDrives = _chkRemovable.Checked;
            _settings.PauseDefender = _chkPauseDefender.Checked;
            _settings.QuarantineAction = _cboAction.SelectedIndex == 1 ? "delete" : "quarantine";
            _settings.UpdateIntervalHours = (int)_numInterval.Value;
            _settings.ClamdPort = (int)_numPort.Value;
            _settings.Normalize();
            _settings.Save();
            ClamAv.WriteConfigs(_settings);

            DialogResult = DialogResult.OK;
            Close();
        }

        private static List<string> CollectList(ListBox list)
        {
            List<string> paths = new List<string>();
            for (int i = 0; i < list.Items.Count; i++)
            {
                string path = (list.Items[i] ?? string.Empty).ToString();
                if (!string.IsNullOrEmpty(path) && !AppPaths.ContainsPath(paths, path)) paths.Add(path);
            }
            return paths;
        }
    }

    /// <summary>
    /// Búsqueda de Indicadores de Compromiso (IOC) en formato STIX2.
    /// </summary>
    public sealed class IocDialog : Form
    {
        private ListBox _results;
        private Label _lblStatus;
        private ProgressBarEx _bar;
        private RoundedButton _btnUpdate;
        private RoundedButton _btnScan;
        private bool _running;

        public IocDialog()
        {
            BuildUi();
        }

        private void BuildUi()
        {
            Text = "Indicadores de compromiso (IOC)";
            ClientSize = new Size(820, 620);
            FormBorderStyle = FormBorderStyle.Sizable;
            MinimumSize = new Size(700, 500);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = Theme.Surface;
            Font = Theme.Ui(9f, FontStyle.Regular);

            Label title = new Label();
            title.Text = "Indicadores de compromiso (IOC)";
            title.Font = Theme.Ui(14f, FontStyle.Bold);
            title.ForeColor = Theme.TextPrimary;
            title.BackColor = Theme.Surface;
            title.AutoSize = true;
            title.Location = new Point(24, 16);
            Controls.Add(title);

            Label subtitle = new Label();
            subtitle.Text = "Descarga la base publica de IOCs (STIX2) y busca coincidencias en procesos, archivos, dominios y registro.";
            subtitle.Font = Theme.Ui(8.75f, FontStyle.Regular);
            subtitle.ForeColor = Theme.TextSecondary;
            subtitle.BackColor = Theme.Surface;
            subtitle.AutoSize = false;
            subtitle.Location = new Point(24, 44);
            subtitle.Size = new Size(772, 32);
            Controls.Add(subtitle);

            Label info = new Label();
            info.Text = "IOCs disponibles localmente: " + IocStore.LocalIndicatorCount();
            info.Font = Theme.Ui(9f, FontStyle.Regular);
            info.ForeColor = Theme.TextMuted;
            info.BackColor = Theme.Surface;
            info.AutoSize = true;
            info.Location = new Point(24, 82);
            Controls.Add(info);

            _lblStatus = new Label();
            _lblStatus.Text = "Listo.";
            _lblStatus.Font = Theme.Ui(9f, FontStyle.Regular);
            _lblStatus.ForeColor = Theme.TextSecondary;
            _lblStatus.BackColor = Theme.Surface;
            _lblStatus.AutoSize = false;
            _lblStatus.Location = new Point(24, 106);
            _lblStatus.Size = new Size(772, 20);
            Controls.Add(_lblStatus);

            _bar = new ProgressBarEx();
            _bar.BackColor = Theme.Surface;
            _bar.Location = new Point(24, 130);
            _bar.Size = new Size(772, 8);
            _bar.IsIndeterminate = true;
            _bar.Visible = false;
            Controls.Add(_bar);

            _btnUpdate = new RoundedButton();
            _btnUpdate.Text = "Actualizar IOCs";
            _btnUpdate.Style = ButtonStyle.Primary;
            _btnUpdate.BackColor = Theme.Surface;
            _btnUpdate.Size = new Size(150, 34);
            _btnUpdate.Location = new Point(24, 150);
            _btnUpdate.Click += Update_Click;
            Controls.Add(_btnUpdate);

            _btnScan = new RoundedButton();
            _btnScan.Text = "Buscar en el equipo";
            _btnScan.Style = ButtonStyle.Secondary;
            _btnScan.BackColor = Theme.Surface;
            _btnScan.Size = new Size(170, 34);
            _btnScan.Location = new Point(186, 150);
            _btnScan.Click += Scan_Click;
            Controls.Add(_btnScan);

            _results = new ListBox();
            _results.Font = Theme.Ui(8.5f, FontStyle.Regular);
            _results.Location = new Point(24, 196);
            _results.Size = new Size(772, 380);
            _results.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            Controls.Add(_results);

            Label note = new Label();
            note.Text = "La busqueda revisa procesos en ejecucion, archivos en Escritorio/Documentos/Temp/Inicio, cache DNS y claves de inicio del registro.";
            note.Font = Theme.Ui(8.25f, FontStyle.Regular);
            note.ForeColor = Theme.TextMuted;
            note.BackColor = Theme.Surface;
            note.AutoSize = false;
            note.Location = new Point(24, 582);
            note.Size = new Size(772, 28);
            note.Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            Controls.Add(note);
        }

        private async void Update_Click(object sender, EventArgs e)
        {
            if (_running) return;
            _running = true;
            SetRunning(true);
            _lblStatus.Text = "Descargando IOCs...";
            _results.Items.Clear();
            int downloaded = 0;
            try
            {
                Progress<IocProgress> progress = new Progress<IocProgress>(OnProgress);
                downloaded = await Task.Run(delegate
                {
                    return IocStore.DownloadAll(progress, CancellationToken.None,
                        new Action<LogLevel, string>(Log));
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Actualizar IOCs", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            SetRunning(false);
            _running = false;
            _lblStatus.Text = "Descarga completada: " + downloaded + " archivo(s). IOCs disponibles: " + IocStore.LocalIndicatorCount();
        }

        private async void Scan_Click(object sender, EventArgs e)
        {
            if (_running) return;
            if (IocStore.LocalIndicatorCount() == 0)
            {
                MessageBox.Show(this, "No hay IOCs descargados. Pulsa «Actualizar IOCs» primero.",
                    "Buscar IOCs", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            _running = true;
            SetRunning(true);
            _lblStatus.Text = "Buscando IOCs...";
            _results.Items.Clear();
            List<IocMatch> matches = null;
            try
            {
                Progress<IocProgress> progress = new Progress<IocProgress>(OnProgress);
                matches = await Task.Run(delegate
                {
                    return IocStore.Search(progress, CancellationToken.None,
                        new Action<LogLevel, string>(Log), null);
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Buscar IOCs", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            SetRunning(false);
            _running = false;

            if (matches != null)
            {
                if (matches.Count == 0)
                {
                    _results.Items.Add("No se encontraron indicadores de compromiso.");
                }
                else
                {
                    for (int i = 0; i < matches.Count; i++)
                    {
                        IocMatch m = matches[i];
                        _results.Items.Add("[" + m.Type + "] " + m.Indicator + " -> " + m.Location +
                            (string.IsNullOrEmpty(m.Source) ? string.Empty : " (" + m.Source + ")"));
                    }
                }
                _lblStatus.Text = "Busqueda completada: " + (matches == null ? 0 : matches.Count) + " coincidencia(s).";
            }
        }

        private void SetRunning(bool running)
        {
            _btnUpdate.Enabled = !running;
            _btnScan.Enabled = !running;
            _bar.Visible = running;
            Cursor = running ? Cursors.WaitCursor : Cursors.Default;
            if (running) _bar.IsIndeterminate = true;
        }

        private void OnProgress(IocProgress value)
        {
            if (value == null || IsDisposed) return;
            if (!string.IsNullOrEmpty(value.Stage)) _lblStatus.Text = value.Stage;
            _bar.IsIndeterminate = value.Indeterminate;
            if (!value.Indeterminate) _bar.Value = value.Percent;
        }

        private void Log(LogLevel level, string message)
        {
            try { AppLog.Write(level, message); } catch { }
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (_running)
            {
                e.Cancel = true;
                return;
            }
            base.OnFormClosing(e);
        }
    }
}
