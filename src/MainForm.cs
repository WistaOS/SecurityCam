using System.Diagnostics;
using System.Reflection;

namespace SecurityCam;

/// <summary>Main window. Layout and wording mirror Rufus (Drive Properties / Format Options / Status).</summary>
public sealed class MainForm : Form
{
    const int M = 16;          // side margin
    const int W = 448;         // content width
    const string RepoUrl = "https://github.com/WistaOS/SecurityCam";

    readonly ToolTip _tt = new() { InitialDelay = 300 };
    readonly List<string> _targets = new();
    List<ScanResult> _results = new();
    CancellationTokenSource? _cts;

    // Scan properties
    readonly SectionHeader _hdrScan = new("Scan Properties");
    readonly Label _lblTarget = Lbl("Target");
    readonly ComboBox _cmbTarget = Combo();
    readonly Label _lblMode = Lbl("Scan mode");
    readonly ComboBox _cmbMode = Combo();
    readonly CheckBadge _badge = new();
    readonly Button _btnSelect = new() { Text = "SELECT", FlatStyle = FlatStyle.System };
    readonly Label _lblType = Lbl("Scan type");
    readonly ComboBox _cmbType = Combo();
    readonly Label _lblSens = Lbl("Sensitivity");
    readonly ComboBox _cmbSens = Combo();
    readonly Label _tglScan = Toggle("Show advanced scan properties");
    readonly Panel _advScan = new() { Height = 96, Visible = false };
    readonly CheckBox _chkSig = new() { Text = "Check digital signature (Authenticode)", Checked = true, AutoSize = true };
    readonly CheckBox _chkEntropy = new() { Text = "Entropy analysis (packed / encrypted sections)", Checked = true, AutoSize = true };
    readonly CheckBox _chkRecursive = new() { Text = "Include subfolders when scanning a folder", Checked = true, AutoSize = true };
    readonly TextBox _txtBlock = new() { PlaceholderText = "Optional hash blocklist (.txt, one SHA-256 per line)", ReadOnly = true };
    readonly Button _btnBlock = new() { Text = "…", FlatStyle = FlatStyle.System };

    // Report options
    readonly SectionHeader _hdrReport = new("Report Options");
    readonly Label _lblLabel = Lbl("Report label");
    readonly TextBox _txtLabel = new() { Text = "SecurityCam report" };
    readonly Label _lblFormat = Lbl("Report format");
    readonly ComboBox _cmbFormat = Combo();
    readonly Label _lblEngine = Lbl("Detection engine");
    readonly ComboBox _cmbEngine = Combo();
    readonly Label _tglReport = Toggle("Show advanced report options");
    readonly Panel _advReport = new() { Height = 54, Visible = false };
    readonly CheckBox _chkAutoOpen = new() { Text = "Open the results window when the scan finishes", Checked = true, AutoSize = true };
    readonly CheckBox _chkShowClean = new() { Text = "List clean files in the results", Checked = true, AutoSize = true };

    // Status
    readonly SectionHeader _hdrStatus = new("Status");
    readonly StatusBarControl _bar = new();
    readonly GlyphButton _icoWeb, _icoInfo, _icoSettings, _icoLog;
    readonly Button _btnStart = new() { Text = "START", FlatStyle = FlatStyle.System };
    readonly Button _btnClose = new() { Text = "CLOSE", FlatStyle = FlatStyle.System };
    readonly StatusStrip _strip = new() { SizingGrip = false };
    readonly ToolStripStatusLabel _stripLabel = new("No item selected") { Spring = true, TextAlign = ContentAlignment.MiddleLeft };

    public MainForm(string[] args)
    {
        Text = "SecurityCam 0.1.0 (Portable)";
        AutoScaleMode = AutoScaleMode.Dpi;
        AutoScaleDimensions = new SizeF(96f, 96f);
        Font = new Font("Segoe UI", 9f);
        BackColor = Color.FromArgb(240, 240, 240);
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        AllowDrop = true;
        LoadIcon();

        _icoWeb = new GlyphButton("", "Open the project page on GitHub", _tt);
        _icoInfo = new GlyphButton("", "About SecurityCam", _tt);
        _icoSettings = new GlyphButton("", "Show / hide advanced options", _tt);
        _icoLog = new GlyphButton("", "Show the last scan results", _tt);

        _cmbMode.Items.AddRange(new object[] { "Files (.bat / .cmd / .exe)", "Folder" });
        _cmbMode.SelectedIndex = 0;
        _cmbType.Items.AddRange(new object[] { "Auto-detect", "Batch scripts only", "Executables only" });
        _cmbType.SelectedIndex = 0;
        _cmbSens.Items.AddRange(new object[] { "Relaxed", "Normal", "Paranoid" });
        _cmbSens.SelectedIndex = 1;
        _cmbFormat.Items.AddRange(new object[] { "Text (.txt)", "CSV (.csv)" });
        _cmbFormat.SelectedIndex = 0;
        _cmbEngine.Items.Add("Heuristic (static analysis)");
        _cmbEngine.SelectedIndex = 0;
        _cmbEngine.Enabled = false;
        _cmbTarget.Items.Add("(no target selected)");
        _cmbTarget.SelectedIndex = 0;
        _cmbTarget.Enabled = false;
        _tt.SetToolTip(_badge, "Heuristic engine ready");

        foreach (Control c in new Control[]
        {
            _hdrScan, _lblTarget, _cmbTarget, _lblMode, _cmbMode, _badge, _btnSelect, _lblType, _cmbType, _lblSens, _cmbSens,
            _tglScan, _advScan, _hdrReport, _lblLabel, _txtLabel, _lblFormat, _cmbFormat, _lblEngine, _cmbEngine,
            _tglReport, _advReport, _hdrStatus, _bar, _icoWeb, _icoInfo, _icoSettings, _icoLog, _btnStart, _btnClose
        }) Controls.Add(c);

        _advScan.Controls.AddRange(new Control[] { _chkSig, _chkEntropy, _chkRecursive, _txtBlock, _btnBlock });
        _advReport.Controls.AddRange(new Control[] { _chkAutoOpen, _chkShowClean });
        _strip.Items.Add(_stripLabel);
        Controls.Add(_strip);

        _chkSig.Location = new Point(0, 2);
        _chkEntropy.Location = new Point(0, 22);
        _chkRecursive.Location = new Point(0, 42);
        _txtBlock.SetBounds(0, 66, W - 36, 23);
        _btnBlock.SetBounds(W - 30, 65, 30, 25);
        _chkAutoOpen.Location = new Point(0, 2);
        _chkShowClean.Location = new Point(0, 24);

        _btnStart.Enabled = true;
        AcceptButton = _btnStart;
        CancelButton = _btnClose;

        // Events
        _btnSelect.Click += (_, _) => SelectTargets();
        _btnBlock.Click += (_, _) => PickBlocklist();
        _btnStart.Click += (_, _) => StartOrCancel();
        _btnClose.Click += (_, _) => Close();
        _tglScan.Click += (_, _) => { _advScan.Visible = !_advScan.Visible; Relayout(); };
        _tglReport.Click += (_, _) => { _advReport.Visible = !_advReport.Visible; Relayout(); };
        _icoSettings.Click += (_, _) =>
        {
            bool show = !(_advScan.Visible && _advReport.Visible);
            _advScan.Visible = _advReport.Visible = show;
            Relayout();
        };
        _icoWeb.Click += (_, _) => OpenUrl(RepoUrl);
        _icoInfo.Click += (_, _) => ShowAbout();
        _icoLog.Click += (_, _) => ShowResults();
        DragEnter += (_, e) => { if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true && _cts == null) e.Effect = DragDropEffects.Copy; };
        DragDrop += (_, e) =>
        {
            if (e.Data?.GetData(DataFormats.FileDrop) is string[] paths) SetTargets(paths);
        };
        FormClosing += (_, _) => _cts?.Cancel();

        Relayout();

        var initial = args.Where(a => File.Exists(a) || Directory.Exists(a)).ToArray();
        if (initial.Length > 0) SetTargets(initial);
    }

    // ---------- layout ----------

    static Label Lbl(string t) => new() { Text = t, AutoSize = true, Font = new Font("Segoe UI", 9f) };

    static Label Toggle(string t) => new()
    {
        Text = "▾  " + t,
        AutoSize = true,
        Cursor = Cursors.Hand,
        Font = new Font("Segoe UI", 9f),
        Tag = t
    };

    static ComboBox Combo() => new() { DropDownStyle = ComboBoxStyle.DropDownList, FlatStyle = FlatStyle.System, DropDownWidth = 360 };

    void Relayout()
    {
        SuspendLayout();
        int y = 8;

        Put(_hdrScan, M, y, W, 34); y += 36;

        _lblTarget.Location = new Point(M, y);
        Put(_cmbTarget, M, y + 18, W, 24); y += 52;

        _lblMode.Location = new Point(M, y);
        Put(_cmbMode, M, y + 18, 330, 24);
        _badge.Location = new Point(M + 342, y + 18);
        Put(_btnSelect, M + W - 84, y + 17, 84, 26); y += 52;

        _lblType.Location = new Point(M, y);
        _lblSens.Location = new Point(M + 234, y);
        Put(_cmbType, M, y + 18, 214, 24);
        Put(_cmbSens, M + 234, y + 18, 214, 24); y += 52;

        SetToggle(_tglScan, _advScan.Visible);
        _tglScan.Location = new Point(M + 4, y); y += 24;
        if (_advScan.Visible) { Put(_advScan, M + 4, y, W - 4, _advScan.Height); y += _advScan.Height + 4; }

        Put(_hdrReport, M, y, W, 34); y += 36;

        _lblLabel.Location = new Point(M, y);
        Put(_txtLabel, M, y + 18, W, 23); y += 52;

        _lblFormat.Location = new Point(M, y);
        _lblEngine.Location = new Point(M + 234, y);
        Put(_cmbFormat, M, y + 18, 214, 24);
        Put(_cmbEngine, M + 234, y + 18, 214, 24); y += 52;

        SetToggle(_tglReport, _advReport.Visible);
        _tglReport.Location = new Point(M + 4, y); y += 24;
        if (_advReport.Visible) { Put(_advReport, M + 4, y, W - 4, _advReport.Height); y += _advReport.Height + 4; }

        Put(_hdrStatus, M, y, W, 34); y += 38;
        Put(_bar, M, y, W, 28); y += 44;

        int bx = M - 4;
        foreach (var b in new[] { _icoWeb, _icoInfo, _icoSettings, _icoLog })
        {
            b.Location = new Point(bx, y + 3);
            bx += 34;
        }
        Put(_btnStart, M + W - 224, y, 108, 30);
        Put(_btnClose, M + W - 108, y, 108, 30);
        y += 46;

        ClientSize = new Size(M * 2 + W, y + _strip.Height);
        ResumeLayout(true);
    }

    static void Put(Control c, int x, int y, int w, int h) => c.SetBounds(x, y, w, h);

    static void SetToggle(Label l, bool open) =>
        l.Text = (open ? "▴  " : "▾  ") + (string)l.Tag!;

    // ---------- actions ----------

    void SelectTargets()
    {
        if (_cts != null) return;
        if (_cmbMode.SelectedIndex == 0)
        {
            using var dlg = new OpenFileDialog
            {
                Title = "Select files to scan",
                Multiselect = true,
                Filter = "Scripts and executables|*.bat;*.cmd;*.exe;*.scr;*.com;*.dll|All files|*.*"
            };
            if (dlg.ShowDialog(this) == DialogResult.OK) SetTargets(dlg.FileNames);
        }
        else
        {
            using var dlg = new FolderBrowserDialog { Description = "Select a folder to scan", UseDescriptionForTitle = true };
            if (dlg.ShowDialog(this) == DialogResult.OK) SetTargets(new[] { dlg.SelectedPath });
        }
    }

    void PickBlocklist()
    {
        using var dlg = new OpenFileDialog { Title = "Hash blocklist", Filter = "Text files|*.txt|All files|*.*" };
        if (dlg.ShowDialog(this) == DialogResult.OK) _txtBlock.Text = dlg.FileName;
    }

    void SetTargets(IEnumerable<string> paths)
    {
        _targets.Clear();
        _targets.AddRange(paths.Where(p => File.Exists(p) || Directory.Exists(p)));
        _cmbTarget.Items.Clear();
        if (_targets.Count == 0)
        {
            _cmbTarget.Items.Add("(no target selected)");
            _cmbTarget.Enabled = false;
            _stripLabel.Text = "No item selected";
        }
        else
        {
            foreach (var t in _targets) _cmbTarget.Items.Add(t);
            _cmbTarget.Enabled = true;
            _stripLabel.Text = _targets.Count == 1 ? Path.GetFileName(_targets[0].TrimEnd('\\', '/')) : $"{_targets.Count} items selected";
            _cmbMode.SelectedIndex = Directory.Exists(_targets[0]) ? 1 : 0;
        }
        _cmbTarget.SelectedIndex = 0;
        SetStatus("READY", 0, Color.FromArgb(6, 176, 37));
    }

    void SetStatus(string caption, int value, Color fill)
    {
        _bar.Caption = caption;
        _bar.Value = value;
        _bar.FillColor = fill;
    }

    void SetBusy(bool busy)
    {
        _btnStart.Text = busy ? "CANCEL" : "START";
        foreach (Control c in new Control[] { _btnSelect, _cmbMode, _cmbType, _cmbSens, _txtLabel, _cmbFormat, _advScan, _advReport, _btnBlock })
            c.Enabled = !busy;
        _cmbTarget.Enabled = !busy && _targets.Count > 0;
    }

    async void StartOrCancel()
    {
        if (_cts != null) { _cts.Cancel(); return; }

        if (_targets.Count == 0)
        {
            SelectTargets();
            if (_targets.Count == 0) return;
        }

        var opt = new ScanOptions
        {
            Sensitivity = _cmbSens.SelectedIndex,
            CheckSignature = _chkSig.Checked,
            EntropyAnalysis = _chkEntropy.Checked,
            Recursive = _chkRecursive.Checked,
            BlocklistPath = string.IsNullOrWhiteSpace(_txtBlock.Text) ? null : _txtBlock.Text
        };
        int typeFilter = _cmbType.SelectedIndex;
        var targets = _targets.ToList();

        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        SetBusy(true);
        SetStatus("Enumerating files…", 0, Color.FromArgb(6, 176, 37));

        var results = new List<ScanResult>();
        try
        {
            var files = await Task.Run(() => Scanner.Expand(targets, opt.Recursive)
                .Where(f => typeFilter switch
                {
                    1 => Scanner.KindOf(f) == "Batch",
                    2 => Scanner.KindOf(f) == "Executable",
                    _ => true
                })
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList(), ct);

            if (files.Count == 0)
            {
                SetStatus("NOTHING TO SCAN", 0, Color.FromArgb(200, 140, 0));
                _stripLabel.Text = "No .bat, .cmd or .exe files found in the selection";
                return;
            }

            var progress = new Progress<(int i, string name)>(p =>
            {
                SetStatus($"Scanning {p.i}/{files.Count}: {p.name}", p.i * 100 / files.Count, Color.FromArgb(6, 176, 37));
                _stripLabel.Text = $"{p.i}/{files.Count}";
            });

            await Task.Run(() =>
            {
                for (int i = 0; i < files.Count; i++)
                {
                    ct.ThrowIfCancellationRequested();
                    ((IProgress<(int, string)>)progress).Report((i + 1, Path.GetFileName(files[i])));
                    results.Add(Scanner.ScanFile(files[i], opt, ct));
                }
            }, ct);

            _results = results;
            Summarise(results);
            if (_chkAutoOpen.Checked) ShowResults();
        }
        catch (OperationCanceledException)
        {
            _results = results;
            SetStatus("CANCELLED", 0, Color.FromArgb(200, 140, 0));
            _stripLabel.Text = $"Cancelled after {results.Count} file(s)";
        }
        catch (Exception ex)
        {
            SetStatus("ERROR", 0, Color.FromArgb(200, 30, 30));
            _stripLabel.Text = ex.Message;
        }
        finally
        {
            _cts?.Dispose();
            _cts = null;
            SetBusy(false);
        }
    }

    void Summarise(List<ScanResult> r)
    {
        int mal = r.Count(x => x.Verdict == Verdict.Malicious);
        int sus = r.Count(x => x.Verdict == Verdict.Suspicious);
        int low = r.Count(x => x.Verdict == Verdict.LowRisk);
        int err = r.Count(x => x.Error != null);

        if (mal > 0) SetStatus($"{mal} MALICIOUS · {sus} suspicious", 100, Color.FromArgb(200, 30, 30));
        else if (sus > 0) SetStatus($"{sus} SUSPICIOUS", 100, Color.FromArgb(230, 130, 0));
        else if (low > 0) SetStatus($"DONE · {low} low-risk", 100, Color.FromArgb(180, 170, 0));
        else SetStatus("DONE · NO THREATS FOUND", 100, Color.FromArgb(6, 176, 37));

        _stripLabel.Text = $"{r.Count} scanned · {mal} malicious · {sus} suspicious · {low} low-risk" + (err > 0 ? $" · {err} error(s)" : "");
    }

    void ShowResults()
    {
        if (_results.Count == 0)
        {
            MessageBox.Show(this, "There are no results yet. Select a file and press START.", "SecurityCam",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        var list = _chkShowClean.Checked ? _results : _results.Where(x => x.Verdict != Verdict.Clean || x.Error != null).ToList();
        using var f = new ResultsForm(list, _txtLabel.Text, _cmbFormat.SelectedIndex == 1);
        f.Icon = Icon;
        f.ShowDialog(this);
    }

    void ShowAbout()
    {
        MessageBox.Show(this,
            "SecurityCam 0.1.0\n\n" +
            "A simple tool for WistaOS that checks .bat/.cmd and .exe files for suspicious or malicious behaviour.\n\n" +
            "Files are analysed statically and never executed. The engine is heuristic: it flags suspicious traits and " +
            "known-bad SHA-256 hashes from your blocklist. It is not a replacement for a full antivirus.\n\n" +
            RepoUrl + "\nLicense: GPL-3.0",
            "About SecurityCam", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    static void OpenUrl(string url)
    {
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); } catch { }
    }

    void LoadIcon()
    {
        try
        {
            using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("app.ico");
            if (s != null) Icon = new Icon(s);
        }
        catch { }
    }
}
