using System.Text;

namespace SecurityCam;

/// <summary>Log window (Rufus' fourth icon): list of results, details of the selected one, report export.</summary>
sealed class ResultsForm : Form
{
    readonly List<ScanResult> _items;
    readonly string _label;
    readonly bool _csv;
    readonly ListView _list = new()
    {
        View = View.Details, FullRowSelect = true, HideSelection = false, MultiSelect = false,
        GridLines = false, Dock = DockStyle.Fill, BorderStyle = BorderStyle.FixedSingle
    };
    readonly TextBox _details = new()
    {
        Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill,
        Font = new Font("Consolas", 9f), BackColor = Color.White, BorderStyle = BorderStyle.FixedSingle
    };

    public ResultsForm(List<ScanResult> items, string label, bool csv)
    {
        _items = items.OrderByDescending(r => r.Score).ToList();
        _label = label;
        _csv = csv;

        Text = "Scan results";
        Font = new Font("Segoe UI", 9f);
        AutoScaleMode = AutoScaleMode.Dpi;
        AutoScaleDimensions = new SizeF(96f, 96f);
        ClientSize = new Size(720, 520);
        MinimumSize = new Size(560, 400);
        StartPosition = FormStartPosition.CenterParent;
        ShowInTaskbar = false;
        BackColor = Color.FromArgb(240, 240, 240);

        _list.Columns.Add("Verdict", 90);
        _list.Columns.Add("Score", 55, HorizontalAlignment.Right);
        _list.Columns.Add("Type", 85);
        _list.Columns.Add("File", 460);

        var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, SplitterDistance = 220, FixedPanel = FixedPanel.None };
        split.Panel1.Controls.Add(_list);
        split.Panel2.Controls.Add(_details);
        split.Panel1.Padding = new Padding(12, 12, 12, 4);
        split.Panel2.Padding = new Padding(12, 4, 12, 4);

        var bottom = new Panel { Dock = DockStyle.Bottom, Height = 48 };
        var save = new Button { Text = "SAVE REPORT", FlatStyle = FlatStyle.System, Size = new Size(120, 30), Anchor = AnchorStyles.Top | AnchorStyles.Right };
        var close = new Button { Text = "CLOSE", FlatStyle = FlatStyle.System, Size = new Size(100, 30), Anchor = AnchorStyles.Top | AnchorStyles.Right, DialogResult = DialogResult.Cancel };
        bottom.Controls.Add(save);
        bottom.Controls.Add(close);
        bottom.Resize += (_, _) =>
        {
            close.Location = new Point(bottom.Width - close.Width - 12, 8);
            save.Location = new Point(close.Left - save.Width - 8, 8);
        };
        bottom.PerformLayout();
        close.Location = new Point(ClientSize.Width - close.Width - 12, 8);
        save.Location = new Point(close.Left - save.Width - 8, 8);

        Controls.Add(split);
        Controls.Add(bottom);
        CancelButton = close;

        foreach (var r in _items)
        {
            var it = new ListViewItem(r.Error != null ? "Error" : r.Verdict.ToString()) { Tag = r, ForeColor = ColorOf(r) };
            it.SubItems.Add(r.Error != null ? "–" : r.Score.ToString());
            it.SubItems.Add(r.Kind);
            it.SubItems.Add(r.Path);
            _list.Items.Add(it);
        }

        _list.SelectedIndexChanged += (_, _) =>
        {
            if (_list.SelectedItems.Count > 0) _details.Text = Describe((ScanResult)_list.SelectedItems[0].Tag!);
        };
        save.Click += (_, _) => SaveReport();

        if (_list.Items.Count > 0) _list.Items[0].Selected = true;
        else _details.Text = "No results to display.";
    }

    static Color ColorOf(ScanResult r)
    {
        if (r.Error != null) return Color.Gray;
        return r.Verdict switch
        {
            Verdict.Malicious => Color.FromArgb(200, 30, 30),
            Verdict.Suspicious => Color.FromArgb(220, 120, 0),
            Verdict.LowRisk => Color.FromArgb(150, 140, 0),
            _ => Color.FromArgb(6, 140, 30)
        };
    }

    static string Describe(ScanResult r)
    {
        var sb = new StringBuilder();
        sb.AppendLine(r.Path);
        sb.AppendLine($"Type: {r.Kind}   Size: {r.Size:N0} bytes");
        if (r.Sha256.Length > 0) sb.AppendLine($"SHA-256: {r.Sha256}");
        if (r.Error != null) { sb.AppendLine(); sb.AppendLine("Could not be scanned: " + r.Error); return sb.ToString(); }
        sb.AppendLine($"Verdict: {r.Verdict}   Score: {r.Score}/100");
        sb.AppendLine();
        if (r.Findings.Count == 0) sb.AppendLine("No suspicious traits found.");
        foreach (var f in r.Findings.OrderByDescending(f => f.Weight))
            sb.AppendLine($"[{(f.Weight >= 0 ? "+" : "")}{f.Weight,3}] {f.Title}\r\n       {f.Detail}");
        return sb.ToString();
    }

    void SaveReport()
    {
        using var dlg = new SaveFileDialog
        {
            Title = "Save report",
            FileName = $"securitycam-{DateTime.Now:yyyyMMdd-HHmm}" + (_csv ? ".csv" : ".txt"),
            Filter = _csv ? "CSV (*.csv)|*.csv" : "Text (*.txt)|*.txt"
        };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;

        var sb = new StringBuilder();
        if (_csv)
        {
            sb.AppendLine("Verdict,Score,Type,Size,SHA256,Path,Findings");
            foreach (var r in _items)
                sb.AppendLine(string.Join(",", Csv(r.Error != null ? "Error" : r.Verdict.ToString()), r.Score, Csv(r.Kind), r.Size, r.Sha256, Csv(r.Path),
                    Csv(string.Join(" | ", r.Findings.Select(f => f.Title)))));
        }
        else
        {
            sb.AppendLine(_label);
            sb.AppendLine($"Generated {DateTime.Now:yyyy-MM-dd HH:mm}  ·  {_items.Count} file(s)");
            sb.AppendLine(new string('=', 72));
            foreach (var r in _items) { sb.AppendLine(Describe(r)); sb.AppendLine(new string('-', 72)); }
        }
        File.WriteAllText(dlg.FileName, sb.ToString(), new UTF8Encoding(true));
    }

    static string Csv(string s) => "\"" + s.Replace("\"", "\"\"") + "\"";
}
