using System.Drawing.Drawing2D;
using System.Drawing.Text;

namespace SecurityCam;

/// <summary>Bold section title followed by a horizontal rule (Rufus style).</summary>
sealed class SectionHeader : Control
{
    public SectionHeader(string text)
    {
        Text = text;
        SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint, true);
        Font = new Font("Segoe UI Semibold", 13f);
        Height = 34;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        e.Graphics.Clear(BackColor);
        e.Graphics.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
        var size = TextRenderer.MeasureText(e.Graphics, Text, Font, Size.Empty, TextFormatFlags.NoPadding);
        TextRenderer.DrawText(e.Graphics, Text, Font, new Point(0, (Height - size.Height) / 2 + 2), Color.Black, TextFormatFlags.NoPadding);
        int y = Height / 2 + 4;
        using var pen = new Pen(Color.Black, 1.5f);
        e.Graphics.DrawLine(pen, size.Width + 8, y, Width, y);
    }
}

/// <summary>Flat status bar with a fill and centred caption, like Rufus' READY bar.</summary>
sealed class StatusBarControl : Control
{
    int _value;
    string _caption = "READY";
    Color _fill = Color.FromArgb(6, 176, 37);

    public StatusBarControl()
    {
        SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint, true);
        Font = new Font("Segoe UI Semibold", 9.5f);
        Height = 28;
    }

    public int Value { get => _value; set { _value = Math.Clamp(value, 0, 100); Invalidate(); } }
    public string Caption { get => _caption; set { _caption = value; Invalidate(); } }
    public Color FillColor { get => _fill; set { _fill = value; Invalidate(); } }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        var r = new Rectangle(0, 0, Width - 1, Height - 1);
        using (var b = new SolidBrush(Color.FromArgb(230, 230, 230))) g.FillRectangle(b, r);
        if (_value > 0)
        {
            using var b = new SolidBrush(_fill);
            g.FillRectangle(b, 1, 1, (int)((Width - 2) * _value / 100.0), Height - 2);
        }
        using (var p = new Pen(Color.FromArgb(172, 172, 172))) g.DrawRectangle(p, r);
        TextRenderer.DrawText(g, _caption, Font, r, Color.Black,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding);
    }
}

/// <summary>Blue glyph button from Segoe MDL2 Assets (globe, info, settings, log).</summary>
sealed class GlyphButton : Control
{
    readonly string _glyph;
    bool _hot;

    public GlyphButton(string glyph, string tip, ToolTip tt)
    {
        _glyph = glyph;
        Size = new Size(30, 30);
        Cursor = Cursors.Hand;
        SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.SupportsTransparentBackColor, true);
        Font = new Font("Segoe MDL2 Assets", 15f);
        tt.SetToolTip(this, tip);
    }

    protected override void OnMouseEnter(EventArgs e) { _hot = true; Invalidate(); base.OnMouseEnter(e); }
    protected override void OnMouseLeave(EventArgs e) { _hot = false; Invalidate(); base.OnMouseLeave(e); }

    protected override void OnPaint(PaintEventArgs e)
    {
        e.Graphics.Clear(BackColor);
        if (_hot)
        {
            using var b = new SolidBrush(Color.FromArgb(40, 0, 120, 215));
            e.Graphics.FillRectangle(b, 0, 0, Width - 1, Height - 1);
        }
        TextRenderer.DrawText(e.Graphics, _glyph, Font, ClientRectangle, Color.FromArgb(30, 120, 200),
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
    }
}

/// <summary>Circle with a tick, shown next to the scan-mode combo (like Rufus' hash check icon).</summary>
sealed class CheckBadge : Control
{
    public CheckBadge()
    {
        Size = new Size(22, 22);
        SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.SupportsTransparentBackColor, true);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.Clear(BackColor);
        g.SmoothingMode = SmoothingMode.AntiAlias;
        using var pen = new Pen(Color.FromArgb(90, 90, 90), 1.6f) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round };
        g.DrawEllipse(pen, 2, 2, Width - 5, Height - 5);
        g.DrawLines(pen, new[] { new PointF(6.5f, 11.5f), new PointF(9.5f, 14.5f), new PointF(15.5f, 7.5f) });
    }
}
