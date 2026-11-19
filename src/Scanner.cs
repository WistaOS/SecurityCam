using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace SecurityCam;

public enum Verdict { Clean, LowRisk, Suspicious, Malicious }

public sealed record Finding(int Weight, string Title, string Detail);

public sealed class ScanResult
{
    public string Path { get; init; } = "";
    public string Kind { get; init; } = "";
    public long Size { get; init; }
    public string Sha256 { get; set; } = "";
    public int Score { get; set; }
    public Verdict Verdict { get; set; }
    public string? Error { get; set; }
    public List<Finding> Findings { get; } = new();
}

public sealed class ScanOptions
{
    /// <summary>0 = Relaxed, 1 = Normal, 2 = Paranoid</summary>
    public int Sensitivity { get; set; } = 1;
    public bool CheckSignature { get; set; } = true;
    public bool EntropyAnalysis { get; set; } = true;
    public bool Recursive { get; set; } = true;
    /// <summary>Optional text file with one known-bad SHA-256 per line.</summary>
    public string? BlocklistPath { get; set; }
}

/// <summary>
/// Heuristic static analyser. It never executes the target.
/// This is NOT a signature antivirus: it flags suspicious traits and known-bad hashes.
/// </summary>
public static class Scanner
{
    public static readonly string[] BatchExt = { ".bat", ".cmd" };
    public static readonly string[] ExeExt = { ".exe", ".scr", ".com", ".dll" };
    const long MaxRead = 256L * 1024 * 1024;

    public static string KindOf(string path)
    {
        var ext = System.IO.Path.GetExtension(path).ToLowerInvariant();
        if (BatchExt.Contains(ext)) return "Batch";
        if (ExeExt.Contains(ext)) return "Executable";
        return "Unknown";
    }

    public static IEnumerable<string> Expand(IEnumerable<string> inputs, bool recursive)
    {
        var all = BatchExt.Concat(ExeExt).ToHashSet();
        foreach (var p in inputs)
        {
            if (Directory.Exists(p))
            {
                var opt = new EnumerationOptions
                {
                    RecurseSubdirectories = recursive,
                    IgnoreInaccessible = true,
                    AttributesToSkip = FileAttributes.ReparsePoint
                };
                foreach (var f in Directory.EnumerateFiles(p, "*", opt))
                    if (all.Contains(System.IO.Path.GetExtension(f).ToLowerInvariant())) yield return f;
            }
            else if (File.Exists(p)) yield return p;
        }
    }

    public static ScanResult ScanFile(string path, ScanOptions opt, CancellationToken ct)
    {
        var res = new ScanResult { Path = path, Kind = KindOf(path) };
        try
        {
            var fi = new FileInfo(path);
            var r = new ScanResult { Path = path, Kind = KindOf(path), Size = fi.Length };
            if (fi.Length > MaxRead) { r.Error = "File too large (> 256 MB), skipped."; return r; }

            byte[] data = File.ReadAllBytes(path);
            ct.ThrowIfCancellationRequested();
            r.Sha256 = Convert.ToHexString(SHA256.HashData(data));

            CheckBlocklist(r, opt);

            // Content decides, not extension: a renamed PE is still a PE.
            bool isPe = data.Length > 64 && data[0] == 'M' && data[1] == 'Z';
            if (isPe)
            {
                if (r.Kind == "Batch")
                    r.Findings.Add(new(40, "Extension mismatch", "File has a script extension but contains a Windows executable (MZ header)."));
                r = ScanPe(r, data, opt, ct);
            }
            else if (r.Kind == "Batch" || r.Kind == "Unknown")
                ScanBatch(r, data, ct);
            else
                r.Findings.Add(new(15, "Extension mismatch", "File has an executable extension but is not a valid PE image."));

            Finish(r, opt);
            return r;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            res.Error = ex.Message;
            return res;
        }
    }

    // ---------- verdict ----------

    static void Finish(ScanResult r, ScanOptions opt)
    {
        int raw = r.Findings.Sum(f => f.Weight);
        double mult = opt.Sensitivity switch { 0 => 0.75, 2 => 1.35, _ => 1.0 };
        r.Score = Math.Clamp((int)Math.Round(raw * mult), 0, 100);
        r.Verdict = r.Score switch
        {
            >= 70 => Verdict.Malicious,
            >= 40 => Verdict.Suspicious,
            >= 15 => Verdict.LowRisk,
            _ => Verdict.Clean
        };
    }

    static void CheckBlocklist(ScanResult r, ScanOptions opt)
    {
        if (string.IsNullOrWhiteSpace(opt.BlocklistPath) || !File.Exists(opt.BlocklistPath)) return;
        foreach (var line in File.ReadLines(opt.BlocklistPath))
        {
            var h = line.Split('#')[0].Trim();
            if (h.Length == 64 && h.Equals(r.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                r.Findings.Add(new(100, "Known-bad hash", "SHA-256 matches an entry in your blocklist."));
                return;
            }
        }
    }

    // ---------- batch / cmd ----------

    static readonly (Regex Rx, int W, string Title, string Detail)[] BatchRules =
    {
        (new Regex(@"powershell(\.exe)?[^\r\n]*\s-(e|enc|encodedcommand)\s", RxO), 45, "Encoded PowerShell", "Runs a Base64-encoded PowerShell command."),
        (new Regex(@"powershell(\.exe)?[^\r\n]*-w(indowstyle)?\s+hidden", RxO), 25, "Hidden PowerShell window", "Launches PowerShell without a visible window."),
        (new Regex(@"powershell[^\r\n]*-ep\s+bypass|-executionpolicy\s+bypass", RxO), 20, "Execution policy bypass", "Disables PowerShell script restrictions."),
        (new Regex(@"(iex|invoke-expression)[^\r\n]*(downloadstring|webclient|invoke-webrequest|iwr)", RxO), 55, "Download and execute", "Downloads code from the network and executes it in memory."),
        (new Regex(@"certutil[^\r\n]*-(urlcache|decode)", RxO), 40, "certutil abuse", "Uses certutil to download or decode payloads."),
        (new Regex(@"bitsadmin[^\r\n]*/transfer", RxO), 35, "bitsadmin download", "Uses BITS to fetch files from the network."),
        (new Regex(@"\b(curl|wget)\b[^\r\n]*https?://[^\r\n]*\.(exe|dll|ps1|bat|vbs|scr)", RxO), 30, "Downloads executable content", "Fetches an executable or script from a URL."),
        (new Regex(@"mshta(\.exe)?\s+(https?:|vbscript:|javascript:)", RxO), 50, "mshta remote script", "Runs remote or inline script through mshta."),
        (new Regex(@"regsvr32[^\r\n]*/i:https?://", RxO), 50, "regsvr32 remote scriptlet", "Squiblydoo-style remote scriptlet execution."),
        (new Regex(@"rundll32[^\r\n]*(javascript:|mshtml,runhtmlapplication)", RxO), 45, "rundll32 script execution", "Runs script content through rundll32."),
        (new Regex(@"vssadmin[^\r\n]*delete\s+shadows", RxO), 70, "Deletes shadow copies", "Typical ransomware behaviour: removes backups."),
        (new Regex(@"wmic[^\r\n]*shadowcopy[^\r\n]*delete", RxO), 70, "Deletes shadow copies", "Typical ransomware behaviour: removes backups."),
        (new Regex(@"bcdedit[^\r\n]*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)", RxO), 60, "Disables Windows recovery", "Prevents the system from booting into recovery."),
        (new Regex(@"wevtutil[^\r\n]*\scl\s", RxO), 35, "Clears event logs", "Removes forensic evidence from Windows event logs."),
        (new Regex(@"set-mppreference[^\r\n]*disable|add-mppreference[^\r\n]*exclusion", RxO), 55, "Tampers with Defender", "Disables Defender protection or adds exclusions."),
        (new Regex(@"reg(\.exe)?\s+add[^\r\n]*disableantispyware|disablerealtimemonitoring", RxO), 55, "Tampers with Defender", "Turns off Windows Defender through the registry."),
        (new Regex(@"netsh[^\r\n]*advfirewall[^\r\n]*state\s+off", RxO), 40, "Disables firewall", "Turns off the Windows firewall."),
        (new Regex(@"taskkill[^\r\n]*(msmpeng|msseces|mbam|avp|avgnt|avast)", RxO), 55, "Kills security software", "Terminates antivirus processes."),
        (new Regex(@"reg(\.exe)?\s+add[^\r\n]*\\currentversion\\run", RxO), 25, "Run-key persistence", "Adds itself to automatic startup in the registry."),
        (new Regex(@"schtasks[^\r\n]*/create", RxO), 20, "Scheduled task", "Creates a scheduled task (persistence)."),
        (new Regex(@"net\s+user[^\r\n]*/add", RxO), 40, "Creates user account", "Adds a local account."),
        (new Regex(@"net\s+localgroup\s+administrators[^\r\n]*/add", RxO), 50, "Adds local administrator", "Escalates an account to administrator."),
        (new Regex(@"(del|erase)\s+(/[fsqa]\s*)+[a-z]:\\(windows|users|\*)", RxO), 55, "Mass deletion", "Recursively deletes system or user files."),
        (new Regex(@"rd\s+/s\s+/q\s+[a-z]:\\(windows|users)?\\?", RxO), 55, "Mass deletion", "Recursively removes directories."),
        (new Regex(@"\bformat\s+[a-z]:", RxO), 60, "Formats a drive", "Calls format on a drive letter."),
        (new Regex(@"cipher\s+/w", RxO), 35, "Wipes free space", "cipher /w overwrites deleted data."),
        (new Regex(@"attrib\s+[^\r\n]*\+h[^\r\n]*\+s", RxO), 15, "Hides files", "Marks files hidden + system."),
        (new Regex(@"takeown[^\r\n]*/f[^\r\n]*(system32|windows)", RxO), 30, "Takes ownership of system files", "Often paired with replacing protected binaries."),
        (new Regex(@"copy\s+[^\r\n]*\\(system32|windows)\\", RxO), 20, "Writes to system directory", "Copies files into the Windows directory."),
        (new Regex(@"start\s+/b\s+\S+\.exe[^\r\n]*>\s*nul", RxO), 10, "Silent background launch", "Starts a program hidden with suppressed output."),
        (new Regex(@"(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}", RxO), 10, "Hard-coded IP:port", "Contains a raw IP address with port (possible C2)."),
    };

    const RegexOptions RxO = RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant;

    static void ScanBatch(ScanResult r, byte[] data, CancellationToken ct)
    {
        // Detect UTF-16 BOM, else treat as ANSI/UTF-8.
        string text = data.Length >= 2 && ((data[0] == 0xFF && data[1] == 0xFE) || (data[0] == 0xFE && data[1] == 0xFF))
            ? Encoding.Unicode.GetString(data)
            : Encoding.UTF8.GetString(data);
        if (text.Length == 0) return;

        var seen = new HashSet<string>();
        foreach (var (rx, w, title, detail) in BatchRules)
        {
            ct.ThrowIfCancellationRequested();
            var m = rx.Match(text);
            if (m.Success && seen.Add(title))
            {
                var snippet = m.Value.Replace('\r', ' ').Replace('\n', ' ');
                if (snippet.Length > 90) snippet = snippet[..90] + "…";
                r.Findings.Add(new(w, title, detail + "  [" + snippet + "]"));
            }
        }

        // Obfuscation: caret-escaping and %var:~n,m% substring abuse.
        int carets = text.Count(c => c == '^');
        int substr = Regex.Matches(text, @"%[a-z0-9_]+:~-?\d+(,-?\d+)?%", RegexOptions.IgnoreCase).Count;
        if (substr > 15)
            r.Findings.Add(new(35, "Variable-substring obfuscation", $"{substr} %var:~n,m% expansions: typical of obfuscated batch."));
        if (text.Length > 200 && carets > text.Length * 0.05)
            r.Findings.Add(new(25, "Caret obfuscation", "Unusually high density of '^' escape characters."));

        // Long Base64 blobs.
        var b64 = Regex.Match(text, @"[A-Za-z0-9+/]{300,}={0,2}");
        if (b64.Success)
            r.Findings.Add(new(25, "Embedded Base64 blob", $"A {b64.Length}-character Base64 string is embedded in the script."));

        // MZ payload smuggled as text (certutil -decode targets, PowerShell [byte[]]).
        if (text.Contains("TVqQAAMAAAAEAAAA") || text.Contains("4d5a9000"))
            r.Findings.Add(new(50, "Embedded executable", "Script contains an encoded PE image (MZ header)."));
    }

    // ---------- PE ----------

    static readonly (string Api, int W)[] SuspiciousApis =
    {
        ("VirtualAllocEx", 8), ("WriteProcessMemory", 10), ("CreateRemoteThread", 12),
        ("NtUnmapViewOfSection", 15), ("SetWindowsHookEx", 8), ("GetAsyncKeyState", 8),
        ("URLDownloadToFile", 10), ("InternetOpenUrl", 4), ("WinExec", 3),
        ("AdjustTokenPrivileges", 4), ("CryptEncrypt", 6), ("IsDebuggerPresent", 4),
        ("CheckRemoteDebuggerPresent", 6), ("NtSetInformationThread", 8),
        ("QueueUserAPC", 8), ("SetThreadContext", 10), ("RtlDecompressBuffer", 4),
        ("OpenProcessToken", 2), ("LoadLibraryA", 1), ("MiniDumpWriteDump", 12),
    };

    static readonly string[] PackerSections = { "upx0", "upx1", ".themida", ".vmp0", ".vmp1", ".aspack", ".petite", ".mpress1", ".enigma1", ".nsp0" };

    static ScanResult ScanPe(ScanResult r, byte[] d, ScanOptions opt, CancellationToken ct)
    {
        int peOff = BitConverter.ToInt32(d, 0x3C);
        if (peOff < 0 || peOff + 24 > d.Length || d[peOff] != 'P' || d[peOff + 1] != 'E')
        {
            r.Findings.Add(new(30, "Corrupt PE header", "MZ header present but PE signature is invalid."));
            return r;
        }

        int nSec = BitConverter.ToUInt16(d, peOff + 6);
        uint ts = BitConverter.ToUInt32(d, peOff + 8);
        int optSize = BitConverter.ToUInt16(d, peOff + 20);
        int optOff = peOff + 24;
        bool pe32Plus = BitConverter.ToUInt16(d, optOff) == 0x20B;
        int ddOff = optOff + (pe32Plus ? 112 : 96);

        // Timestamp
        if (ts == 0)
            r.Findings.Add(new(5, "Zeroed timestamp", "Compile timestamp is 0 (stripped or forged)."));
        else if (DateTimeOffset.FromUnixTimeSeconds(ts) > DateTimeOffset.UtcNow.AddDays(1))
            r.Findings.Add(new(15, "Future timestamp", "Compile timestamp is in the future (forged)."));

        // Sections
        int secOff = optOff + optSize;
        long maxRaw = 0;
        int highEntropy = 0;
        for (int i = 0; i < nSec && secOff + 40 <= d.Length; i++, secOff += 40)
        {
            ct.ThrowIfCancellationRequested();
            string name = Encoding.ASCII.GetString(d, secOff, 8).TrimEnd('\0');
            uint rawSize = BitConverter.ToUInt32(d, secOff + 16);
            uint rawPtr = BitConverter.ToUInt32(d, secOff + 20);
            uint chars = BitConverter.ToUInt32(d, secOff + 36);
            maxRaw = Math.Max(maxRaw, (long)rawPtr + rawSize);

            if (PackerSections.Contains(name.ToLowerInvariant()))
                r.Findings.Add(new(25, "Known packer section", $"Section '{name}' belongs to a packer/protector."));

            bool wx = (chars & 0x20000000) != 0 && (chars & 0x80000000) != 0;
            if (wx && name != ".text")
                r.Findings.Add(new(15, "Writable + executable section", $"Section '{name}' is both writable and executable."));

            if (opt.EntropyAnalysis && rawSize > 4096 && rawPtr < d.Length)
            {
                long len = Math.Min(rawSize, d.Length - rawPtr);
                double e = Entropy(d, (int)rawPtr, (int)len);
                if (e > 7.2) { highEntropy++; r.Findings.Add(new(15, "High-entropy section", $"'{name}' entropy {e:F2}/8 (compressed or encrypted data).")); }
            }
        }

        // Overlay
        if (maxRaw > 0 && d.Length - maxRaw > 1024 * 1024)
            r.Findings.Add(new(10, "Large overlay", $"{(d.Length - maxRaw) / 1024} KB of data appended after the last section."));

        // Imports (by string presence; cheap and good enough for a heuristic).
        string ascii = Encoding.Latin1.GetString(d);
        int apiScore = 0; var hit = new List<string>();
        foreach (var (api, w) in SuspiciousApis)
            if (ascii.Contains(api, StringComparison.Ordinal)) { apiScore += w; hit.Add(api); }
        if (apiScore >= 12)
            r.Findings.Add(new(Math.Min(apiScore, 40), "Suspicious API combination", string.Join(", ", hit.Take(8)) + (hit.Count > 8 ? ", …" : "")));

        // Tiny import table = probably packed.
        if (!ascii.Contains("KERNEL32", StringComparison.OrdinalIgnoreCase) && nSec > 0)
            r.Findings.Add(new(10, "No visible imports", "Imports are hidden or resolved at run time (packed?)."));

        // Embedded script / LOLBin strings
        if (ascii.Contains("powershell", StringComparison.OrdinalIgnoreCase) && ascii.Contains("-enc", StringComparison.OrdinalIgnoreCase))
            r.Findings.Add(new(25, "Spawns encoded PowerShell", "Strings reference PowerShell with -enc."));
        if (Regex.IsMatch(ascii, @"(vssadmin|wbadmin)[^\0]{0,20}delete", RegexOptions.IgnoreCase))
            r.Findings.Add(new(45, "Backup deletion strings", "References deleting shadow copies / backups."));
        if (Regex.IsMatch(ascii, @"https?://\d{1,3}(\.\d{1,3}){3}", RegexOptions.None))
            r.Findings.Add(new(15, "URL with raw IP", "Contains an HTTP URL pointing at a raw IP address."));

        // Authenticode
        if (opt.CheckSignature)
        {
            uint secDirSize = ddOff + 4 * 8 + 8 <= d.Length ? BitConverter.ToUInt32(d, ddOff + 4 * 8 + 4) : 0;
            bool signed = secDirSize > 0;
            if (signed)
            {
                try
                {
                    var cert = X509Certificate.CreateFromSignedFile(r.Path);
                    var c2 = new X509Certificate2(cert);
                    r.Findings.Add(new(-20, "Digitally signed", "Signer: " + c2.GetNameInfo(X509NameType.SimpleName, false)));
                }
                catch
                {
                    r.Findings.Add(new(20, "Broken signature", "A signature block exists but could not be parsed."));
                }
            }
            else if (r.Size < 2 * 1024 * 1024)
                r.Findings.Add(new(5, "Unsigned", "No Authenticode signature."));
        }

        return r;
    }

    static double Entropy(byte[] d, int off, int len)
    {
        var freq = new int[256];
        for (int i = 0; i < len; i++) freq[d[off + i]]++;
        double e = 0;
        foreach (var f in freq)
        {
            if (f == 0) continue;
            double p = (double)f / len;
            e -= p * Math.Log2(p);
        }
        return e;
    }
}
