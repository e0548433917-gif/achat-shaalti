using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace OtzariaBridge;

/// <summary>
/// תוכנות מותרות לפתיחה מתוך אוצריא גם במצב נעילה (כתבי הקודש, אוצר החכמה, בר אילן, Word ועוד).
/// הרשימה מוגדרת בסיסמה בלבד. הפתיחה היא לפי מזהה מהרשימה — אף פעם לא לפי נתיב חופשי.
/// בזמן שתוכנה מהרשימה בחזית, השומר של הנעילה לא מחזיר את אוצריא לחזית.
/// </summary>
public static class Programs
{
    private const string Key = "kiosk.programs";
    private const string AutoKey = "kiosk.autoTorahPrograms";
    private const string KeywordsKey = "kiosk.autoTorahKeywords";
    internal const int MaxPrograms = 20;
    private const int GraceSeconds = 30;

    // מעטפות ומנהלי מערכת שאסור להוסיף לרשימה (עוקף את הנעילה)
    /// <summary>קיום קובץ הפעלה — כולל "כינוי הפעלה" של אפליקציית חנות (קובץ reparse של 0 בתים ב-WindowsApps שלפעמים File.Exists מחזיר עליו false)</summary>
    internal static bool ExeExists(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        if (File.Exists(path)) return true;
        try { var fi = new FileInfo(path); return (fi.Attributes & FileAttributes.ReparsePoint) != 0 && (fi.Attributes & FileAttributes.Directory) == 0; }
        catch { return false; }
    }

    private static readonly HashSet<string> Blocked = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer", "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "regedit",
        "taskmgr", "mmc", "control", "conhost", "wt", "rundll32", "msiexec",
        "powershell_ise", "windowsterminal", "openconsole", "wsl", "bash"
    };

    // בעיה #14 סעיף 6: נכתבים בחוט בקשה (Activate) ונקראים בחוט השומר (ShouldYieldTo וכו') —
    // DateTime אינו Interlocked-ידידותי, ולכן ננעלים עם אובייקט נעילה קטן ייעודי
    private static readonly object GraceGate = new();
    private static DateTime _graceUntil = DateTime.MinValue;
    private static DateTime _lastLaunchAt = DateTime.MinValue;
    private static DateTime GraceUntil { get { lock (GraceGate) return _graceUntil; } set { lock (GraceGate) _graceUntil = value; } }
    private static DateTime LastLaunchAt { get { lock (GraceGate) return _lastLaunchAt; } set { lock (GraceGate) _lastLaunchAt = value; } }

    public sealed class Entry
    {
        public string Id = "";
        public string Name = "";
        public string Path = "";
        public string[] Procs = Array.Empty<string>();
        public bool Auto;
    }

    // מילות מפתח לזיהוי תוכנות תורניות בשמות התוכנות המותקנות (אפשר להרחיב ב-kiosk.autoTorahKeywords)
    private static readonly string[] TorahKeywords =
    {
        "אוצר החכמה", "אוצר הספרים", "בר אילן", "בר-אילן", "כתבי הקודש", "ספריא", "זית",
        "otzar hachochma", "otzar hasfarim", "bar-ilan", "bar ilan", "responsa", "kitvei hakodesh", "zayit",
    };

    private static readonly object AutoGate = new();
    private static List<Entry> _autoCache = new();
    private static DateTime _autoAt = DateTime.MinValue;

    // כשרכיב ההקשחה מותקן, הרשימה והגדרות הזיהוי האוטומטי נקראות מהעותק שלו (config.json כתיב למשתמש המחובר);
    // אחרת — מ-config.json כמו תמיד. ראו HardLock.Policy
    public static bool AutoEnabled => HardLock.Policy?.AutoTorah ?? Config.Get(AutoKey, true);

    private static string[] Keywords => HardLock.Policy?.AutoTorahKeywords ?? Config.GetList(KeywordsKey);

    public static void Register()
    {
        Server.Route("/kiosk/programs", _ => ListResult());
        Server.Route("/kiosk/programs/launch", Launch);
        Server.Route("/kiosk/programs/focus", Launch);   // "העבר לחזית": זהה לפתיחה, ולא פותח עותק נוסף
        Server.Route("/kiosk/programs/close", Close); // מנהל משימות פשוט: סגירת תוכנה מותרת בלבד (גם בנעילה)
        Server.Route("/kiosk/programs/add", Add);
        Server.Route("/kiosk/programs/remove", Remove);
        Server.Route("/kiosk/programs/detect", _ => Detect());
        Server.Route("/kiosk/programs/auto", SetAuto);
    }

    // ---------- אחסון ----------

    /// <summary>הרשימה המלאה: ידנית + (אם הזיהוי האוטומטי דולק) תוכנות תורניות שזוהו</summary>
    public static List<Entry> Load()
    {
        var list = LoadManual();
        if (AutoEnabled)
            foreach (var a in DetectAuto())
                if (!list.Any(x => x.Path.Equals(a.Path, StringComparison.OrdinalIgnoreCase))) list.Add(a);
        return list;
    }

    private static List<Entry> LoadManual()
    {
        var list = new List<Entry>();
        foreach (var s in HardLock.Policy?.Programs ?? Config.GetList(Key))
        {
            try
            {
                if (JsonNode.Parse(s) is not JsonObject o) continue;
                string id = (string)o["id"], name = (string)o["name"], path = (string)o["path"];
                if (string.IsNullOrEmpty(id) || string.IsNullOrEmpty(path)) continue;
                string[] procs = o["procs"] is JsonArray a
                    ? a.Select(x => x?.ToString() ?? "").Where(x => x.Length > 0).ToArray()
                    : Array.Empty<string>();
                list.Add(new Entry { Id = id, Name = name ?? id, Path = path, Procs = procs });
            }
            catch { }
        }
        return list;
    }

    private static JsonArray ToJson(List<Entry> list) => new(list.Select(e => (JsonNode)new JsonObject
    {
        ["id"] = e.Id,
        ["name"] = e.Name,
        ["path"] = e.Path,
        ["procs"] = new JsonArray(e.Procs.Select(p => (JsonNode)p).ToArray()),
    }).ToArray());

    /// <summary>
    /// שמירת הרשימה הידנית. כשרכיב ההקשחה מותקן היא נשלחת קודם אליו (הוא מקור האמת, והשליחה מאומתת בסיסמה);
    /// אם השליחה נכשלה — לא שומרים גם מקומית, כדי שהשניים לא יתפצלו
    /// </summary>
    private static void Save(List<Entry> list, string password)
    {
        if (HardLock.Available) HardLock.SetPrograms(password, ToJson(list), AutoEnabled, Keywords);
        Config.Set(Key, ToJson(list));
        Config.Save();
    }

    /// <summary>
    /// הגירה לרכיב ההקשחה (בהתקנה/עדכון שלו): אם עוד אין לו רשימה, מעבירים את הרשימה וההגדרות הנוכחיות מ-config.json
    /// </summary>
    internal static void SyncToService(string password)
    {
        var pol = HardLock.Policy;
        if (pol == null || pol.Programs != null) return;
        HardLock.SetPrograms(password, ToJson(LoadManual()), AutoEnabled, Keywords);
    }

    private static string[] ProcNames(Entry e) =>
        e.Procs.Append(System.IO.Path.GetFileNameWithoutExtension(e.Path))
            .Select(x => x.ToLowerInvariant()).Distinct().ToArray();

    // ---------- נקודות קצה ----------

    private static object ListResult() => new
    {
        autoTorah = AutoEnabled,
        programs = Load().Select(e => new
        {
            id = e.Id,
            name = e.Name,
            path = e.Path,
            procs = e.Procs,
            exists = ExeExists(e.Path),
            running = ExistingWindow(e) != IntPtr.Zero,
            auto = e.Auto,
        }).ToArray()
    };

    private static object SetAuto(JsonElement b)
    {
        Kiosk.RequirePassword(b.Str("password"));
        if (HardLock.Available) HardLock.SetPrograms(b.Str("password"), ToJson(LoadManual()), b.Bool("enabled"), Keywords);
        Config.Set(AutoKey, JsonValue.Create(b.Bool("enabled")));
        Config.Save();
        lock (AutoGate) _autoAt = DateTime.MinValue; // סריקה מחדש
        return ListResult();
    }

    private static object Launch(JsonElement b)
    {
        string id = b.Req("id");
        var e = Load().FirstOrDefault(x => x.Id == id)
                ?? throw BridgeException.NotFound("התוכנה אינה ברשימת התוכנות המותרות");
        return new { opened = true, alreadyRunning = Activate(e) };
    }

    /// <summary>
    /// פותח תוכנה מהרשימה, ואם היא כבר פתוחה (גם מוקטנת) — מחזיר אותה לחזית ולא פותח עותק שני.
    /// מחזיר true אם הייתה פתוחה.
    /// </summary>
    /// <summary>
    /// פותח חלון חסד זמני: השומר (Kiosk.Watch) לא יחזיר את אוצריא לחזית במשך כמה שניות, גם אם
    /// החלון הקדמי הוא תהליך לא-מוכר. לשימוש בפתיחת תוכנה חיצונית מאושרת שלא עוברת דרך Activate
    /// (למשל "הצגה בסייר Windows" ב-FsApi.cs) - בלעדיו השומר היה מחזיר את אוצריא תוך 2 שניות,
    /// עוד לפני שהחלון שנפתח מספיק להיראות בכלל.
    /// </summary>
    internal static void GrantForegroundGrace() => GraceUntil = DateTime.UtcNow.AddSeconds(GraceSeconds);

    /// <summary>חלון חסד פתוח כרגע (למשל אחרי "הצגה בסייר Windows") - KioskGuard לא סוגר אז חלון סייר שנפתח בכוונה</summary>
    internal static bool InForegroundGrace => DateTime.UtcNow < GraceUntil;

    public static bool Activate(Entry e)
    {
        if (!ExeExists(e.Path)) throw BridgeException.NotFound("הקובץ לא נמצא: " + e.Path);
        GraceUntil = DateTime.UtcNow.AddSeconds(GraceSeconds);
        IntPtr h = ExistingWindow(e);
        if (h != IntPtr.Zero)
        {
            Kiosk.BringToFront(h);
            Task.Run(() => { Thread.Sleep(400); Kiosk.BringToFront(h); }); // ניסיון שני: חלק מהתוכנות גוזלות פוקוס בעת הטעינה
            return true;
        }
        LastLaunchAt = DateTime.UtcNow;
        // משוב 15.10: כלי Windows מהחנות (כלי חיתוך, פנקס רשימות...) הם "כינויי הפעלה" ב-WindowsApps —
        // אין להם תיקיית עבודה רגילה ו-Process.Start עלול להיכשל/להחזיר null; מנסים שוב בלי תיקיית עבודה.
        try
        {
            using var started = Process.Start(new ProcessStartInfo(e.Path) { UseShellExecute = true, WorkingDirectory = System.IO.Path.GetDirectoryName(e.Path) });
            if (started != null) RememberLaunched(started.Id);
        }
        catch (Exception ex1)
        {
            Config.Log("launch retry " + e.Path + ": " + ex1.Message);
            try
            {
                using var started = Process.Start(new ProcessStartInfo(e.Path) { UseShellExecute = true });
                if (started != null) RememberLaunched(started.Id);
            }
            catch (Exception ex2) { throw new BridgeException("launch_failed", "הפעלת התוכנה נכשלה: " + ex2.Message, 500); }
        }
        Task.Run(() => Focus(e));
        return false;
    }

    /// <summary>חלון ראשי של התוכנה אם היא כבר רצה (כולל חלון מוקטן), אחרת Zero</summary>
    /// מנהל משימות פשוט: סוגר רק תהליכים של תוכנה מהרשימה המותרת — סגירה רגילה, ואחרי 3 שניות בכוח.
    private static object Close(JsonElement b)
    {
        string id = b.Req("id");
        var e = Load().FirstOrDefault(x => x.Id == id)
                ?? throw BridgeException.NotFound("התוכנה אינה ברשימת התוכנות המותרות");
        int session = Process.GetCurrentProcess().SessionId, n = 0;
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                if (p.SessionId != session || IsOwnOrBlocked(p) || !MatchesList(p, new[] { e })) { p.Dispose(); continue; }
                n++;
                var proc = p;
                Task.Run(() =>
                {
                    try { if (!proc.CloseMainWindow() || !proc.WaitForExit(3000)) proc.Kill(entireProcessTree: true); } catch { }
                    finally { proc.Dispose(); }
                });
            }
            catch { p.Dispose(); }
        }
        return new { closed = n };
    }

    public static IntPtr ExistingWindow(Entry e)
    {
        int session = Process.GetCurrentProcess().SessionId;
        IntPtr found = IntPtr.Zero;
        try
        {
            EnumWindows((h, _) =>
            {
                if (!IsWindowVisible(h) || GetWindow(h, 4 /* GW_OWNER */) != IntPtr.Zero || GetWindowTextLength(h) == 0) return true;
                GetWindowThreadProcessId(h, out uint pid);
                try
                {
                    using var p = Process.GetProcessById((int)pid);
                    if (p.SessionId != session || IsOwnOrBlocked(p)) return true;
                    if (MatchesList(p, new[] { e })) { found = h; return false; }
                }
                catch { }
                return true;
            }, IntPtr.Zero);
        }
        catch { }
        return found;
    }

    /// <summary>
    /// כל החלונות הראשיים הגלויים (עם כותרת) של התוכנה, כולל הכותרת של כל אחד מהם — משמש את סרגל הצד
    /// להציג רשימת חלונות לבחירה (למשל כמה מסמכי Word פתוחים), כתחליף בטוח ל-Alt+Tab שחסום בזמן נעילה.
    /// </summary>
    public static List<(IntPtr Handle, string Title)> ExistingWindows(Entry e)
    {
        int session = Process.GetCurrentProcess().SessionId;
        var found = new List<(IntPtr, string)>();
        try
        {
            EnumWindows((h, _) =>
            {
                if (!IsWindowVisible(h) || GetWindow(h, 4 /* GW_OWNER */) != IntPtr.Zero || GetWindowTextLength(h) == 0) return true;
                GetWindowThreadProcessId(h, out uint pid);
                try
                {
                    using var p = Process.GetProcessById((int)pid);
                    if (p.SessionId != session || IsOwnOrBlocked(p)) return true;
                    if (MatchesList(p, new[] { e })) found.Add((h, WindowTitle(h)));
                }
                catch { }
                return true;
            }, IntPtr.Zero);
        }
        catch { }
        return found;
    }

    /// <summary>כותרת החלון (למשל שם הקובץ הפתוח); מחרוזת ריקה אם אין</summary>
    private static string WindowTitle(IntPtr h)
    {
        int len = GetWindowTextLength(h);
        if (len <= 0) return "";
        var sb = new System.Text.StringBuilder(len + 1);
        GetWindowText(h, sb, sb.Capacity);
        return sb.ToString();
    }

    private static object Add(JsonElement b)
    {
        Kiosk.RequirePassword(b.Str("password"));
        string name = (b.Str("name") ?? "").Trim();
        string path = (b.Str("path") ?? "").Trim().Trim('"');
        if (name.Length == 0 || name.Length > 60) throw BridgeException.BadRequest("יש להזין שם באורך של עד 60 תווים");
        if (!System.IO.Path.IsPathRooted(path) || !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            throw BridgeException.BadRequest("יש להזין נתיב מלא לקובץ הפעלה (exe)");
        if (!ExeExists(path)) throw BridgeException.NotFound("הקובץ לא נמצא: " + path);
        string stem = System.IO.Path.GetFileNameWithoutExtension(path);
        if (Blocked.Contains(stem)) throw BridgeException.Forbidden("אי אפשר להוסיף את התוכנה הזו לרשימה");

        var procs = new List<string>();
        foreach (string p in (b.Str("procs") ?? "").Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries))
        {
            string n = System.IO.Path.GetFileNameWithoutExtension(p.Trim());
            if (!Regex.IsMatch(n, @"^[\w .\-]{1,60}$")) throw BridgeException.BadRequest("שם תהליך לא תקין: " + p);
            if (Blocked.Contains(n)) throw BridgeException.Forbidden("אי אפשר להוסיף את התהליך " + n);
            procs.Add(n);
        }

        var list = LoadManual();
        if (list.Count >= MaxPrograms) throw BridgeException.BadRequest("אפשר להגדיר עד " + MaxPrograms + " תוכנות");
        if (Load().Any(x => x.Path.Equals(path, StringComparison.OrdinalIgnoreCase)))
            throw BridgeException.Exists("התוכנה כבר ברשימה");

        list.Add(new Entry
        {
            Id = Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant(),
            Name = name,
            Path = path,
            Procs = procs.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
        });
        Save(list, b.Str("password"));
        return ListResult();
    }

    private static object Remove(JsonElement b)
    {
        Kiosk.RequirePassword(b.Str("password"));
        string id = b.Req("id");
        if (id.StartsWith("auto-", StringComparison.Ordinal))
            throw BridgeException.BadRequest("תוכנה שזוהתה אוטומטית אי אפשר להסיר. כבו את הזיהוי האוטומטי");
        var list = LoadManual();
        if (list.RemoveAll(x => x.Id == id) == 0) throw BridgeException.NotFound("התוכנה אינה ברשימה");
        Save(list, b.Str("password"));
        return ListResult();
    }

    /// <summary>מאתר תוכנות נפוצות להצעה: Word ותוכנות התורה המוכרות (בנתיבים הידועים, ואם לא — בחיפוש בכוננים)</summary>
    private static object Detect()
    {
        var found = new List<object>();
        string word = AppPath("WINWORD.EXE");
        if (word != null) found.Add(new { name = "Word", path = word, procs = "WINWORD" });
        foreach (var (name, path, procs) in KnownTorah())
            found.Add(new { name, path, procs = string.Join(", ", procs) });
        foreach (var (name, path, procs) in KnownUtilities())
            found.Add(new { name, path, procs = string.Join(", ", procs) });
        // משוב 15.10: כל התוכנות המותקנות מתפריט התחל (Excel, מחשבון וכו') — להצעה בלבד, לא אוטומטי
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, path) in StartMenuApps())
            if (seen.Add(path)) found.Add(new { name, path, procs = System.IO.Path.GetFileNameWithoutExtension(path) });
        return new { found = found.ToArray() };
    }

    /// <summary>
    /// כלים מובנים של Windows שימושיים בזמן נעילה (למשל לצילום מסך כדי לדווח על תקלה) - להצעה בלבד
    /// כאן ב-Detect(), לא ב-KnownList: אסור שאלה ייכנסו ל-DetectAuto (הזיהוי האוטומטי הוא ל"תוכנה
    /// תורנית" בלבד ודולק כברירת מחדל - תוסף מערכת לא אמור להתווסף לרשימה המותרת בלי אישור מפורש).
    /// נתיבים ידועים בלבד (בלי חיפוש בכוננים) - אלה כלי מערכת במקום קבוע, לא תוכנות שמתקינים לבד.
    /// </summary>
    /// <summary>קיצורי דרך בתפריט התחל (משותף + משתמש) שמפנים ל-exe קיים; בלי מסירי התקנה וחסומים</summary>
    private static List<(string name, string path)> StartMenuApps()
    {
        var res = new List<(string, string)>();
        try
        {
            var t = Type.GetTypeFromProgID("WScript.Shell");
            if (t == null) return res;
            dynamic sh = Activator.CreateInstance(t);
            foreach (var root in new[] { Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), Environment.GetFolderPath(Environment.SpecialFolder.Programs) })
            {
                if (!Directory.Exists(root)) continue;
                foreach (var lnk in Directory.EnumerateFiles(root, "*.lnk", SearchOption.AllDirectories).Take(400))
                {
                    try
                    {
                        string target = (string)sh.CreateShortcut(lnk).TargetPath;
                        string name = System.IO.Path.GetFileNameWithoutExtension(lnk);
                        if (string.IsNullOrEmpty(target) || !target.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || !ExeExists(target)) continue;
                        if (Regex.IsMatch(name + " " + target, @"(?i)uninstall|unins\d|הסר|setup|update|readme")) continue;
                        if (Blocked.Contains(System.IO.Path.GetFileNameWithoutExtension(target))) continue;
                        res.Add((name.Length > 60 ? name[..60] : name, target));
                    }
                    catch { }
                    if (res.Count >= 150) break;
                }
            }
        }
        catch (Exception ex) { Config.Log("programs: תפריט התחל: " + ex.Message); }
        return res.OrderBy(x => x.Item1).ToList();
    }

    private static IEnumerable<(string name, string path, string[] procs)> KnownUtilities()
    {
        string sys32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        string winApps = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "WindowsApps");
        string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var list = new (string name, string[] procs, string[] candidates)[]
        {
            // "חדש" (צילום אזור) פותח שכבת-גרירה במסך מלא דרך תהליך-עזר נפרד (ScreenClippingHost/ScreenSketch),
            // לא תחת SnippingTool.exe עצמו - בלעדי זה השומר (Kiosk.Watch) לא מזהה את שכבת הגרירה כ"מותר"
            // ומחזיר את אוצריא לחזית תוך רגע, עוד לפני שהמשתמש הספיק לגרור/לבחור אזור (נראה כמו "תקוע בטעינה")
            ("כלי חיתוך (צילום מסך)", new[] { "SnippingTool", "ScreenClippingHost", "ScreenSketch" }, new[] { System.IO.Path.Combine(sys32, "SnippingTool.exe"), System.IO.Path.Combine(winApps, "SnippingTool.exe") }),
            ("פתקים דביקים", new[] { "Microsoft.Notes" }, new[] { System.IO.Path.Combine(winApps, "StickyNotes.exe"), System.IO.Path.Combine(winApps, "Microsoft.MicrosoftStickyNotes.exe") }),
            ("שעון וטיימר", new[] { "Time", "ApplicationFrameHost" }, new[] { System.IO.Path.Combine(winApps, "Time.exe") }),
            // משוב 15.10: עוד כלים מובנים (נתיבים קבועים של Windows 10/11)
            ("פנקס רשימות", new[] { "notepad", "Notepad" }, new[] { System.IO.Path.Combine(winApps, "notepad.exe"), System.IO.Path.Combine(sys32, "notepad.exe"), System.IO.Path.Combine(win, "notepad.exe") }),
            ("מחשבון", new[] { "CalculatorApp", "Calculator", "calc", "ApplicationFrameHost" }, new[] { System.IO.Path.Combine(sys32, "calc.exe") }),
            ("צייר (Paint)", new[] { "mspaint" }, new[] { System.IO.Path.Combine(winApps, "mspaint.exe"), System.IO.Path.Combine(sys32, "mspaint.exe") }),
            ("WordPad", new[] { "wordpad" }, new[] { System.IO.Path.Combine(pf, "Windows NT", "Accessories", "wordpad.exe") }),
            ("מפת תווים", new[] { "charmap" }, new[] { System.IO.Path.Combine(sys32, "charmap.exe") }),
            ("מקלדת על המסך", new[] { "osk" }, new[] { System.IO.Path.Combine(sys32, "osk.exe") }),
            ("זכוכית מגדלת", new[] { "Magnify" }, new[] { System.IO.Path.Combine(sys32, "Magnify.exe") }),
            ("מקליט קול", new[] { "SoundRec", "VoiceRecorder" }, new[] { System.IO.Path.Combine(winApps, "SoundRec.exe") }),
        };
        foreach (var u in list)
        {
            string hit = u.candidates.FirstOrDefault(ExeExists);
            if (hit != null) yield return (u.name, hit, u.procs);
        }
    }

    // ---------- תוכנות תורה מוכרות ----------

    private record Known(string Name, string[] Exes, string[] Procs, Func<IEnumerable<string>> Candidates);

    private static IEnumerable<string> Drives()
    {
        foreach (var d in DriveInfo.GetDrives())
        {
            bool ok = false;
            try { ok = d.IsReady && (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable); } catch { }
            if (ok) yield return d.RootDirectory.FullName;
        }
    }

    /// <summary>#4: כל הכוננים המוכנים (גם רשת/וירטואלי/תקליטור) — לבדיקת נתיבים ידועים בלבד (File.Exists, זול)</summary>
    private static IEnumerable<string> AllDrives()
    {
        foreach (var d in DriveInfo.GetDrives())
        {
            bool ok = false;
            try { ok = d.IsReady; } catch { }
            if (ok) yield return d.RootDirectory.FullName;
        }
    }

    /// <summary>#7: קובץ נייד לפי תבנית שם בתיקיות המשתמש הנפוצות ובשורש הכוננים (עומק 2)</summary>
    private static IEnumerable<string> Portable(string pattern)
    {
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var roots = new[] { "Desktop", "Downloads", "Documents", "" }.Select(x => System.IO.Path.Combine(home, x)).Concat(AllDrives());
        foreach (var r in roots)
        {
            string[] hits;
            try { hits = Directory.Exists(r) ? Directory.GetFiles(r, pattern) : Array.Empty<string>(); } catch { hits = Array.Empty<string>(); }
            foreach (var h in hits) yield return h;
            string[] subs;
            try { subs = Directory.Exists(r) ? Directory.GetDirectories(r) : Array.Empty<string>(); } catch { subs = Array.Empty<string>(); }
            foreach (var sd in subs)
            {
                try { hits = Directory.GetFiles(sd, pattern); } catch { continue; }
                foreach (var h in hits) yield return h;
            }
        }
    }

    /// <summary>קבצי exe ניידים ששמם שונה: התאמה לפי פרטי הגרסה המוטבעים בקובץ (לא משתנים בשינוי שם)</summary>
    private static IEnumerable<string> ByInfo(string[] keys)
    {
        foreach (var f in Portable("*.exe"))
        {
            System.Diagnostics.FileVersionInfo vi = null;
            try { vi = System.Diagnostics.FileVersionInfo.GetVersionInfo(f); } catch { }
            if (vi == null) continue;
            var fields = new[] { vi.OriginalFilename, vi.InternalName, vi.ProductName, vi.FileDescription };
            if (fields.Any(x => !string.IsNullOrEmpty(x) && keys.Any(k => x.Contains(k, StringComparison.OrdinalIgnoreCase))))
                yield return f;
        }
    }

    private static IEnumerable<string> Under(string dir, string pattern, string tail)
    {
        string[] dirs;
        try { dirs = Directory.Exists(dir) ? Directory.GetDirectories(dir, pattern) : Array.Empty<string>(); } catch { dirs = Array.Empty<string>(); }
        return dirs.Select(x => System.IO.Path.Combine(x, tail));
    }

    private static readonly Known[] KnownList =
    {
        new("בר אילן — שו\"ת", new[] { "RESPONSA.exe" }, new[] { "RESPONSA" }, () =>
            Under(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "ResponsaCD*", "RESPONSA.exe")
            .Concat(Under(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ResponsaCD*", "RESPONSA.exe"))
            .Concat(Drives().SelectMany(r => Under(r, "ResponsaCD*", "RESPONSA.exe")))),
        new("כתבי הקודש", new[] { "כתבי הקודש.exe", "KleiKodesh.exe" }, new[] { "כתבי הקודש", "KleiKodesh" }, () =>
            new[]
            {
                System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "KleiKodesh", "כתבי הקודש.exe"),
                System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "KleiKodesh", "KleiKodesh.exe"),
                System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "KleiKodesh", "כתבי הקודש.exe"),
            }),
        new("אוצר החכמה", new[] { "otzar.exe", "אוצר החכמה.exe" }, new[] { "otzar", "אוצר החכמה", "OtzarLauncher" }, () =>
            AllDrives().SelectMany(r => new[]
            {
                System.IO.Path.Combine(r, "OtzarApp", "OtzarLocal", "launcher", "bin", "x64", "app", "otzar.exe"),
                System.IO.Path.Combine(r, "אוצר החכמה.exe"),
                System.IO.Path.Combine(r, "OtzarApp", "OtzarLocal", "launcher", "otzar.exe"),
            }).Concat(Portable("אוצר החכמה*.exe"))),
        // #6: גשר חבורתא לאוצריא
        new("חבורתא", new[] { "ChavrutaLauncher.exe" }, new[] { "ChavrutaLauncher", "Chavruta" }, () =>
            new[] { System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Chavruta", "ChavrutaLauncher.exe") }),
        // #7: הנקדן אופליין — תוכנה ניידת, איתור לפי שם הקובץ
        new("הנקדן — אוצריא", new[] { "הנקדן - אוצריא - V1.0.exe" }, new[] { "הנקדן - אוצריא - V1.0" }, () => Portable("הנקדן*.exe")),
        // עדכוני אוצריא — מזוהה גם אחרי שינוי שם הקובץ, לפי פרטי הגרסה המוטבעים (OriginalFilename/ProductName)
        new("עדכוני אוצריא", new[] { "עדכוני אוצריא.exe" }, new[] { "עדכוני אוצריא" }, () =>
            Portable("עדכוני אוצריא*.exe").Concat(ByInfo(new[] { "עדכוני אוצריא", "OtzariaUpdate", "Otzaria Update" }))),
        // עדכון ספרים אישיים — תוכנה ניידת
        new("עדכון ספרים אישיים", new[] { "BooksOfflineUpdate.exe" }, new[] { "BooksOfflineUpdate" }, () =>
            Portable("BooksOfflineUpdate*.exe").Concat(ByInfo(new[] { "BooksOfflineUpdate" }))),
        // התקנה למשתמש בלבד (כמו VS Code/Electron) תחת %LOCALAPPDATA%\Programs — לא ב-Program Files
        new("זית", new[] { "zayit.exe" }, new[] { "zayit" }, () =>
            new[] { System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "zayit", "zayit.exe") }),
    };

    private static List<(string name, string path, string[] procs)> _knownCache;
    private static DateTime _knownAt = DateTime.MinValue;

    /// <summary>לכל תוכנה מוכרת: קודם הנתיבים הידועים, ואם לא נמצאה — חיפוש לפי שם הקובץ בכוננים (עד עומק 4).
    /// התוצאה נשמרת ל-10 דקות כדי לא לסרוק שוב בכל פתיחה</summary>
    private static List<(string name, string path, string[] procs)> KnownTorah()
    {
        lock (AutoGate)
        {
            if (_knownCache != null && (DateTime.UtcNow - _knownAt).TotalMinutes < 10) return _knownCache;
            var res = new List<(string, string, string[])>();
            foreach (var k in KnownList)
            {
                string hit = null;
                try { hit = k.Candidates().FirstOrDefault(File.Exists); } catch { }
                hit ??= Search(k.Exes);
                if (hit != null) res.Add((k.Name, hit, k.Procs));
            }
            _knownCache = res;
            _knownAt = DateTime.UtcNow;
            return res;
        }
    }

    private static readonly HashSet<string> SkipDirs = new(StringComparer.OrdinalIgnoreCase)
    { "Windows", "$Recycle.Bin", "System Volume Information", "ProgramData", "Recovery", "node_modules", ".git", "AppData" };

    private static string Search(string[] exes)
    {
        var deadline = DateTime.UtcNow.AddSeconds(8);
        var roots = Drives().Concat(new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        });
        foreach (string root in roots)
        {
            var q = new Queue<(string dir, int depth)>();
            q.Enqueue((root, 0));
            while (q.Count > 0 && DateTime.UtcNow < deadline)
            {
                var (dir, depth) = q.Dequeue();
                foreach (string exe in exes)
                {
                    string p = System.IO.Path.Combine(dir, exe);
                    if (File.Exists(p)) return p;
                }
                if (depth >= 4) continue;
                try
                {
                    foreach (string sub in Directory.EnumerateDirectories(dir))
                        if (!SkipDirs.Contains(System.IO.Path.GetFileName(sub))) q.Enqueue((sub, depth + 1));
                }
                catch { }
            }
        }
        return null;
    }

    private static string AppPath(string exe)
    {
        foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                try
                {
                    using var bk = RegistryKey.OpenBaseKey(hive, view);
                    using var k = bk.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\" + exe);
                    string v = (k?.GetValue(null) as string)?.Trim().Trim('"');
                    if (!string.IsNullOrEmpty(v) && File.Exists(v)) return v;
                }
                catch { }
            }
        return null;
    }

    // ---------- זיהוי אוטומטי של תוכנות תורניות ----------

    private static List<Entry> DetectAuto()
    {
        lock (AutoGate)
        {
            if ((DateTime.UtcNow - _autoAt).TotalSeconds < 60) return _autoCache;
            var found = new List<Entry>();
            try
            {
                string word = AppPath("WINWORD.EXE");
                if (word != null) AddAuto(found, "Word", word, new[] { "WINWORD" });
                foreach (var (kn, kp, kprocs) in KnownTorah()) AddAuto(found, kn, kp, kprocs);

                var keywords = TorahKeywords.Concat(Keywords).Select(k => k.ToLowerInvariant()).ToArray();
                foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
                    foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
                    {
                        try
                        {
                            using var bk = RegistryKey.OpenBaseKey(hive, view);
                            using var root = bk.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                            if (root == null) continue;
                            foreach (string sub in root.GetSubKeyNames())
                            {
                                using var k = root.OpenSubKey(sub);
                                string display = (k?.GetValue("DisplayName") as string)?.Trim();
                                if (string.IsNullOrEmpty(display)) continue;
                                string low = display.ToLowerInvariant();
                                if (!keywords.Any(low.Contains)) continue;
                                string exe = ResolveExe(k);
                                if (exe != null) AddAuto(found, display, exe, Array.Empty<string>());
                            }
                        }
                        catch { }
                    }
            }
            catch (Exception ex) { Config.Log("programs auto-detect: " + ex.Message); }
            _autoCache = found;
            _autoAt = DateTime.UtcNow;
            return _autoCache;
        }
    }

    private static void AddAuto(List<Entry> list, string name, string path, string[] procs)
    {
        if (Blocked.Contains(System.IO.Path.GetFileNameWithoutExtension(path))) return;
        if (list.Any(x => x.Path.Equals(path, StringComparison.OrdinalIgnoreCase))) return;
        string hash = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(path.ToLowerInvariant()))).Substring(0, 8).ToLowerInvariant();
        list.Add(new Entry { Id = "auto-" + hash, Name = name, Path = path, Procs = procs, Auto = true });
    }

    /// <summary>קובץ ההפעלה של תוכנה מותקנת: לפי DisplayIcon, ואם אין — קובץ exe הגדול בתיקיית ההתקנה</summary>
    private static string ResolveExe(RegistryKey k)
    {
        string icon = k.GetValue("DisplayIcon") as string;
        if (!string.IsNullOrWhiteSpace(icon))
        {
            var m = Regex.Match(icon, "^\\s*\"?([^\",]+\\.exe)", RegexOptions.IgnoreCase);
            if (m.Success && File.Exists(m.Groups[1].Value) && !IsHelperExe(m.Groups[1].Value)) return m.Groups[1].Value;
        }
        string loc = (k.GetValue("InstallLocation") as string)?.Trim().Trim('"');
        if (!string.IsNullOrEmpty(loc) && Directory.Exists(loc))
        {
            try
            {
                return Directory.EnumerateFiles(loc, "*.exe", SearchOption.TopDirectoryOnly)
                    .Where(f => !IsHelperExe(f)).OrderByDescending(f => new FileInfo(f).Length).FirstOrDefault();
            }
            catch { }
        }
        return null;
    }

    private static bool IsHelperExe(string path)
    {
        string n = System.IO.Path.GetFileNameWithoutExtension(path).ToLowerInvariant();
        return n.StartsWith("unins") || n.StartsWith("uninstall") || n.StartsWith("setup") || n.StartsWith("update") || n.StartsWith("vc_redist");
    }

    // ---------- שילוב עם השומר של הנעילה ----------

    // תהליכים שנפתחו דרך הגשר (מזהה → זמן פתיחה). נשמרים 10 דקות, כדי לזהות גם תהליכי בן
    // של מפעיל שכבר נסגר (למשל תוכנה שמפעילה תהליך אחר שמציג את החלון).
    private static readonly Dictionary<int, DateTime> Launched = new();
    private static readonly Dictionary<int, (int parent, DateTime at)> ParentCache = new();
    private static readonly object PidGate = new();

    private static void RememberLaunched(int pid)
    {
        lock (PidGate)
        {
            foreach (int k in Launched.Where(x => DateTime.UtcNow - x.Value > TimeSpan.FromMinutes(10)).Select(x => x.Key).ToList())
                Launched.Remove(k);
            Launched[pid] = DateTime.UtcNow;
        }
    }

    private static int ParentOf(int pid)
    {
        lock (PidGate)
            if (ParentCache.TryGetValue(pid, out var c) && DateTime.UtcNow - c.at < TimeSpan.FromSeconds(10)) return c.parent;
        int parent = 0;
        try
        {
            using var q = new ManagementObjectSearcher("SELECT ParentProcessId FROM Win32_Process WHERE ProcessId=" + pid);
            foreach (ManagementObject mo in q.Get())
                using (mo) parent = Convert.ToInt32(mo["ParentProcessId"]);
        }
        catch { /* אין גישה ל-WMI */ }
        lock (PidGate) ParentCache[pid] = (parent, DateTime.UtcNow);
        return parent;
    }

    /// <summary>האם התהליך נפתח דרך הגשר, או שהוא תהליך בן (עד 6 דורות) של תהליך שנפתח כך</summary>
    private static bool IsLaunchedTree(int pid)
    {
        for (int i = 0; i < 6 && pid > 4; i++)
        {
            lock (PidGate) if (Launched.ContainsKey(pid)) return true;
            pid = ParentOf(pid);
        }
        return false;
    }

    /// <summary>תיקיות רחבות מדי כדי להתיר את כל מה שבהן (Windows, Program Files, תיקיית משתמש...)</summary>
    private static bool BroadDir(string dir)
    {
        if (string.IsNullOrEmpty(dir)) return true;
        string d = dir.TrimEnd('\\');
        string root = (System.IO.Path.GetPathRoot(dir) ?? "").TrimEnd('\\');
        if (d.Length <= root.Length) return true;
        string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\');
        if (d.Equals(win, StringComparison.OrdinalIgnoreCase) || d.StartsWith(win + "\\", StringComparison.OrdinalIgnoreCase)) return true;
        foreach (var f in new[]
        {
            Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86,
            Environment.SpecialFolder.CommonApplicationData, Environment.SpecialFolder.UserProfile,
            Environment.SpecialFolder.DesktopDirectory, Environment.SpecialFolder.MyDocuments,
            Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolder.ApplicationData,
        })
        {
            string x = Environment.GetFolderPath(f).TrimEnd('\\');
            if (x.Length > 0 && d.Equals(x, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    /// <summary>
    /// האם השומר צריך לוותר על החזרת אוצריא לחזית. כן אם: פתיחה טרייה (30 שניות), או שהתהליך בחזית הוא
    /// תוכנה מהרשימה — לפי שם תהליך, לפי קובץ ההפעלה המלא, לפי תיקיית ההתקנה (תהליכי עזר ומפעילים נפרדים),
    /// או לפי עץ התהליכים של מה שנפתח דרך הגשר.
    /// </summary>
    public static bool ShouldYieldTo(uint foregroundPid)
    {
        if (DateTime.UtcNow < GraceUntil) return true;
        try
        {
            using var p = Process.GetProcessById((int)foregroundPid);
            if (MatchesList(p, Load())) return true;
            if (IsLaunchedTree((int)foregroundPid)) return true;
            // תוכנה שהחלון שלה שייך לתהליך אחר מהקובץ שהופעל (מפעיל נפרד, תהליך עזר, מופע יחיד):
            // כל תהליך חדש שנפתח בדקות שאחרי הפתיחה דרך הגשר, שאינו מעטפת/מנהל מערכת/אוצריא/הגשר
            return !IsOwnOrBlocked(p) && IsNewAfterLaunch(p);
        }
        catch { return false; }
    }

    /// <summary>האם התהליך הוא תוכנה מהרשימה: לפי שם תהליך, קובץ הפעלה מלא, או תיקיית ההתקנה (לא רחבה)</summary>
    private static bool MatchesList(Process p, IEnumerable<Entry> list)
    {
        string fg = p.ProcessName.ToLowerInvariant();
        if (list.Any(e => ProcNames(e).Contains(fg))) return true;
        string exe = null;
        try { exe = p.MainModule?.FileName; } catch { /* תהליך מוגבה או ללא גישה */ }
        if (string.IsNullOrEmpty(exe)) return false;
        foreach (var e in list)
        {
            if (exe.Equals(e.Path, StringComparison.OrdinalIgnoreCase)) return true;
            string dir = System.IO.Path.GetDirectoryName(e.Path);
            if (!BroadDir(dir) && exe.StartsWith(dir.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    /// <summary>אוצריא, הגשר, מעטפות ומנהלי מערכת: לעולם לא "תוכנה שנפתחה"</summary>
    private static bool IsOwnOrBlocked(Process p)
    {
        if (p.Id == Environment.ProcessId) return true;
        string n = p.ProcessName;
        if (Blocked.Contains(n)) return true;
        string otz = System.IO.Path.GetFileNameWithoutExtension(Kiosk.OtzariaPath() ?? "otzaria");
        return n.Equals(otz, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>שם קובץ/תהליך (בלי סיומת) שאסור להוסיף לרשימה ולא להגדיר כאוצריא — לשימוש גם באימות שבשירות</summary>
    internal static bool IsBlockedName(string stem) => !string.IsNullOrEmpty(stem) && Blocked.Contains(stem);

    /// <summary>שם תהליך תקין לרשימה (אותו כלל כמו בהוספה דרך הגשר)</summary>
    internal static bool IsValidProcName(string n) =>
        !string.IsNullOrEmpty(n) && Regex.IsMatch(n, @"^[\w .\-]{1,60}$") && !Blocked.Contains(n);

    // מעטפות פקודה, מסופים ומארחי סקריפטים: חלון כזה בחזית בזמן נעילה נסגר בידי השומר.
    // הגשר מפעיל בעצמו cmd/powershell לפקודות עזר, אבל תמיד בלי חלון (CreateNoWindow), ולכן הם אף פעם לא בחזית
    private static readonly HashSet<string> ShellHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd", "powershell", "pwsh", "powershell_ise", "wscript", "cscript", "mshta",
        "conhost", "openconsole", "wt", "windowsterminal", "wsl", "bash",
    };

    /// <summary>האם התהליך הוא מעטפת פקודה/מסוף/מארח סקריפטים</summary>
    public static bool IsShellHost(Process p)
    {
        try { return ShellHosts.Contains(p.ProcessName); }
        catch { return false; }
    }

    /// <summary>
    /// האם התהליך בחזית הוא תוכנה מותרת. כמו ShouldYieldTo, אבל מעטפות, מארחי סקריפטים ומנהלי מערכת (Blocked)
    /// לעולם אינם "מותרים" — גם בחלון החסד שאחרי פתיחת תוכנה, וגם כשהם תהליך בן של תוכנה מהרשימה
    /// (למשל חלון שנפתח מתוך דיאלוג פתיחת קובץ של תוכנה מותרת).
    /// </summary>
    public static bool IsAllowedForeground(uint foregroundPid)
    {
        try
        {
            using var p = Process.GetProcessById((int)foregroundPid);
            if (p.Id != Environment.ProcessId && Blocked.Contains(p.ProcessName)) return false;
        }
        catch { /* תהליך שנסגר: ההחלטה נשארת ל-ShouldYieldTo */ }
        return ShouldYieldTo(foregroundPid);
    }

    private static bool StartedAfterLaunch(Process p)
    {
        var last = LastLaunchAt;
        if (last == DateTime.MinValue) return false;
        try { return p.StartTime.ToUniversalTime() >= last.AddSeconds(-3); }
        catch { return false; } // תהליך מוגבה: אין גישה לזמן ההתחלה
    }

    /// <summary>תהליך שהתחיל בין 3 שניות לפני הפתיחה דרך הגשר לבין 90 שניות אחריה</summary>
    private static bool IsNewAfterLaunch(Process p)
    {
        if (!StartedAfterLaunch(p)) return false;
        try { return p.StartTime.ToUniversalTime() <= LastLaunchAt.AddSeconds(90); }
        catch { return false; }
    }

    private delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] private static extern IntPtr GetWindow(IntPtr h, uint cmd);
    [DllImport("user32.dll")] private static extern int GetWindowTextLength(IntPtr h);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowText(IntPtr h, System.Text.StringBuilder s, int max);

    /// <summary>
    /// מחפש חלון ראשי גלוי (עם כותרת, בלי בעלים) של תהליך שהוא התוכנה שנפתחה: מהרשימה, או חדש אחרי הפתיחה
    /// (כולל תהליכי בן). כך מוצאים את החלון גם כשהוא לא שייך לתהליך עם שם הקובץ שהופעל.
    /// </summary>
    private static IntPtr FindLaunchedWindow(int session, Entry e)
    {
        IntPtr found = IntPtr.Zero;
        EnumWindows((h, _) =>
        {
            if (!IsWindowVisible(h) || GetWindow(h, 4 /* GW_OWNER */) != IntPtr.Zero || GetWindowTextLength(h) == 0) return true;
            GetWindowThreadProcessId(h, out uint pid);
            try
            {
                using var p = Process.GetProcessById((int)pid);
                if (p.SessionId != session || IsOwnOrBlocked(p)) return true;
                if (MatchesList(p, new[] { e }) || (StartedAfterLaunch(p) && (IsNewAfterLaunch(p) || IsLaunchedTree((int)pid))))
                {
                    found = h;
                    return false;
                }
            }
            catch { /* תהליך נסגר או ללא גישה */ }
            return true;
        }, IntPtr.Zero);
        return found;
    }

    /// <summary>מביא את חלון התוכנה שנפתחה לחזית (עד כ-20 שניות; תוכנות כבדות נפתחות לאט)</summary>
    private static void Focus(Entry e)
    {
        var names = ProcNames(e);
        int session = Process.GetCurrentProcess().SessionId;
        for (int i = 0; i < 40; i++)
        {
            Thread.Sleep(500);
            try
            {
                foreach (string name in names)
                    foreach (var p in Process.GetProcessesByName(name))
                    {
                        using (p)
                        {
                            if (p.SessionId != session) continue;
                            IntPtr h = p.MainWindowHandle;
                            if (h == IntPtr.Zero) continue;
                            Kiosk.BringToFront(h);
                            return;
                        }
                    }
                // החלון שייך לתהליך אחר מהקובץ שהופעל (מפעיל נפרד): מחפשים לפי החלונות הגלויים
                IntPtr w = FindLaunchedWindow(session, e);
                if (w != IntPtr.Zero)
                {
                    Kiosk.BringToFront(w);
                    Thread.Sleep(600);
                    Kiosk.BringToFront(w);
                    Config.Log("programs focus: החלון נמצא לפי תהליך חדש ולא לפי שם הקובץ (" + e.Name + ")");
                    return;
                }
            }
            catch (Exception ex) { Config.Log("programs focus: " + ex.Message); }
        }
    }
}
