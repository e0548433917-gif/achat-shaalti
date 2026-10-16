using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace OtzariaBridge;

/// <summary>
/// שומר מהיר (כל 300ms, בנוסף ל-Watch שרץ כל 2 שניות): סוגר חלונות חורגים שנפתחים מתוך כלי החיתוך המאושר -
/// "שמירה בשם" (PickerHost, מאפשר לדפדף בכל המחשב), חלונית "שתף" (חלון ApplicationFrameWindow בתוך explorer),
/// תפריט התחל/חיפוש/מעבר-משימות - ומסתיר את שורת המשימות כש-explorer חי בזמן הצילום.
/// </summary>
public static partial class Kiosk
{
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetClassName(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr FindWindowEx(IntPtr parent, IntPtr after, string cls, string title);
    [DllImport("user32.dll")] private static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);

    private static System.Threading.Timer _fastGuard;
    private static int _fastBusy;
    private static readonly int MySession = Process.GetCurrentProcess().SessionId;

    private static void StartFastGuard() => _fastGuard ??= new System.Threading.Timer(_ => FastGuard(), null, 0, 300);

    private static bool _taskbarHidden;

    private static void StopFastGuard()
    {
        _fastGuard?.Dispose();
        _fastGuard = null;
        // שחרור הנעילה חייב להחזיר את שורת המשימות שהוסתרה (אחרת היא נעלמת גם אחרי הביטול)
        if (_taskbarHidden) SetTaskbars(true);
    }

    private static void SetTaskbars(bool show)
    {
        foreach (string cls in new[] { "Shell_TrayWnd", "Shell_SecondaryTrayWnd" })
        {
            IntPtr h = IntPtr.Zero;
            while ((h = FindWindowEx(IntPtr.Zero, h, cls, null)) != IntPtr.Zero) ShowWindow(h, show ? 5 /* SW_SHOW */ : 0 /* SW_HIDE */);
        }
        _taskbarHidden = !show;
    }

    private static void FastGuard()
    {
        if (!IsActive)
        {
            if (_taskbarHidden) SetTaskbars(true); // Release כבר רץ - לא משאירים את שורת המשימות מוסתרת
            return;
        }
        if (Interlocked.Exchange(ref _fastBusy, 1) == 1) return;
        try
        {
            if (_snipSeen != DateTime.MinValue && IsActive) SetTaskbars(false); // explorer חי בזמן הצילום - שורת המשימות לא תוצג
            else if (_taskbarHidden) SetTaskbars(true);             // הצילום הסתיים: מחזירים (explorer יעלה מחדש/יימחק כרגיל)

            IntPtr fg = GetForegroundWindow();
            if (fg == IntPtr.Zero) return;
            GetWindowThreadProcessId(fg, out uint pid);
            if (pid == 0 || pid == (uint)Environment.ProcessId) return;
            using var p = Process.GetProcessById((int)pid);
            if (p.SessionId != MySession) return;

            string name = p.ProcessName;
            var sb = new StringBuilder(128);
            GetClassName(fg, sb, sb.Capacity);
            string cls = sb.ToString();

            bool closeIt =
                (name.Equals("PickerHost", StringComparison.OrdinalIgnoreCase) && cls == "#32770") ||
                (name.Equals("explorer", StringComparison.OrdinalIgnoreCase) &&
                 (cls is "ApplicationFrameWindow" or "XamlExplorerHostIslandWindow" ||
                  (cls == "CabinetWClass" && !Programs.InForegroundGrace))); // "הצגה בסייר Windows" נפתח בכוונה, עם חלון חסד
            if (closeIt)
            {
                PostMessage(fg, 0x0010 /* WM_CLOSE */, IntPtr.Zero, IntPtr.Zero);
                LogThrottled("fast:" + name + cls, "watchdog: נסגר חלון חסום בנעילה (" + name + " / " + cls + ")", 30);
                Tray.Notify(Program.AppName, Lang.T("החלון הזה חסום בזמן נעילה", "This window is blocked while locked"));
            }
            else if (name is "StartMenuExperienceHost" or "SearchHost")
            {
                p.Kill();
                LogThrottled("fast:" + name, "watchdog: " + name + " נסגר (תפריט התחל/חיפוש חסומים בנעילה)", 30);
            }
        }
        catch { /* חלון/תהליך נסגר באמצע */ }
        finally { Interlocked.Exchange(ref _fastBusy, 0); }
    }
}
