using System.Globalization;

namespace OtzariaBridge;

/// <summary>
/// חלון זמן יומי לנעילה מתוזמנת (גרסה 3.x). תומך בחלון שחוצה חצות, למשל 20:00–02:00:
/// הנעילה פעילה מ-20:00 בערב עד 02:00 בלילה, ובשאר השעות המחשב רגיל.
/// פונקציה טהורה וקלה לבדיקה — אותו היגיון משמש את הגשר (נעילה רכה) ואת השירות (נעילה מוקשחת).
/// </summary>
public static class Sched
{
    /// <summary>מנתח "HH:mm" ל-TimeSpan; null אם אינו תקין</summary>
    public static TimeSpan? ParseTime(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        if (TimeSpan.TryParseExact(s.Trim(), new[] { @"hh\:mm", @"h\:mm" }, CultureInfo.InvariantCulture, out var t)
            && t >= TimeSpan.Zero && t < TimeSpan.FromDays(1))
            return t;
        return null;
    }

    public static bool IsValid(string s) => ParseTime(s) != null;

    /// <summary>
    /// האם 'now' (לפי שעון מקומי) נמצא בחלון [start, end).
    /// start==end או זמן לא תקין → תמיד false (כדי לא לנעול בטעות לכל היום).
    /// start&lt;end → חלון באותו יום; start&gt;end → חלון שחוצה חצות.
    /// </summary>
    public static bool InWindow(string start, string end, DateTime now)
    {
        var s = ParseTime(start);
        var e = ParseTime(end);
        if (s == null || e == null || s == e) return false;
        var t = now.TimeOfDay;
        return s < e ? (t >= s && t < e) : (t >= s || t < e);
    }

    /// <summary>הרגע שבו נגמר החלון הנוכחי (אם 'now' בתוכו), אחרת null. חלון שחוצה חצות: אם הסוף כבר עבר היום - מחר</summary>
    public static DateTime? CurrentWindowEnd(string start, string end, DateTime now)
    {
        if (!InWindow(start, end, now)) return null;
        var e = ParseTime(end)!.Value;
        var endToday = now.Date + e;
        return endToday > now ? endToday : endToday.AddDays(1);
    }

    /// <summary>סוף החלון המאוחר ביותר מבין כמה חלונות שבהם 'now' נמצא (הראשי + נוספים); null אם באף אחד</summary>
    public static DateTime? CurrentWindowEnd(IEnumerable<(string start, string end)> windows, DateTime now)
    {
        DateTime? best = null;
        foreach (var (s, e) in windows)
            if (CurrentWindowEnd(s, e, now) is DateTime x && (best == null || x > best)) best = x;
        return best;
    }

    /// <summary>"HH:mm-HH:mm,HH:mm-HH:mm" → חלונות. פריט לא תקין מדולג</summary>
    public static List<(string start, string end)> ParseWindows(string csv)
    {
        var list = new List<(string, string)>();
        foreach (var part in (csv ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            var p = part.Trim().Split('-');
            if (p.Length == 2 && IsValid(p[0]) && IsValid(p[1])) list.Add((p[0], p[1]));
        }
        return list;
    }
}
