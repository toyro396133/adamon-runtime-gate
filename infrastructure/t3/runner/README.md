# התאמת Runner מוגנת — מימוש מועמד

מקור ציבורי בלבד: `actions/runner` v2.338.0, commit
`197ca027b90de199464dee3bb9ff198a1db60967`. שום קוד מחקר פרטי אינו כלול כאן.

`apply_patch.py` מסרב למקור אחר או checkout מלוכלך, מאמת ארבעה SHA256,
מבצע `git apply --check` ורק אחר כך מחיל patch ומוסיף bridge.
`runner-v4.patch` מחליף Worker spawn ישיר בפנייה ל־supervisor דרך FD מוגן;
מבטל העברת stdout/stderr של Worker; מאמת raw assignment לפני הרצת Job;
מדלג על JobExtension setup/finalize hooks; יוצר צעד Main יחיד;
ומחליף `step.RunAsync()` בקריאה סגורה ללא shell/fallback.

`P4ProtectedBridge.cs` משתמש רק ב־FD198 ל־Listener ו־FD199 ל־Worker,
שעל ה־supervisor ליצור ולהוריש. SCM_RIGHTS מעביר שני pipe descriptors
שה־Listener יצר. המסגור הוא uint32 big-endian + JSON, בגבול 1MiB,
עם UUID לכל בקשה וחמש פעולות בלבד. אין address/path/command/seed בקשת משתמש.
ה־bridge מאמת socket type בלבד; הוא **אינו** מוכיח מקור FD, UID או pidfd.
הוכחה זו חייבת לבוא מ־supervisor שמחזיק handles לפני יצירת תהליכים.
פרטי Job ו־tokens מועברים רק ב־IPC פרטי, לא ל־public log.

Assignment gate דורש Job GUID/Plan GUID/RequestId, github context, צעד script
יחיד וליטרלי, marker מדויק, condition success(), ללא overrides/hooks/containers.
ה־supervisor נדרש לאמת workflow/ref/SHA/REST correlation/permit באופן עצמאי.
לא מתקבל credential ממזהה Job ציבורי. שינוי serialized assignment לאחר
raw acknowledgement נדחה. bootstrap/authorize מוגבלים ל־30 שניות.
Cancellation שולח revoke; observer supervisor עצמאי חייב להרוג cgroup
גם אם ה־FD נכשל. revoke אינו ראיה להריגה שהתרחשה.

## בדיקות ובנייה

```
python -m unittest discover -s infrastructure/t3/runner/tests -v
python infrastructure/t3/runner/apply_patch.py /path/to/clean/pinned/runner
DOTNET_CLI_TELEMETRY_OPTOUT=1 dotnet build src/Runner.Listener/Runner.Listener.csproj \
  -c Release -p:Version=2.338.0 -p:BuildNumber=0 \
  -p:RuntimeIdentifiers= -p:RuntimeIdentifier= -p:SelfContained=false
```

בדיקות Python הן בדיקות source boundary ו־applier, לא בידוד Runtime.
מימוש Linux spawn/clone3/execveat/UID/cgroup/LSM והקשר authenticated Listener
טרם הוכחו. supervisor חסר מחזיר BLOCKED, ולא מפעיל Worker או מחקר.
אין Job registration, deployment, GitHub Actions run או ניסוי T3 כאן.
החבילה אינה runner מותקן, אינה execution freeze ואינה הרשאה למחקר.

המוביל אימת מחדש החלה על checkout נקי ומוצמד. source tree המתקבל הוא
`db277ecf8ca79d1d78ea57c098670f5f145c2741`, וחותמות ארבעת השינויים וה־overlay
ב־`implementation_receipt.json`. `UPSTREAM_LICENSE` משמר את רישיון המקור.
לא נוצר מאגר fork מרוחק נוסף; ה־patch הציבורי משחזר מקור מותאם מדויק.

קוד ה־bridge עצמו התקמפל עם SDK8.0.425 כנגד upstream-shape test doubles,
ושבע בדיקות Unix stream/SCM_RIGHTS אמיתיות עברו. זוהי ראיה לתעבורה בלבד,
לא לבניית Listener/Worker המלאים או לתאימות GitHub. קומפילציית bridge נתנה
אזהרת CS1701 בגלל הפניה של Newtonsoft ל־System.Runtime6 מול net8.
שלושה ניסיונות build מלא נעצרו ב־NuGet restore עקב ENOSPC לפני compiler;
אין תוצאת PASS לבנייה המלאה.
