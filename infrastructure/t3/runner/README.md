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
`dd76b7e1054d1e4070b1024ec27466474154500e`, וחותמות ארבעת השינויים וה־overlay
ב־`implementation_receipt.json`. `UPSTREAM_LICENSE` משמר את רישיון המקור.
לא נוצר מאגר fork מרוחק נוסף; ה־patch הציבורי משחזר מקור מותאם מדויק.

קוד ה־bridge עצמו התקמפל עם SDK8.0.425 כנגד upstream-shape test doubles,
ושבע בדיקות Unix stream/SCM_RIGHTS אמיתיות עברו. זוהי ראיה לתעבורה בלבד,
לא לבניית Listener/Worker המלאים או לתאימות GitHub. קומפילציית bridge נתנה
אזהרת CS1701 בגלל הפניה של Newtonsoft ל־System.Runtime6 מול net8.
שלושה ניסיונות build מלא נעצרו ב־NuGet restore עקב ENOSPC לפני compiler;
אין תוצאת PASS לבנייה המלאה.

## חיבור Runtime — עדכון המשך

`assignment.py` מפענח את פורמט המקור המוצמד, כולל DictionaryContextData
מסוג t=2 ו־TemplateToken map. מפענח זה אינו מקור הרשאה: הוא דורש digest
של ה־Listener המהימן ומעביר זהות לבדיקת REST נפרדת. Job GUID, check_run_id
ומזהה REST Job נשארים תחומים נפרדים. runner_id חייב לבוא מה־supervisor
ומהתאמת REST, ולא משדה שה־Workflow בחר. check_run_id נקשר ל־check_run_url
של Job ולא מונח כשווה ל־job.id. חסר במקור הזהות נכשל סגור.

עיון בקוד המקור האמיתי גילה ש־MappingToken.Count הוא internal ל־Sdk
ואינו חשוף ל־Runner.Common. תוקן השימוש ל־Enumerable.Count(), דרך הממשק
הציבורי IEnumerable. Transport doubles עודכנו בהתאם, אך אינם מוכיחים
תאימות מלאה. debugger, snapshot, job output ו־ActionsEnvironment נדחים כעת.

20 בדיקות Python עברו, ובהן 13 בקרות פענוח שליליות/חיוביות; שבע בדיקות
תעבורה אמיתיות עברו שוב על ה־bridge המעודכן. ניסיון build ללא restore
נעצר ב־NETSDK1004 כי project.assets.json לא קיים. בסביבה היו כ־284MiB
פנויים ב־workspace וכ־81MiB ב־tmp; לא נמחקה ראיה היסטורית ולא נבחרה
סביבת בנייה חלופית בלתי מורשית. אין ראיית build מלא או Job מאומת חי.

מקורות לעיון: src/Sdk/DTPipelines/Pipelines/ContextData/PipelineContextDataJsonConverter.cs,
src/Runner.Worker/JobContext.cs, src/Sdk/DTObjectTemplating/ObjectTemplating/Tokens/TemplateTokenJsonConverter.cs,
src/Sdk/DTObjectTemplating/ObjectTemplating/Tokens/MappingToken.cs ו־src/Sdk/InternalsVisibleTo.cs
ב־commit הציבורי המוצמד לעיל.

נבדק גם JsonUtility.cs:255: ה־serializer המוצמד משתמש ב־VssJsonMediaTypeFormatter
עם camelCase resolver. לכן המפענח מקבל contextData/jobId/steps ו־map key/value
ולא DTO בדיקה עם PascalCase. ערבוב אותיות או כפילויות נדחים.

### קשירת היתר — מזהה repository וטביעת Step

המפענח דורש גם github.repository_id חיובי, ש־REST צריך לאמת מול מזהה
המאגר. step_sha256 מחושב כ־SHA256 של כל אובייקט Step המפוענח בפורמט
`security.protocol.canonical`: מפתחות ממוינים, ASCII, ללא whitespace,
מספרים שלמים בטווח הבטוח וללא float. ה־raw assignment digest נשאר עוגן
נפרד לבתים המקוריים. הגדרת קידוד זו היא החלטת מימוש prospective לתשתית,
ואינה משנה סמכות מחקר או מתיימרת להיות SHA של מקטע JSON מקורי.
Step Unicode או מספר float שאינם מתקבלים ב־codec נדחים סגור. היתר הבעלים
חייב להשתמש באותה הגדרה בדיוק; אין קבלה של hash שנבחר על ידי Workflow.

### בדיקת graph בנייה ללא רשת — 2026-10-12

`build_graph.py` קורא רק checkout קיים. הוא מאמת HEAD, חמשת קובצי ה־patch,
כל csproj בגרף Listener/Worker, global.json ו־Directory.Build.props מול המקור
המוצמד; דוחה ProjectReference החורג מן המקור ו־PackageReference צף. אין restore,
הורדה או הרצת Runner. `build_prerequisites_receipt.json` מתעד את חמשת הפרויקטים,
גרסאות התלויות הישירות והחסר ב־assets. גרסאות ישירות אינן lock לתלויות טרנזיטיביות:
ה־receipt מסמן במפורש שגם אימות content pins של NuGet וגם build מלא חסרים.
פקודת הבנייה המוצעת כוללת `--no-restore`, ואינה workflow מותקן.

### מניעת חשיפה בשגיאת פענוח מוקדמת

ValidateAssignment מסנן JsonException ו־FormatException לפני שה־Worker יכול
להתקין SecretMasker. החריגה מוחלפת בקוד קבוע ללא inner exception או fragment.
שמונה בדיקות C# עברו על ה־bridge המעודכן: שבע בדיקות התעבורה ועוד שליחת
JSON פגום עם sentinel ווידוא שאינו מופיע ב־stdout/stderr. הקומפילציה עדיין
משתמשת ב־upstream-shape doubles; אזהרת CS1701 נשארת ו־Runner מלא לא נבנה.
