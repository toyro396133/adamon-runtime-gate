# תשתית T3 — מועמד מימוש, ללא הרשאת ניסוי

הקוד מחולק ל־`runner/`, `security/`, `roles/`, `storage/` ו־`preflight/`.
מתאמי המחקר והסמכות הפרטית אינם במאגר הציבורי. כל חישוב מחקרי עתידי
נדרש להתבצע בתוך Job של GitHub Actions, על אותו host, עם microVM מקומי.
אין שירות RPC שמבצע מחקר במחשב אחר.

אין להפעיל LIFE/MICRO/AUDIT/AGGREGATION מחקריים בחבילת המימוש הנוכחית.
סמכות הביצוע לא הוקפאה ולא הונפק היתר מחקר. תבנית ההפעלה נמצאת מחוץ
ל־`.github/workflows`; אין Workflow ניסויי מותקן.

## בדיקות פיתוח שאינן מחקר

```sh
python3 -m venv /workspace/.cache/t3-dev-venv
/workspace/.cache/t3-dev-venv/bin/pip install -r infrastructure/t3/requirements-tested.txt
PYTHONDONTWRITEBYTECODE=1 /workspace/.cache/t3-dev-venv/bin/python -m pytest -q infrastructure/t3
/workspace/.cache/t3-dev-venv/bin/python infrastructure/t3/preflight/check.py --probe
```

פקודת probe מחזירה exit 2 כש־Preflight לא הושלם. זו אינה בדיקת קבלה
לניסוי, ויש לשמר את מצב UNVERIFIED של בידוד מערכת ההפעלה, תאימות
Runner, שירותי האחסון וההרשאות שעדיין לא נבדקו. אין סודות בקובץ התלויות.

ה־Runner upstream מוצמד ל־`v2.338.0` ול־commit
`197ca027b90de199464dee3bb9ff198a1db60967`. התאמת המקור נמצאת כ־patch
מדויק ו־overlay, ללא מאגר fork כפול. build/registration/broker/legacy
ו־cancel descendants מחייבים Preflight עצמאי לפני פריסה.

בדיקות S3 המבוססות על לקוח מדומה בודקות את חוזה SDK בלבד; אחסון מקומי
מוצפן אינו הוכחה ל־Object Lock. קבלות הרכיבים מפרטות את גבולות האימות.

## הכרעת מסירה

`T3_INFRASTRUCTURE_IMPLEMENTATION_PARTIAL`. נוספו גם `runtime/` ו־`integration_tests/`. 136 בדיקות מרכזיות וארבע בדיקות משנה עברו בשני המאגרים; שבע בדיקות transport עברו ב־C# עם upstream type doubles. אין להסיק מכך שה־Runner המלא נבנה או שבידוד privileged נבדק. ניסיונות restore של ה־Runner המלא נעצרו בשל ENOSPC.

חסרים חיבורי deployment מאומתים בין הקצאת GitHub, supervisor, Launcher ותמונת guest, וכן כיסוי מדידות וסגירת כל שערי הקבלה. נקודות הכניסה המחקריות חסומות ללא אפשרות הפעלה. נדרשים השלמת קוד וביקורת מימוש, ולא רק הפעלת preflight.

## 2026-10-11 — המשך חיבור Runtime

נוספו מפענח Assignment לפי המקור המוצמד, חיבור REST–Worker–Supervisor, מפעל תהליכים native, Session mTLS/challenge/ledger, הזרקת מקור מאומתת ושרשרת ראיות חתומה. בדיקות הבתים וה־bootstrap מחוברות בפועל בין הרכיבים. 209 בדיקות ו־17 בדיקות משנה עברו בשני המאגרים; שבע בדיקות C# transport עברו בנפרד. זו תערובת של unit/synthetic ושל קריפטוגרפיה, sockets ותהליכים מקומיים אמיתיים, ולא הרצת Job ב־Actions.

הסטטוס נשאר PARTIAL: אין רשת ו־mounts מחוברים ל־namespace, אין Launcher/guest image מוכנים, אין KVM בסביבה, Runner מלא חסום ב־NETSDK1004/אחסון, וכיסוי השערים הפרטי חלקי. אין research entry או terminal PASS מורשים. receipt ומניפסט חדשים משמרים את קבלות הסבב הקודם כהיסטוריה.
