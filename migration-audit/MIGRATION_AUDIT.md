# Audit הגירה: benchmark למערכות התאמת טביעות אצבע מלאות

תאריך הבדיקה: 2026-07-21  
שלב: `audit_only`  
ריפו מקור: `C:\fingerprint-recognition-research` (`0893d50d08972fc68337749332ecdaa0faef2a70`)  
בסיס נתונים מועמד: `C:\fingerprint-datasets\NIST\_curation\stage0_v1`

## 1. תקציר מנהלים

פסק הדין הוא **`READY_WITH_OPEN_QUESTIONS`**. ארבעת ה־manifests הקיימים של Stage 0 תקינים ועקביים: 50 נבדקים ייחודיים, 10 אצבעות לכל נבדק, 500 זוגות genuine ו־500 זוגות impostor לכל release, אותו סדר לוגי ב־SD300B וב־SD300C, מיפוי אגודלים נכון, ללא FRGP 13/14, וכל הנתיבים וה־hashes תואמים ל־inventory הקפוא. לא נמצא שימוש ב־matcher בבחירה.

עם זאת, אין לאשר את Stage 0 כ־`READY` סופי לפני הכרעה בארבע נקודות:

1. `stage0_config.yaml` הנוכחי אינו תואם ל־`config_sha256` שב־lock. ההבדל הסמנטי היחיד הוא הוספת `verification_dir`, אך גם הערות הקובץ השתנו לאחר ההקפאה ולכן ה־hash הבת־לבתי שונה.
2. `manual_review_decisions.csv` הוא קלט שמשפיע בפועל על המדגם, אך אינו ננעל כקלט עצמאי ב־`manifest_lock.json`.
3. החסימה של `00001585` ו־`00001586` נשענת על `prior_report` חשוד ולא מאומת. היא אלגוריתם־עצמאית, אך מוסיפה תנאי מעבר ל־10×10 המבני ודורשת אישור מנחה.
4. יצירת PLAIN-self ו־ROLL-self תוסיף תוצרי פרוטוקול ולכן מחייבת lock וגרסת protocol חדשים, בלי לשנות את cohort או את Stage 0 המקורי.

הגירת הקוד צריכה לשמר את תשתית ה־benchmark הכללית ואת SourceAFIS end-to-end בלבד. כל SIFT, RootSIFT, Harris/GFTT, local features, detector-only, final-minutiae, RANSAC, DeepPrint, FingerCode ו־phase-only correlation מוחרגים.

## 2. היקף ושיטת הבדיקה

הבדיקה בוצעה בקריאה בלבד מתוך הקוד, הקונפיגורציה, קובצי CSV/JSON, hashes ו־lock קפואים. לא הופעל Stage 0 מחדש, לא נסרקו מחדש 106GB, ולא חושב hash מחדש לתמונות הגולמיות. במקום זאת:

- הושוו ה־manifests ישירות זה לזה ול־`dataset_inventory.csv`;
- נבדק קיום 4,000 הפניות path ושוויון 4,000 הפניות hash ל־inventory (2,000 לכל release);
- חושבו hashes רק לתוצרי curation הקפואים והקטנים/בינוניים;
- נבדקו קוד הבחירה, קוד ההחרגה, קוד duplicate review וקוד ה־freeze;
- הוצלבו `_analysis` ו־`_curation` ברמת key, filename, dimensions, FRGP ו־PPI;
- נותחו imports, symbols, CLI branches, Java endpoints, Maven dependencies והבדיקות בריפו המקור.

לא הופעל SourceAFIS, לא הופעל matcher אחר, לא נבחר cohort מחדש ולא נוצר manifest חדש.

## 3. אימות Stage 0 מתוך הקבצים

| בדיקה | ממצא |
|---|---|
| נבדקים | 50 שורות, 50 IDs ייחודיים; `subject_index` הוא 1–50 והסדר זהה לקובץ הטקסט |
| שלמות לכל release | לכל נבדק 10 PLAIN, 10 ROLL ו־10 אצבעות קנוניות |
| genuine | 500 שורות בכל release; 50 לכל אצבע; אותו subject ואותה אצבע משני הצדדים |
| impostor | 500 שורות בכל release; 50 לכל אצבע; subjects שונים; offset ציקלי 1 לפי סדר 50 הנבדקים |
| cross-release | מבנה pair IDs, נבדקים, אצבעות וסדר זהים בין B ו־C |
| אגודלים | PLAIN 11→canonical 1 ו־PLAIN 12→canonical 6 בכל השורות הרלוונטיות |
| slaps | אין FRGP 13 או 14 ב־manifests |
| נתיבים | כל path בארבעת ה־manifests קיים |
| hashes | כל hash ב־manifests תואם ל־`dataset_inventory.csv` |
| nominal PPI | כל שורת SD300B היא 1000 וכל שורת SD300C היא 2000 |
| שחזור הבחירה | `sorted(random.Random(20260720).sample(sorted_pool, 50))` משחזר בדיוק את הרשימה והסדר הקפוא |

`protocol_manifest_summary.json` מאשר 23 זוגות challenge ו־477 valid בכל genuine manifest; challenge נשמר ולא סונן.

### 3.1 Lock ו־hashes

- 27/27 artifacts שב־`manifest_lock.json` תואמים byte size ו־SHA-256 לקבצים הנוכחיים.
- 13/13 סקריפטים הרשומים ב־lock תואמים ל־SHA-256 הנוכחי.
- 28/28 הרשומות ב־`MANIFEST_SHA256SUMS.txt` תואמות, כולל `manifest_lock.json` עצמו.
- `raw_data_verification.json` הקפוא מדווח 19,435/19,435 התאמות לכל release מול checksums רשמיים, ללא mismatch. בדיקה זו לא הורצה מחדש במסגרת audit זה.
- `manifest_lock.json` מכסה את 27 התוצרים שב־`FROZEN_ARTIFACTS`, אך אינו מכסה את `raw_data_verification.json`, את דוחות `stage0_summary.*`, את קובצי `verification\`, או את `manual_review_decisions.csv` כקלט נפרד.

### 3.2 כשל התאמת הקונפיגורציה

ה־lock שומר:

```text
config_sha256 = 4903c78b3d93218e05b834fc4d9a4308defda894b1a7e47d3169f5aa07bc7570
```

הקובץ הנוכחי הוא:

```text
sha256(stage0_config.yaml) = 3c0fbd38861da31b5bb015f62d7332a58863527529580e5a8a8a66406529e7f3
```

ה־lock נכתב ב־19:07:48 UTC והקונפיגורציה שונתה ב־19:33:10 UTC. השוואת YAML סמנטית מצאה תוספת יחידה: `verification_dir`; יתר השינוי הוא הערות. התוצרים עצמם עדיין תואמים ל־lock, אך שרשרת השחזור מהקובץ הנוכחי אינה סגורה. אין להריץ או לתקן זאת במסגרת audit; בשלב המימוש יש לשחזר את קובץ הקונפיגורציה הנעול או להקפיא גרסה חדשה במפורש.

## 4. 832 לעומת 830 ו־duplicate blocking

`_analysis\subset_gold_subjects.txt` מכיל בדיוק 832 נבדקים. זו בדיוק אותה קבוצה שמסומנת `has_all_10_in_both=true` ב־`eligible_subjects.csv`; אין IDs עודפים או חסרים באף צד.

שני נבדקים מבניים הוצאו מ־eligible pool:

| subject | evidence | status | תוצאת Stage 0 |
|---|---|---|---|
| `00001585` | `prior_report` | `suspected` | blocked |
| `00001586` | `prior_report` | `suspected` | blocked |

הראיה המדויקת היא משפט בקונפיגורציה: הזוג סומן במפרט Stage 0 כחשד לאותו אדם, ולא אושר עצמאית. `duplicate_identity_review.csv` אינו מכיל score, matcher או ראיה ביומטרית. לא נמצאה התנגשות SHA-256 חוצת־subjects ולא נמצא finding נוסף בריצה הקפואה.

ההחלטה תואמת את האיסור להשתמש ב־matcher, אך אינה נובעת מדרישת 10 PLAIN + 10 ROLL. זו חסימה שמרנית שנועדה למנוע genuine סמוי ב־impostor, ולכן היא מוצדקת הנדסית אך **`UNCERTAIN` מחקרית עד אישור המנחה**. אין לשנות את הזוג או לבחור חלופה במסגרת ההגירה.

קיים גם פער פנימי בקוד: ההערה ב־`review_duplicates.py` מגדירה `identical_dimensions_set` כ־weak triage שאינו חוסם לבדו, אך branch של `identical_geometry_signature` כן קובע `selection_blocked=true`. בריצה הקפואה branch זה לא יצר finding ולכן לא שינה את ה־cohort, אך יש לתקן את המדיניות לפני freeze עתידי.

## 5. ביקורת מדיניות הבחירה וההחרגה

| תנאי | סוג | אלגוריתם־עצמאי | הטיית איכות אפשרית | השפיע בפועל |
|---|---|---:|---:|---:|
| 50 נבדקים, 10 PLAIN, 10 ROLL, אותה אצבע | דרישת מנחה | כן | לא | כן |
| missing counterpart | שלמות מבנית | כן | נמוכה | כן: 56 נבדקים לא שלמים |
| duplicate suspected pair | תנאי נוסף | כן | לא איכותית, אך משנה אוכלוסייה | כן: 832→830 |
| blank/no-ridge thresholds | תנאי נוסף | כן | גבוהה אילו הופעל | לא: no-ridge הושבת, blank לא הופעל |
| challenge classification | תיוג נוסף | כן | לא, משום שנשמר | כן בתיעוד בלבד |
| manual review | תנאי נוסף | כן | אפשרית | כן, בעקיפין ובאופן מהותי |
| seeded random sample | מנגנון בחירת 50 | כן | לא מבוסס איכות | כן |
| `_analysis` quality rank/density | heuristic | כן, אך אינו תקן איכות | גבוהה | לא נקרא בקוד Stage 0 |

כל 202 ההחרגות בריצה הן `missing_counterpart`; אין החרגת תוכן ואין reason שמקורו ב־matcher. `no_ridge_block_frac=0.0` ו־`no_ridge_largest_cc=0` משביתים למעשה את כלל no-ridge. 1,182 רשומות סומנו challenge, ו־210 subjects eligible כוללים challenge records.

### 5.1 השפעת manual review

11 logical records אצל ארבעה subjects נבחנו ידנית וסווגו `challenge`, כלומר נשמרו. שלושה מהם (`00001019`, `00001111`, `00001281`) הם בעלי 10×10 מלא ונכנסו ל־eligible pool; `00001738` אינו שלם. אף אחד מארבעת ה־subjects לא נבחר לבסוף.

עם זאת, אילו שלושת הנבדקים המלאים היו נשארים `manual_review_required`, pool הדגימה היה קטן מ־830 ל־827. בשל דגימה לפי index מתוך רשימה ממוינת, המדגם החוזר היה מחליף 45 מתוך 50 הנבדקים. לכן manual review **השפיע בפועל על cohort**, אף שהנבדקים שנבדקו ידנית אינם בתוצאה. יש לנעול את קובץ ההחלטות, את ה־hash שלו ואת מדיניות ההכרעה.

### 5.2 quality heuristics

אין reference ל־`subject_quality_rank.csv`, `roll_density_1000.csv` או `_analysis` בסקריפטי Stage 0. הבחירה קוראת רק `eligible_subjects.csv` ו־`duplicate_identity_review.csv`. שני נבדקים שנבחרו נמצאים בין 50 התחתונים בדירוג density של `_analysis`, ראיה נוספת לכך שהדירוג לא שימש לסינון.

## 6. `_analysis` לעומת `_curation`

| קובץ analysis | תפקיד | החלטה |
|---|---|---|
| `README.md` | תיעוד מוקדם של מבנה, FRGP ו־PPI | potentially reusable documentation, לאחר REWRITE |
| `master_index.csv` | preliminary structural analysis | corroborating evidence; obsolete כקלט פרוטוקול |
| `genuine_pairs.csv` | כל 8,779 ה־PLAIN↔ROLL joins | corroborating evidence; unsafe protocol input |
| `subset_gold_subjects.txt` | 832 subjects מבניים | corroborating evidence; הוחלף ב־eligible/duplicate policy |
| `subset_gold_pairs.csv` | 8,320 pairs של ה־832 | obsolete after stage0_v1 |
| `subset_native_registered.csv` | 12,397 native captures ב־2× | corroborating evidence בלבד |
| `sd300c_bad_ppi_files.txt` | 10,115 pHYs חריגים | corroborating evidence, תואם בדיוק ל־curation |
| `subject_quality_rank.csv` | quality heuristic | אסור כקלט בחירה |
| `roll_density_1000.csv` | quality heuristic | אסור כקלט בחירה |

הצלבות מדויקות:

- 19,435 keys ב־`master_index.csv` זהים ל־19,435 keys ב־`cross_resolution_map.csv`.
- filenames וכל ארבעת שדות הממדים תואמים ללא mismatch.
- 8,779 genuine pairs ב־analysis זהים בדיוק ל־`all_genuine_pairs_sd300b.csv` ברמת subject, canonical finger ושני filenames.
- מיפוי 11→1 ו־12→6 זהה ואין slaps בזוגות.
- רשימת 10,115 קובצי PPI חריגים זהה בדיוק.

סתירה תיעודית אחת נשארת: README של `_analysis` טוען שחלק מ־66 רשומות amputated מכילות AMP בלבד, ואילו Stage 0 טוען שלא נמצא AMP/blank ומנטרל content exclusion. Stage 0 לא תיעד adjudication פרטני של כל 66 הרשומות; מצד שני, הרשומות חסרות counterpart ממילא אינן יכולות להיכנס ל־832 או ל־50. הסתירה אינה משנה את cohort הקפוא, אך יש לשמר אותה כ־diagnostic ולא למחוק אותה בשכתוב התיעוד.

## 7. ביקורת PPI

המדיניות בקונפיגורציה, ב־manifests וב־SourceAFIS adapter נכונה:

```text
SD300B nominal PPI = 1000
SD300C nominal PPI = 2000
PNG pHYs = diagnostic only
```

SD300B: 19,435/19,435 קבצים מצהירים כ־1000 בקירוב.  
SD300C: 9,320 מצהירים כ־2000 בקירוב ו־10,115 מצהירים 5080. רשימת 10,115 זהה ב־analysis וב־curation.

ארבעת ה־base manifests מכילים `nominal_ppi` של 1000/2000, לא 5080. `SourceAfisAdapter._effective_dpi()` קורא `ppi`/`dpi` מ־image metadata ואינו קורא PNG metadata; מסלול `/extract-template` מקבל DPI מפורש. בעת REWRITE של manifest reader חובה למפות `nominal_ppi` ל־metadata key `ppi` ולא לחשב אותו מה־PNG.

## 8. מדיניות אחסון עתידית לתוצרי curation

### COPY בעתיד, לאחר אישור Stage 0

- `config\manual_review_decisions.csv`
- `outputs\selected_50_subjects.csv`
- `outputs\selected_50_subjects.txt`
- `outputs\selection_provenance.json`
- `outputs\eligible_subjects.csv`
- `outputs\duplicate_identity_review.csv`
- `outputs\duplicate_identity_summary.json`
- `outputs\subject_completeness_summary.json`
- `outputs\cross_resolution_summary.json`
- `outputs\protocol_manifest_summary.json`
- `outputs\raw_data_verification.json`
- `outputs\base_500_genuine_sd300b.csv`
- `outputs\base_500_genuine_sd300c.csv`
- `outputs\base_500_impostor_sd300b.csv`
- `outputs\base_500_impostor_sd300c.csv`

אלה 15 קבצים קטנים יחסית שמגדירים cohort, pair structure ו־provenance. אין להעתיקם בשלב הנוכחי.

### REWRITE / UNCERTAIN

- `README.md`: לכתוב תיעוד protocol מצומצם, בלי הוראות להרצת curation מתוך benchmark repo.
- `config\stage0_config.yaml`: `UNCERTAIN` עד התאמה ל־lock; לאחר מכן לשמר snapshot נעול או schema מצומצם.
- `outputs\manifest_lock.json`: `UNCERTAIN`; יש ליצור בעתיד lock אריזת־פרוטוקול שמכסה גם manual decisions ו־self manifests.
- `outputs\MANIFEST_SHA256SUMS.txt`: `UNCERTAIN`; יש ליצור listing חדש התואם לחבילת הקבצים המצומצמת.

### REFERENCE_EXTERNAL_READ_ONLY

ה־inventories, maps, content statistics, full-pool pairs, exclusions, queues, summaries המלאים, סקריפטי Stage 0, בדיקות Stage 0 וקובצי verification טבלאיים צריכים להישאר תחת dataset root. הם evidence ויכולת audit, לא runtime input של benchmark.

### EXCLUDE מ־Git

`cache\`, `logs\`, `.pytest_cache\`, כל `__pycache__`/`.pyc`, `verification\plain_roll_sheets\*.png` ו־`verification\slap_overlays\*.png` מוחרגים. ה־100 גיליונות/overlays הם visual review חיצוני, לא artifact להרצה.

החלטה פרטנית עבור כל 191 קובצי curation מופיעה ב־`migration_manifest.json`.

## 9. ארכיטקטורת SourceAFIS המותרת

המסלול המלא הקיים הוא:

```text
CLI run-sourceafis*
→ ManagedSourceAfisSidecar
→ SourceAfisSidecarClient.health + validate_health
→ SourceAfisAdapter.prepare
→ POST /extract-template
→ FingerprintImage(encoded bytes, explicit DPI)
→ FingerprintTemplate + toByteArray
→ SourceAfisAdapter.compare
→ POST /verify
→ FingerprintTemplate deserialize
→ FingerprintMatcher.match
→ raw SourceAFIS similarity score
```

`SourceAfisAdapter` הוא COPY: הוא אינו מפעיל preprocessing, threshold, normalization, cache או decision. הוא קורא encoded image bytes ומעביר DPI מפורש.

`SourceAfisSidecarClient` הוא REWRITE משום שהוא כולל גם raw/final-minutiae contracts. יש לשמר health, loopback-only transport, persistent connection, structured failures, `extract_template`, `verify` וגרסאות; ולהסיר raw pixels ו־final minutiae.

### החלטת `/extract-template-raw`

ה־endpoint אינו נקרא על ידי `SourceAfisAdapter` ואינו נדרש ל־SourceAFIS end-to-end. הקוד והתיעוד מראים שהוא נוצר כדי לבדוק parity בין OpenCV grayscale raw pixels לבין `/extract-final-minutiae` בענף detector-only. הוא גם משנה ingestion לעומת המסלול הרשמי encoded-image. לכן סיווגו **EXCLUDE** מה־benchmark החדש. אם בעתיד יידרש decoder diagnostic עצמאי, יש לקבל אישור מחקרי ולבודד אותו מחוץ למסלול benchmark; אין צורך כזה כעת.

`/extract-final-minutiae`, `SourceAfisFinalMinutiaeDetector`, native CBOR parsing וכל העברת minutiae ל־RootSIFT מסווגים **EXCLUDE** ללא הסתייגות.

## 10. Dependency graph מילולי

תלות ההרצה המותרת:

```text
CLI [REWRITE]
→ runner [REWRITE: manifest/result schema]
→ contract/hash/io/bundle/provenance [COPY/REWRITE מצומצם]
→ SourceAfisAdapter [COPY]
→ SourceAfisSidecarClient [REWRITE]
→ ManagedSourceAfisSidecar [COPY]
→ shaded Java JAR [REGENERATE, לא Git]
→ SourceAfisSidecarService [REWRITE]
→ SourceAfisV2Engine [REWRITE]
→ com.machinezoo.sourceafis:sourceafis:3.18.1 [PIN]
→ FingerprintMatcher.match [raw score]
```

תלויות Python במסלול זה הן ספריית התקן בלבד. `numpy` ו־`opencv-python` נדרשים רק לאלגוריתמים המוחרגים ויש להסירם. `pytest` הוא development dependency.

תלויות Java שיש לשמר: Java release 11, SourceAFIS 3.18.1, Jackson databind 2.17.2, JUnit 5.10.3 וגרסאות Maven plugins הרשומות ב־pom. `jackson-dataformat-cbor` דרוש רק ל־final-minutiae parsing ויש להסירו ב־REWRITE.

תלויות provenance: manifest SHA-256, config hash, implementation source hashes, JAR SHA-256, Maven coordinates, Java runtime, SourceAFIS version, sidecar contract/version ו־Git commit/dirty state.

## 11. סיווג קבצי ריפו המקור

סיכום 161 פריטי repository שנבדקו (159 tracked ושני JARs קיימים):

| סיווג | כמות |
|---|---:|
| COPY | 16 |
| REWRITE | 28 |
| EXCLUDE | 117 |

קבצי מפתח:

| קובץ | סיווג | מה נשמר | מה מוסר/משתנה |
|---|---|---|---|
| `src\fingerprint_benchmark\sourceafis_adapter.py` | COPY | prepare/compare, DPI policy, raw score | ללא שינוי התנהגות |
| `src\fingerprint_benchmark\sourceafis_client.py` | REWRITE | health, extract_template, verify, loopback, errors | raw-template/final-minutiae symbols ו־health fields |
| `src\fingerprint_benchmark\sourceafis_sidecar.py` | COPY | JVM lifecycle, JAR hash, safe output | ללא algorithm branch |
| `src\fingerprint_benchmark\cli.py` | REWRITE | sourceafis-smoke, run-sourceafis, run-sourceafis-all, summarize | כל imports/commands של SIFT, Harris ו־detector-joint500 |
| `src\fingerprint_benchmark\runner.py` | REWRITE | timing, failures, validation, atomic bundle, reproducibility | old discovery root והנחות schema |
| `src\fingerprint_benchmark\manifest.py` | REWRITE | strict schema/order/unique IDs | לתמוך בשדות Stage 0 וב־subject A/B של impostor |
| `src\fingerprint_benchmark\preflight.py` | REWRITE | hash/identity/path validation | registry של validators ישנים |
| `src\fingerprint_benchmark\bundle.py` | COPY | candidate publication/rollback | — |
| `src\fingerprint_benchmark\hashing.py` | COPY | canonical JSON ו־SHA-256 | — |
| `src\fingerprint_benchmark\io.py` | COPY | atomic CSV/JSON | — |
| `src\fingerprint_benchmark\provenance.py` | COPY | source/JAR/repo provenance | — |
| `src\fingerprint_benchmark\contract.py` | REWRITE | adapter contract ו־failure statuses | bump result schema אם subject A/B מתווספים |
| `pyproject.toml` | REWRITE | packaging ו־benchmark CLI | להסיר numpy/OpenCV וכל discovery commands ישנים |
| `environment.yml` | REWRITE | Python 3.11 ו־pytest | להסיר numpy/OpenCV |
| `apps\sourceafis-sidecar\target\*.jar` | EXCLUDE | JAR SHA רק ב־provenance | regenerate; לא להכניס ל־Git |

כל תיקיות `sift\`, `gftt_harris_full\`, `local_features\`, `detectors\`, הקובץ `detector_only_joint500.py`, protocol `detector_only_joint_500_v1`, research preflights ו־run logs הם EXCLUDE. גם ה־protocols הישנים תחת `protocols\sd300b` ו־`protocols\sd300c` הם EXCLUDE ואסורים כמקור אמת ל־50 הנבדקים.

## 12. חיפוש coupling אסור

| קבוצה | סוג coupling | משפיע על SourceAFIS full? | החלטה |
|---|---|---:|---|
| `cli.py` | imports ו־runtime branches לכל SIFT/Harris/joint500 | כן, מונע import צר | REWRITE |
| `sourceafis_client.py` | final-minutiae/raw classes, methods ו־health contract | כן, health מחייב endpoints אסורים | REWRITE |
| Java engine/service/pom/test | raw endpoint, final-minutiae CBOR, extra Maven dependency | כן, sidecar רחב | REWRITE |
| `detectors\sourceafis_final_minutiae.py` | SourceAFIS minutiae → project RootSIFT | לא למסלול full, אך משתמש באותו client/JAR | EXCLUDE |
| `detector_only_joint500.py` | protocol, preflight, detector orchestration/reporting | לא | EXCLUDE |
| `sift\*` | detector, RootSIFT, matching, RANSAC, score | לא | EXCLUDE |
| `gftt_harris_full\*` | Harris/GFTT, RootSIFT, RANSAC, score | לא | EXCLUDE |
| `local_features\*` | orientation, descriptors, matching, geometry, score | לא | EXCLUDE |
| `research\deepprint_style_preflight_v1\*` | preliminary experiment | לא | EXCLUDE |
| `research\fingercode_preflight_v1\*` | preliminary experiment | לא | EXCLUDE |
| `research\poc_preflight_v1\*` וה־pycache של phase-only | preliminary experiment/cache | לא | EXCLUDE |
| README ו־method docs | documentation only | לא runtime | REWRITE או EXCLUDE לפי הקובץ |

רשימת file-level מלאה, לרבות כל הופעות הקוד הרלוונטיות, נמצאת ב־`migration_manifest.json` באמצעות `allowed_symbols`, `excluded_symbols`, `imports_or_dependencies` ו־`reason`.

## 13. Java sidecar

### Endpoints נדרשים

- `GET /health`
- `POST /extract-template`
- `POST /verify`

### Endpoints detector-only

- `POST /extract-template-raw`
- `POST /extract-final-minutiae`

### Classes/methods לשימור

- `SourceAfisSidecarService`: main, loopback validation, request limits, JSON/errors, שלושת ה־routes המותרים.
- `SourceAfisV2Engine`: `health`, `extractTemplate`, `verify`, `templateFromSerialized`, `requiredDpi`, Base64/error/timing helpers.
- `BuildInfo`, `ApiException`.
- `FingerprintImage`, `FingerprintImageOptions`, `FingerprintTemplate`, `FingerprintMatcher` imports.

### להסרה

`extractTemplateRaw`, `extractFinalMinutiae`, `parseNativeTemplate`, `finalMinutiaeResponse`, raw image structures, minutia structures, CBOR/HashSet/geometry imports, final-minutiae health capabilities ושני ה־routes.

ניתן ליצור sidecar צר יותר בלי לשנות את התנהגות SourceAFIS full, משום שהמסלול המלא אינו קורא ל־branches אלה. עם זאת, הסרת fields מה־health היא שינוי contract ולכן יש לעדכן contract/implementation version ולבדוק את Python client וה־adapter יחד. SourceAFIS נשאר 3.18.1.

בדיקות קבלה ל־sidecar הצר:

- health schema/version/loopback;
- encoded-image extraction ב־1000 וב־2000 PPI;
- missing/invalid DPI;
- invalid image/base64/template;
- deterministic template bytes לאותו input/runtime;
- verify מחזיר finite raw score בלבד;
- אין normalized score, threshold או decision;
- אין routes raw/final;
- JAR SHA ו־Maven coordinates נשמרים ב־provenance;
- parity של `/extract-template` ו־`/verify` מול sidecar הישן על fixtures סינתטיים, ללא benchmark dataset.

## 14. תשתית benchmark

הרכיבים הכלליים הבאים ראויים לשימור: `prepare`, `compare`, opaque representation, raw score, wall/internal timing, failure statuses, ordered manifest validation, config/implementation/manifest hashes, candidate-directory publication, full bundle validation, metadata ו־`score_payload_sha256` שאינו כולל timings.

נדרשים REWRITE ממוקדים:

1. `runner.py` ו־`preflight.py` מייבאים `fingerprint_data_discovery.nist_sd300.DEFAULT_DATA_ROOT` ו־validators של protocols ישנים.
2. `manifest.py` מצפה schema של 10 עמודות, בעוד Stage 0 base manifests מכילים paths/hashes/statuses ומבנה שונה.
3. `PairRecord` ו־result rows מכילים `subject_id` יחיד. impostor דורש `subject_id_a` ו־`subject_id_b`; אסור לאבד זהות של צד B.
4. CLI מניח `plain_self`, `roll_self`, `plain_roll` ואינו מבחין בין genuine/impostor לפי ה־base manifests החדשים.

לכן יש לשמר את semantics של timing/failures/publication, אך להגדיר schema ו־result schema חדשים לפני מימוש. אין להמיר בשקט את ה־base manifests לפורמט הישן.

## 15. בדיקות

### COPY

- `tests\test_canonical_fingers.py`
- `tests\test_sourceafis_sidecar_lifecycle.py`
- `tests\conftest.py`
- בדיקות Java/Python נקיות יישמרו רעיונית, אך קבצים מעורבים מסווגים REWRITE.

### REWRITE

- `test_benchmark_runner.py`: לשמר contract, hashes, failure semantics, rollback, reproducibility; להתאים schema.
- `test_sourceafis_adapter.py`: לשמר PPI, raw score, failures/no threshold; להסיר health fields של raw/final.
- `test_sourceafis_client_contract_v2.py`: לשמר loopback, connection reuse, structured errors, extract/verify; להסיר raw tests.
- `test_sourceafis_sidecar_integration_optional.py`: להשאיר health/extract/verify בלבד.
- Java `SourceAfisV2EngineTest.java`: להשאיר full-path/DPI/error/binding tests; להסיר minutiae/CBOR/transparency/raw tests.
- `test_nist_sd300.py`, `test_protocol_dataset.py`, `test_protocol_hardening.py`, `test_self_manifest_common.py`: לשכתב מול Stage 0 הקפוא, בלי scan מחדש.

### EXCLUDE

כל בדיקות SIFT, GFTT/Harris, detector-only, final-minutiae, local features, Joint-500 וה־protocol generators הישנים.

## 16. תכנון PLAIN-self ו־ROLL-self

ניתן להפיק בעתיד את שני הסוגים באופן דטרמיניסטי **רק** מארבעת `base_500_genuine_*` הקפואים. לכל שורת genuine קיימת בדיוק תמונת PLAIN אחת ותמונת ROLL אחת לזהות `subject_id + canonical_finger`.

### schema מומלץ

```text
pair_id
comparison_kind              # plain_self | roll_self
subject_index
subject_id
canonical_finger
hand
finger_name
dataset_release
nominal_ppi
path_a
path_b
sha256_a
sha256_b
source_frgp_a
source_frgp_b
image_status_a
image_status_b
pair_status
source_genuine_pair_id
```

מקור השדות הוא שורת genuine קיימת. עבור PLAIN-self שני הצדדים מקבלים את שדות `plain_*`; עבור ROLL-self שני הצדדים מקבלים את `roll_*`. `path_a == path_b`, `sha256_a == sha256_b`, ו־FRGP/status זהים. אין לפתוח או לשנות תמונה.

pair ID מומלץ, זהה לוגית בין B ו־C:

```text
PSELF_<subject_id>_F<canonical_finger:02d>
RSELF_<subject_id>_F<canonical_finger:02d>
```

סדר השורות חייב להיות סדר שורות ה־genuine base manifest: `subject_index` עולה ואז canonical finger 1–10. צפויות 500 שורות לכל self manifest ולכל release.

ה־generator העתידי צריך לקלוט גם SHA-256 צפוי של ה־genuine source manifest, לכתוב candidate אטומי, לאמת schema/order/paths/hashes, ואז להוסיף את ארבעת ה־self manifests ואת קובץ ההכרעות הידניות ל־lock חדש. יצירתם משנה את חבילת הפרוטוקול ולכן מחייבת גרסה חדשה (למשל `protocol_v2` או `stage0_v1.1`), אך אינה משנה את Stage 0 selection או את 50 הנבדקים.

## 17. סיכונים ושאלות להחלטה

1. האם המנחה מאשר חסימת `00001585`/`00001586` על בסיס `prior_report` לא מאומת?
2. האם המנחה מאשר ש־manual review שמשמר challenge records הוא חלק ממדיניות Stage 0, למרות השפעתו העקיפה על 45/50 מהמדגם?
3. איזו גרסת protocol תוקצה להוספת self manifests ול־lock החדש?
4. האם יש לשחזר byte-for-byte את הקונפיגורציה שננעלה, או להקפיא את הקונפיגורציה הנוכחית בגרסה חדשה?
5. האם לשמר את דוחות finger-correspondence מחוץ ל־Git בלבד או לכלול summary נעול בחבילת provenance?
6. האם לבצע בעתיד adjudication תיעודי נפרד של סתירת AMP ב־analysis? אין לכך השפעה על ה־50 הקפואים.
7. האם result schema חדש יכיל `subject_id_a/subject_id_b` ו־`comparison_kind` במפורש? ההמלצה היא כן.

## 18. סדר הגירה מומלץ

1. לקבל הכרעות מחקריות על duplicate blocking, manual review וגרסת protocol.
2. לתקן את שרשרת ה־freeze בלי לשנות cohort: config snapshot, manual-decision hash ו־minimal protocol lock.
3. להגדיר schemas ל־genuine, impostor, PLAIN-self, ROLL-self ול־result rows.
4. להעתיק רק את 15 תוצרי curation המאושרים ולייצר lock חדש מתוך הקלט הקפוא.
5. להעביר contract/hash/io/bundle/provenance/process lifecycle.
6. לשכתב manifest/preflight/runner ל־Stage 0 schemas ולשתי זהויות impostor.
7. להעביר `SourceAfisAdapter` ולשכתב client/sidecar למסלול health/extract/verify בלבד.
8. לשכתב CLI, packaging, docs והבדיקות; להסיר OpenCV/numpy/algorithm branches.
9. לבנות JAR חדש מה־pom הנעול, להריץ unit/contract tests, ורק לאחר קבלה להריץ smoke/benchmark מאושר.

## 19. בדיקות קבלה לשלב המימוש

- בדיוק ארבעת סוגי comparison, אותו cohort ואותו סדר לוגי בשני releases;
- hashes של ארבעת base manifests תואמים ל־Stage 0 הנוכחי;
- self manifests נגזרים דטרמיניסטית ומכילים 500 שורות כל אחד;
- no rescan/no reselection/no matcher-based curation;
- PPI עובר 1000/2000 בלבד ולא נקרא מ־PNG;
- manifest/result schemas משמרים subject A ו־subject B;
- SourceAFIS prepare משתמש encoded image bytes וה־verify מחזיר raw `FingerprintMatcher.match` score;
- אין import או runtime dependency של SIFT/Harris/local_features/detector-only;
- אין `/extract-template-raw` או `/extract-final-minutiae` ב־health/routes/client;
- config, implementation, JAR, manifest ו־score payload hashes נבדקים;
- failure rows, atomic publication, skip-existing validation ו־process cleanup נשמרים;
- Maven/SourceAFIS versions נעולים ומדווחים;
- Git אינו מכיל JAR, raw data, caches, logs או visual sheets.

## 20. מסקנה

Stage 0 ראוי לשמש בסיס קפוא **לאחר** סגירת שאלות ה־duplicate/manual-review והשלמת lock עקבי. ארבעת ה־base manifests עצמם עברו את כל הבדיקות המבניות והקריפטוגרפיות שבוצעו ב־audit. `_analysis` הוא corroborating evidence בלבד ואינו מקור פרוטוקול. תשתית benchmark כללית ו־SourceAFIS end-to-end ניתנות להעברה; כל אלגוריתם פרויקטלי מוחרג.

**ההגירה לא התחילה. לא הועתק קוד או manifest, לא נוצר protocol חדש, ולא הופעל matcher. נעצרנו לפני שלב המימוש כנדרש.**
