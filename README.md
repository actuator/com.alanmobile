# com.alanmobile — Dirty Stream (path traversal via shared content URI)

Zero-click arbitrary file write into `com.alanmobile`'s private internal storage, reachable by any installed app through the exported share activity. No permission required. This repo is the attacker app that demonstrates it.

## 1. Vulnerability (confirmed from bytecode)

Exported entry point, fired by any app:

```xml
<activity android:name="com.alaneu.reactnativeshareextension.share.ShareReceiverActivity"
          android:exported="true" android:launchMode="2">
    <intent-filter>
        <action android:name="android.intent.action.SEND"/>
        ...
```

The destination filename is taken from the incoming content URI's `_display_name` with no sanitization:

```
# ShareReceiverActivity.b(Landroid/net/Uri;)Ljava/lang/String;
query(uri, ...) -> Cursor
idx  = cursor.getColumnIndex("_display_name")
name = cursor.getString(idx)        // raw: no basename, no ".." check
return name
```

and written straight to a path built from it:

```
# ShareReceiverActivity.f(Landroid/net/Uri;)Lorg/json/JSONObject;
name = b(uri)                              // attacker-controlled, else "shared-<UUID>"
dir  = new File(getCacheDir(), "shared")   // /data/data/com.alanmobile/cache/shared
dst  = new File(dir, name)                 // traversal here
in   = getContentResolver().openInputStream(uri)
out  = new FileOutputStream(dst)
kotlin.io.copyTo(in, out)                  // attacker bytes -> dst
```

No canonicalization or `startsWith` containment check exists between the `_display_name` read and the `FileOutputStream`. The JSON returned to React Native reports `dst.getName()` (a cosmetic basename), but the write to the traversed path has already happened.

### Traversal

`getCacheDir()` is `/data/data/com.alanmobile/cache`, so `cache/shared/` sits two levels under the data root:

```
_display_name = "../../PWNED_by_actuator.txt"
literal path  = /data/data/com.alanmobile/cache/shared/../../PWNED_by_actuator.txt
resolves to   = /data/data/com.alanmobile/PWNED_by_actuator.txt
```

A file owned by the victim's UID, inside its private data dir, written from attacker bytes — which the attacker app cannot otherwise create.

## 2. PoC components

- `EvilProvider` — content provider whose `query()` returns `_display_name = "../../PWNED_by_actuator.txt"` and whose `openFile()` returns the payload bytes.
- `MainActivity` — fires an explicit `Intent(ACTION_SEND)` at `com.alanmobile/...ShareReceiverActivity` with `EXTRA_STREAM` set to the content URI and `FLAG_GRANT_READ_URI_PERMISSION`. Explicit targeting bypasses the victim's mime filters; the grant plus `ClipData` ensures the victim can read the URI whether it uses `EXTRA_STREAM` or `getData()`.

Demo video: https://github.com/actuator/com.alanmobile/blob/main/ALAN.mp4


## 3. Remediation

Reduce the incoming name to its last path segment before use — `new File(dir, new File(displayName).getName())` — and reject the result if it still contains a separator. Better: write under a generated name (the existing `shared-<UUID>` fallback) and never trust `_display_name` for the on-disk path.
