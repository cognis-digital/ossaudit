# Demo 05 — Mobile app shipped to the App Store / Play Store

## Where this data came from

A proprietary Android app team is preparing a store release and exported their
Gradle dependency tree. Most libraries are permissive (Apache-2.0 from
OkHttp/Coroutines/Gson/Material, BSD-3-Clause from Glide). But two media
components are **GPL**: the VLC Android SDK (GPL-2.0-or-later) and the
`ffmpeg-kit-full-gpl` build (GPL-3.0-only — the "-gpl" flavor enables
GPL-licensed codecs).

The licenses shown are the publicly documented terms for these libraries.

## Why GPL matters for a store binary

Apple App Store and Google Play distribution is **distribution of a binary**.
GPL is strong copyleft: linking it into a closed-source app and distributing
that app can obligate releasing the whole app under the GPL — which also
conflicts with the App Store's terms. This is the classic "VLC pulled from the
App Store" problem.

## Run it (distribute-binary policy)

```
python -m ossaudit audit demos/05-mobile-app-store/deps.json --policy distribute-binary
```

Expected: **FAIL** (exit code 2). `vlc-android-sdk` and `ffmpeg-kit-full-gpl`
are flagged as strong-copyleft violations; everything else passes.

## How to act

1. Swap `ffmpeg-kit-full-gpl` for the **LGPL** build (`ffmpeg-kit-full`) and
   dynamic-link it, which is permitted under `distribute-binary` (weak
   copyleft) if you preserve the ability to relink.
2. Replace the VLC SDK with a permissively licensed player (e.g. ExoPlayer /
   Media3, Apache-2.0).
3. Re-run; `RESULT: PASS`.
