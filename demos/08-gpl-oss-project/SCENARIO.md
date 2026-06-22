# Demo 08 — GPL open-source project: GPL is fine, AGPL still isn't

## Where this data came from

You ship a **GPL-licensed** command-line tool (think a GNU-style utility). You
are happy to depend on GPL and LGPL components — that's compatible with your own
license. This manifest is a realistic native dependency set: glibc/GnuTLS
(LGPL-2.1-or-later), GNU readline and coreutils (GPL-3.0-or-later), ncurses
(X11/MIT-style), and the MinIO object store (**AGPL-3.0-or-later**). All
licenses are the publicly documented terms for these projects.

## The subtle trap: AGPL is not "just more GPL"

Even a GPL project usually wants to avoid **AGPL**: its network clause imposes
source-disclosure obligations on anyone who runs a modified version as a network
service — an extra obligation many GPL projects deliberately don't take on. The
`gpl-project` policy encodes exactly this: GPL and LGPL pass, AGPL/SSPL fail.

## Run it

```
python -m ossaudit audit demos/08-gpl-oss-project/deps.json --policy gpl-project
```

Expected: **FAIL** (exit code 2), exactly one violation — `minio`
(AGPL-3.0-or-later). All the GPL/LGPL deps pass.

## Contrast: a proprietary project would reject far more

```
python -m ossaudit audit demos/08-gpl-oss-project/deps.json --policy proprietary
```

Now readline, coreutils, *and* minio all fail — proprietary distribution can't
take the GPL either. Same manifest, different policy, very different result.

## How to act

If you need object storage, either keep MinIO as a **separate, independently
deployed service** you don't link or redistribute, or pick a permissively
licensed alternative. Keep `gpl-project` in CI so a future AGPL dependency is
caught before release.
