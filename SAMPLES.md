# Obtaining the samples

The write-up in `README.md` covers a specific build of "ElriaGame" whose
hashes are in `HASHES.txt`. The samples themselves are not published here.
If you are doing defensive research and need the artifacts to reproduce the
unpack, the ways to find them are:

1. Search MalwareBazaar / VirusTotal / MalShare / Any.Run by SHA-256:
   - Installer: `319acc0f884b20f8c36c03912996c98f7860abf99d39e7492775c0320ae9e00d`
   - JAR:       `33f0ac160b6807c7e70015a148ac4ddfe89341c7a8b8454234afc3c3b2060712`
2. If you already have a candidate installer, verify by hashing it before
   running `scripts/unpack_installer.sh`.
3. If neither works, open an issue describing your use case; sample sharing
   between defenders will happen out of band, not through this repo.

If you obtain a related but non-identical build (a different Azure IP, a
different `APP_NAME`, a different install directory), that's expected —
the operator rotates strings between builds. The dropper *shape* and the
JAR *identity* (`Implementation-Title: Exastealer`) are the stable pieces.
