# Fuzzy Extractor (McEliece 348864f)

This folder contains a small constant-time fuzzy extractor wrapper that uses
the McEliece `348864f` KEM internal functions via a locally built `liboqs`.

## Structure

- Public API: `fuzzy/fuzzy_extractor.h`
- Umbrella compile unit (build this one file): `fuzzy/fuzzy_extractor.c`
- Implementation modules: `fuzzy/src/*.c`

### APIs

- McEliece KEM adapter (ECC-like facade): `mceliece_kem_encode_like()` / `mceliece_kem_decode_like()`
- Code-offset fuzzy extractor: `code_offset_encode()` / `code_offset_decode()`

## Run / Build (Windows / MinGW)

### Prerequisites

- Windows
- MinGW-w64 `gcc`
- Git + **Git LFS**
- (Optional) CMake (only needed if you want to rebuild `liboqs` yourself)

### 1) Clone (Git LFS required)

This repository stores `fuzzy/liboqs.dll` using Git LFS.

```powershell
git lfs install
git clone <YOUR_REPO_URL>
cd ConstantsFuzzyExtractor
git lfs pull
```

Verify the DLL is present (should be a large file, not a tiny LFS pointer):

```powershell
Get-Item .\fuzzy\liboqs.dll | Format-List Name,Length,LastWriteTime
```

### 2) (Optional) Rebuild liboqs yourself

This repo is designed to build without a local `liboqs/` folder.
If you modify liboqs sources (e.g., `decrypt.c`) you can rebuild liboqs in a separate checkout and then copy the artifacts into this repo:

- Runtime DLL: copy to `fuzzy/liboqs.dll`
- MinGW import lib: copy to `fuzzy/third_party/liboqs/lib/liboqs.dll.a`
- Headers: copy/update under `fuzzy/third_party/liboqs/include/oqs/`

### 3) Build the tests / benchmark

All builds link against the vendored MinGW import library `fuzzy/third_party/liboqs/lib/liboqs.dll.a` via `-L ... -loqs`.

From PowerShell:

```powershell
$root = (Resolve-Path .).Path   # repo root (after `cd ConstantsFuzzyExtractor`)
Set-Location "$root\fuzzy\tests"

# Smoke test
gcc -O2 -DNDEBUG -I.. -I"$root\fuzzy\third_party\liboqs\include" -L"$root\fuzzy\third_party\liboqs\lib" test_fuzzy.c ..\fuzzy_extractor.c -loqs -o test_fuzzy.exe

# Timing harness (writes timing_results.csv)
gcc -O2 -DNDEBUG -I.. -I"$root\fuzzy\third_party\liboqs\include" -L"$root\fuzzy\third_party\liboqs\lib" timing_test.c ..\fuzzy_extractor.c -loqs -o timing_test.exe
```

### 4) Run (force loading the DLL from `fuzzy/`)

At runtime, Windows resolves `liboqs.dll` from the current process search order (working directory / PATH, etc.).
To ensure you use the DLL that is shipped under `fuzzy/`, prepend `fuzzy/` to `PATH`:

```powershell
$root = (Resolve-Path .).Path
$oldPath = $env:PATH
$env:PATH = "$root\fuzzy;" + $oldPath

& "$root\fuzzy\tests\test_fuzzy.exe"

# Example: quick timing run
& "$root\fuzzy\tests\timing_test.exe" -iterations 100 -max_errors 5 -progress

$env:PATH = $oldPath
```

If you see "DLL not found" errors, it means the loader did not find `liboqs.dll` on PATH.
If you see architecture errors, ensure your `gcc` and `liboqs.dll` are both x64.
