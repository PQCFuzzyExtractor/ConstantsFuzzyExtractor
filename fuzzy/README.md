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

## Building (Windows / MinGW)

Example (assumes `liboqs` built under `liboqs/build` and `liboqs/build/bin` is on PATH at runtime):

```bat
cd fuzzy\tests
gcc -O2 -I.. -I..\.. -I..\..\liboqs\include -I..\..\liboqs\build\include -L..\..\liboqs\build\lib \
	..\fuzzy_extractor.c test_fuzzy.c -loqs -o test_fuzzy.exe
test_fuzzy.exe
```
