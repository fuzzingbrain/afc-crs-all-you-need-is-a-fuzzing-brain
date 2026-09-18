# runtime_libs

Runtime shared libraries that some challenges' prebuilt fuzzers need but that
are missing from both the shipped binary tree and the challenge run image.

`libcap.so.2` — systemd's fuzzers link `libsystemd-shared-*.so`, which NEEDs
`libcap.so.2`. The prebuilt systemd binaries ship only the binary plus
`$ORIGIN/src/shared/libsystemd-shared-*.so`, and the `aixcc-afc/systemd:latest`
image (Ubuntu 20.04, glibc 2.31) has `libcap-ng` but not `libcap`. Without it the
binary aborts at load with rc=127 and every PoV silently reports "no crash".

This copy is extracted from `gcr.io/oss-fuzz-base/base-runner` (glibc 2.14 max
requirement, so it loads on the Focal challenge images). It is staged next to the
binary's `$ORIGIN` runpath libs and reached via LD_LIBRARY_PATH at run time.
