# Dependency requirements and tested configuration

The basic build/run checks used Ubuntu 22.04, GCC 11.4, CMake, OpenSSL 3.0.2, SEAL 4.1, Kuku 2.1, Cargo 1.92 and JDK 17. Existing external dependencies were reused; this is not a clean-machine dependency installation test.

## Metered-LPSI

The tested libOTe source declares `project(libOTe VERSION 2.2.0)`. Required enabled features include KOS, actual base OT, SimplestOT, KyberOT and sodium. The tested cache has `ENABLE_KOS=ON`, `ENABLE_SIMPLESTOT=ON`, `ENABLE_SIMPLESTOT_ASM=ON`, `ENABLE_MR_KYBER=ON`, `ENABLE_SODIUM=ON`, `SODIUM_MONTGOMERY=ON`, `ENABLE_BOOST=ON`, and `ENABLE_MOCK_OT=OFF`.

The current build expects these paths relative to `LIBOTE_ROOT`:

```
out/build/linux/libOTe/liblibOTe.a
out/build/linux/cryptoTools/cryptoTools/libcryptoTools.a
out/build/linux/coproto/coproto/libcoproto.a
out/build/linux/macoro/macoro/libmacoro.a
out/build/linux/thirdparty/KyberOT/libKyberOT.a
out/build/linux/thirdparty/SimplestOT/libSimplestOT.a
out/install/linux/lib/libsodium.a
```

Headers from the source/build/install directories are also required, as listed in CMakeLists.txt. A generic system libOTe package is not sufficient for this layout. Rust dependencies are pinned by `code/metered-lpsi/vendor/rust_h2g/Cargo.lock`; build with `cargo build --release --locked` (also invoked by CMake).

The tested libOTe directory has no independent Git metadata. Running `git rev-parse HEAD` there resolves its enclosing project and **does not identify the upstream libOTe revision**.

## APSI

Use SEAL 4.1 built with `SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF`. With vcpkg, request `seal[no-throw-tran]`. For manual installation, pass that option when building SEAL itself, not APSI. When multiple SEAL installations exist, explicitly select the compatible installation via `SEAL_DIR`. Include the installation prefix for FlatBuffers/flatc, jsoncpp, log4cplus, ZeroMQ/cppzmq, TCLAP and Kuku.

## PPSI

Use JDK 17 for both `java` and Maven. A default JDK 21 fails with the inherited preview/source-17 compiler settings. Follow README to install the MPC4J `v1.1.4-beta` modules. The successful smoke check reused locally installed 1.1.4-beta Maven artifacts; these were not rebuilt from a clean tag during this check. Payable PSI needs native-tool; Payable PIR additionally needs native-fhe. Only Payable PSI ZLP24/BASELINE were run in the basic check.
