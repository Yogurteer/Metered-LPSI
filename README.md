# Payable / Metered Labeled PSI — Artifact Release

This repository contains the source code and build/run instructions for **Metered-LPSI** and the two baseline implementations evaluated in our experiments: **APSI** and **PPSI (MPC4J Payable PSI / PIR)**.

## Repository Structure

| Directory | Project | Description |
| :--- | :--- | :--- |
| `code/metered-lpsi` | **Metered-LPSI** | C++/Rust implementation of our Metered Labeled Private Set Intersection protocol. |
| `code/apsi` | **APSI** | Microsoft APSI (Asymmetric Private Set Intersection) C++ baseline with labeled mode support. |
| `code/ppsi` | **PPSI** | Java/Native implementation of Payable PSI and Payable PIR (`ZLP24` and `BASELINE`) built on `mpc4j`. |

## Environment Setup

Run all commands below in a Linux environment (including WSL2 on Windows). First, enter the root of this release directory and save its path:

```bash
export RELEASE_ROOT="$PWD"
```

> **Note:** When running two-party protocols across two terminals (Sections 2 and 3), make sure `RELEASE_ROOT` (and any language/library environment variables) are exported in **both** terminals.

---

## 1. Metered-LPSI

### 1.1 Prerequisites

- **Compiler & Build Tools:** GCC with C++20 support (GCC 11+ recommended), CMake >= 3.18, Rust & Cargo
- **System & Crypto Libraries:** OpenSSL 3, OpenMP, Boost (`system`, `thread`)
- **FHE & Hashing Libraries:** Microsoft SEAL 4.1, Kuku 2.1
- **OT Library (`libOTe`):** A prebuilt `libOTe` 2.2-series source tree with KOS and actual base OT enabled, including linked `KyberOT`, `SimplestOT`, `cryptoTools`, `coproto`, `macoro`, and `libsodium`.
  - The `libOTe` root directory must contain `out/build/linux` and `out/install/linux`.
  - Install these external dependencies separately; they are not bundled with this release.
  - The tested tree declares version **2.2.0**. See [DEPENDENCIES.md](DEPENDENCIES.md) for the required build options, directory layout, and dependency provenance limits.

### 1.2 Build

Replace `/absolute/path/to/built/libOTe` with your local `libOTe` path:

```bash
cd "$RELEASE_ROOT/code/metered-lpsi"
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DLIBOTE_ROOT=/absolute/path/to/built/libOTe
cmake --build build -j2
```

- If SEAL or Kuku is installed in a non-standard location, append `-DCMAKE_PREFIX_PATH="/path/to/seal/install;/path/to/kuku/install"` to the first `cmake` command.
- The first build automatically fetches and compiles the Rust dependencies pinned in `Cargo.lock`.

### 1.3 Prepare Input and Run

#### Input Format

The input file is UTF-8 text structured in two consecutive sections:
1. **Sender section:** A header line (`db size <x> label bytes <p> item bytes <q>`), followed by `-x` rows of `item,label`.
2. **Receiver section:** A header line (`query size <y> intersection size <i> item bytes <q>`), followed by `-y` query items (one per line).

Items and labels must not contain commas or newlines, and their byte lengths must match `-q` and `-p`, respectively.

#### Generate Sample Input & Execute

Use Python 3 to generate a test dataset and run `lpsi` (both sender and receiver execute within the same process):

```bash
cd "$RELEASE_ROOT/code/metered-lpsi"
mkdir -p input
python3 - <<'PY'
from pathlib import Path
n, m, overlap = 8192, 512, 256
rows = [f"db size {n} label bytes 16 item bytes 16"]
rows += [f"{i:016x},{i + 1:016x}" for i in range(n)]
rows += [f"query size {m} intersection size {overlap} item bytes 16"]
queries = list(range(overlap)) + list(range(n, n + m - overlap))
rows += [f"{i:016x}" for i in queries]
Path("input/dataset.csv").write_text("\n".join(rows) + "\n", encoding="utf-8")
PY

./build/bin/lpsi \
  -x 8192 -y 512 -i 256 -p 16 -q 16 -t 1 -m 0 -u 8 \
  -f input/dataset.csv
```

#### Command-Line Options

| Flag | Description | Notes / Constraints |
| :--- | :--- | :--- |
| `-x` | Server (sender) database size | Must match the sender section in the input file |
| `-y` | Client (receiver) query set size | Must match the receiver section in the input file |
| `-i` | Actual intersection size | Ground-truth overlap count in the dataset |
| `-p` | Label length in bytes | E.g., `16` |
| `-q` | Item length in bytes | E.g., `16` |
| `-t` | Worker thread count | `1`–`64` |
| `-m` | PIR mode | `0` = Direct PIR, `1` = Batch PIR |
| `-u` | Purchase count | Must not exceed `-i`; omit `-u` to purchase the entire intersection |
| `-f` | Input dataset path | Path to the generated CSV file |

#### Expected Output

A successful run exits with code `0` and prints:
- `CX_STRICT_CORRECTNESS PASS`
- `CX_RUN_JSON` containing `"correct":true`

---

## 2. APSI

### 2.1 Prerequisites

- **Compiler & Build Tools:** C++17 compiler, CMake >= 3.16
- **Libraries:** Microsoft SEAL 4.1, Kuku 2.1, FlatBuffers (including `flatc`), `jsoncpp`, `log4cplus`, ZeroMQ / `cppzmq`, and `TCLAP`

### 2.2 Build

If you manage dependencies via `vcpkg` (using package versions that provide SEAL 4.1 and Kuku 2.1):

```bash
export VCPKG_ROOT=/absolute/path/to/vcpkg
"$VCPKG_ROOT/vcpkg" install 'seal[no-throw-tran]' kuku \
  flatbuffers jsoncpp log4cplus cppzmq tclap

cd "$RELEASE_ROOT/code/apsi"
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DAPSI_BUILD_CLI=ON \
  -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
cmake --build build -j2 --target sender_cli receiver_cli
```

> If dependencies are installed via another method, omit `-DCMAKE_TOOLCHAIN_FILE` and pass `-DCMAKE_PREFIX_PATH` pointing to their installation directories.

**SEAL requirement for all installation methods:** build SEAL with `-DSEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF`. The vcpkg feature `seal[no-throw-tran]` above supplies this setting. If multiple installations exist, also pass `-DSEAL_DIR=/absolute/path/to/the/compatible/SEALConfig-directory`. A cached `SEAL_DIR` can override the prefix. Use a fresh build directory when switching installations.

### 2.3 Prepare Input and Run

#### Generate Sample Input

Neither the server CSV (`item,label` per line) nor the query file (one `item` per line) uses a header row:

```bash
cd "$RELEASE_ROOT/code/apsi"
mkdir -p input
printf 'alice,label_alice\nbob,label_bob\ncarol,label_carol\n' > input/sender.csv
printf 'alice\ncarol\ndave\n' > input/query.txt
```

#### Run Server and Client

1. **Terminal 1 (Server):** Start the sender and wait until it finishes preparing the database and begins listening for requests:

   ```bash
   cd "$RELEASE_ROOT/code/apsi"
   ./build/bin/sender_cli \
     -d input/sender.csv -p parameters/1M-256.json \
     --port 1212 -t 1
   ```

2. **Terminal 2 (Client):** Ensure `RELEASE_ROOT` is set, then run the receiver:

   ```bash
   cd "$RELEASE_ROOT/code/apsi"
   ./build/bin/receiver_cli \
     -q input/query.txt -a 127.0.0.1 --port 1212 \
     -o input/intersection.csv -t 1
   ```

#### Expected Output & Notes

- Intersection results are written to `input/intersection.csv` (for the example above, `alice` and `carol` along with their labels).
- For other dataset sizes, choose a matching parameter file from `parameters/`.
- To run across separate machines, change `-a 127.0.0.1` on the client to the server's IP address.
- Stop the server with `Ctrl+C` when finished.

---

## 3. PPSI (MPC4J Payable PSI & PIR)

### 3.1 Prerequisites & Build

- **Java & Build Tools:** JDK 17, Maven
- **MPC4J Framework:** Depends on [MPC4J v1.1.4-beta](https://github.com/alibaba-edu/mpc4j/tree/v1.1.4-beta) (`mpc4j-common-rpc`, `mpc4j-s2pc-opf`, `mpc4j-s2pc-pso`, `mpc4j-s2pc-pir`).
- **MPC4J Native Libraries:** Follow the [MPC4J v1.1.4-beta README](https://github.com/alibaba-edu/mpc4j/blob/v1.1.4-beta/README.md) to install FourQ and compile `mpc4j-native-tool` (and `mpc4j-native-fhe` for Payable PIR).

#### Step 1: Install MPC4J Dependencies and Build `ppsi`

Skip `git clone` if you already have the `v1.1.4-beta` source tree, and skip `mvn ... install` if the MPC4J modules are already installed in your local Maven repository:

```bash
export JAVA_HOME=/absolute/path/to/jdk-17
export PATH="$JAVA_HOME/bin:$PATH"
export MPC4J_ROOT=/absolute/path/to/mpc4j-v1.1.4-beta

# Both commands must report Java 17; Maven must use the same JAVA_HOME.
java -version
mvn -version

git clone --branch v1.1.4-beta --depth 1 \
  https://github.com/alibaba-edu/mpc4j.git "$MPC4J_ROOT"
mvn -f "$MPC4J_ROOT/pom.xml" \
  -pl mpc4j-common-rpc,mpc4j-s2pc-opf,mpc4j-s2pc-pso,mpc4j-s2pc-pir \
  -am install -Dmaven.test.skip=true

cd "$RELEASE_ROOT/code/ppsi"
mvn package -Dmaven.test.skip=true
```

#### Step 2: Export Native Library Paths

Run the following in **both** server and client terminals before executing the JAR:

```bash
export JAVA_HOME=/absolute/path/to/jdk-17
export PATH="$JAVA_HOME/bin:$PATH"
export MPC4J_ROOT=/absolute/path/to/mpc4j-v1.1.4-beta
export MPC4J_NATIVE_LIBS="$MPC4J_ROOT/mpc4j-native-tool/cmake-build-release:$MPC4J_ROOT/mpc4j-native-fhe/cmake-build-release"
export LD_LIBRARY_PATH="$MPC4J_NATIVE_LIBS:$LD_LIBRARY_PATH"
```

### 3.2 Configure and Run Payable PSI

Create the runtime working directory and `payable-psi.properties` in `code/ppsi`:

```bash
cd "$RELEASE_ROOT/code/ppsi"
mkdir -p temp
cp src/main/resources/log4j.properties ./log4j.properties
cat > payable-psi.properties <<'EOF'
pto_type = PAYABLE_PSI_TASK
payable_psi_pto_name = ZLP24
server_name = server
server_ip = 127.0.0.1
server_port = 9000
client_name = client
client_ip = 127.0.0.1
client_port = 9001
element_byte_length = 16
server_log_set_size = 12
client_log_set_size = 8
parallel = false
save_path = temp
append_string = run
EOF
```

- Set sizes are powers of two (`2^12 = 4096` server items and `2^8 = 256` client items in this example).
- Synthetic inputs and execution logs/results are automatically generated in `temp/` (no external dataset download is needed; note that this entry point does not expose a custom intersection-size parameter).
- To evaluate the baseline protocol instead, change `payable_psi_pto_name` to `BASELINE`.
- To enable multi-threading, set `parallel = true` for both parties and increase `-Djava.util.concurrent.ForkJoinPool.common.parallelism`.

Start the server in **Terminal 1**, wait until it finishes generating input files and listens for connections, and then start the client in **Terminal 2**:

```bash
# Terminal 1 (Server)
cd "$RELEASE_ROOT/code/ppsi"
java --add-modules jdk.incubator.vector \
  -Djava.library.path="$MPC4J_NATIVE_LIBS" \
  -Djava.util.concurrent.ForkJoinPool.common.parallelism=1 \
  -jar target/mpc4j-work-payable-1.1.4-beta-jar-with-dependencies.jar \
  payable-psi.properties server
```

```bash
# Terminal 2 (Client)
cd "$RELEASE_ROOT/code/ppsi"
java --add-modules jdk.incubator.vector \
  -Djava.library.path="$MPC4J_NATIVE_LIBS" \
  -Djava.util.concurrent.ForkJoinPool.common.parallelism=1 \
  -jar target/mpc4j-work-payable-1.1.4-beta-jar-with-dependencies.jar \
  payable-psi.properties client
```

### 3.3 Configure and Run Payable PIR

Using the same build and environment variables from Section 3.1, generate `payable-pir.properties` in `code/ppsi`:

```bash
cd "$RELEASE_ROOT/code/ppsi"
mkdir -p temp
cp -f src/main/resources/log4j.properties ./log4j.properties
cat > payable-pir.properties <<'EOF'
pto_type = PAYABLE_PIR_TASK
payable_pir_pto_name = ZLP24
server_name = server
server_ip = 127.0.0.1
server_port = 9000
client_name = client
client_ip = 127.0.0.1
client_port = 9001
element_bit_length = 128
server_log_set_size = 12
query_number = 8
parallel = false
save_path = temp
append_string = run
EOF
```

Launch the server and client in two terminals using `payable-pir.properties`:

```bash
# Terminal 1 (Server)
cd "$RELEASE_ROOT/code/ppsi"
java --add-modules jdk.incubator.vector \
  -Djava.library.path="$MPC4J_NATIVE_LIBS" \
  -Djava.util.concurrent.ForkJoinPool.common.parallelism=1 \
  -jar target/mpc4j-work-payable-1.1.4-beta-jar-with-dependencies.jar \
  payable-pir.properties server
```

```bash
# Terminal 2 (Client)
cd "$RELEASE_ROOT/code/ppsi"
java --add-modules jdk.incubator.vector \
  -Djava.library.path="$MPC4J_NATIVE_LIBS" \
  -Djava.util.concurrent.ForkJoinPool.common.parallelism=1 \
  -jar target/mpc4j-work-payable-1.1.4-beta-jar-with-dependencies.jar \
  payable-pir.properties client
```

## Licensing

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for included third-party licenses and the licensing status of the original code.
