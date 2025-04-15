# TLSKeyHunter

This repository contains the artifacts and implementation details for the research paper **"All Your TLS Keys Are Belong to Us: A Novel Approach to Live Memory Forensic Key Extraction"**. Below is an overview of the repository structure and how to utilize the provided tools.

---

## Repository Overview

### Directory Structure

- `Dockerfile`: Dockerfile to build the TLSKeyHunter container.
- `MinimalAnalysisOption.java`: Java class for configuring minimal analysis options in Ghidra.
- `TLSKeyHunter.java`: Core Java implementation of TLSKeyHunter.
- `tlskeyhunterforjava-1.0-SNAPSHOT.jar`: TLSKeyHunter targeting Java based TLS implementations.
- `ghidra_analysis.sh`: Shell script to run Ghidra's headless analyzer directly.
- `custom_log4j.xml`: Logging configuration for detailed output during analysis.
- `README.md`: This documentation file.

### Directories

- **`ground_truth`**
  Contains the ground truth dataset (**TLS-KeyGround**) used to validate the accuracy and reliability of our key extraction methodology. This includes pre-computed cryptographic material and expected outcomes for controlled test cases.

- **`real_world_examples`**  
  Includes binaries and applications evaluated in our research. These real-world examples demonstrate TLS key extraction across diverse environments and implementations. The binaries are also available at [Zenodo](https://zenodo.org/records/15188139?preview=1&token=eyJhbGciOiJIUzUxMiJ9.eyJpZCI6IjRiM2ZmZjlmLTFkYzgtNDVmMi1iODA4LTY2MDQxODI5NjQ4MiIsImRhdGEiOnt9LCJyYW5kb20iOiJlZGVkZWI1MzVjYTk5MTgwNjU5MDk4N2U5MTc2MDM3YyJ9.CWkv3gZcoQp-sZPTN2cZ1hMT0avpQMgaF61NEwjPSohKShauGsfVfl92P79gF7uAgTX0ISXkMwUmP1qN1EsXPg).

- **`tlsKeyExtraction`**  
  Hooking scripts leveraging **Frida** to intercept TLS key derivation processes dynamically during runtime. Each script is tailored specifically to the targeted cryptographic library, as hooking key derivation functions is library-specific.

- **`tlskeyhunterforjava`**
  Contains a standalone Java tool that uses the ASM framework to analyze Java binaries and identify TLS key derivation functions. This tool is specifically designed for extracting Key-Derivation Fingerprints from Java-based TLS implementations.

- **`network_decryption`**  
  Includes the script `randomInverse.py`, which facilitates network traffic decryption using extracted TLS keys when the client_random value is unavailable. The script identifies the correct client random associated with each TLS secret and generates an SSLKEYLOG file, directly compatible with Wireshark and other network analysis tools.

---

## Running TLSKeyHunter

**TLSKeyHunter** generates Key-Derivation Fingerprints, which must be provided to our Frida scripts to identify TLS key derivation functions at runtime. You can invoke **TLSKeyHunter** using Docker or directly via Ghidra's headless analyzer script:

### Using Docker

#### Build Docker Image:

```bash
docker build -t tlskeyhunter .
```

#### Run TLSKeyHunter Analysis:

```bash
docker run --rm -v "$(pwd)/binary":/usr/local/src/binaries -v "$(pwd)/results":/host_output tlskeyhunter
```

**Example invocation:**

```
docker run --rm -v "$(pwd)/binary":/usr/local/src/binaries -v "$(pwd)/results":/host_output tlskeyhunter

                TLSKeyHunter
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠾⠛⢉⣉⣉⣉⡉⠛⠷⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠋⣠⣴⣿⣿⣿⣿⣿⡿⣿⣶⣌⠹⣷⡀⠀⠀⠀⠀⠀⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⣼⠁⣴⣿⣿⣿⣿⣿⣿⣿⣿⣆⠉⠻⣧⠘⣷⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢰⡇⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠈⠀⢹⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⢸⣿⠛⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠈⣷⠀⢿⡆⠈⠛⠻⠟⠛⠉⠀⠀⠀⠀⠀⠀⣾⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⡀⠻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⠃⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢼⠿⣦⣄⠀⠀⠀⠀⠀⠀⠀⣀⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣠⣾⣿⣦⠀⠀⠈⠉⠛⠓⠲⠶⠖⠚⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣄⠈⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

Identifying the TLS PRF and the HKDF function for extracting TLS key material using Frida.
Version: 0.9.4.0 by Anonymous

[*] Start analyzing binary libssl3.so (CPU Architecture: x86-64). This might take a while ...

[*] Start identifying the HKDF by looking for String "s hs traffic"
[*] String "s hs traffic" wasn't found in binary! Trying to reduce string ...
[*] Start identifying the HKDF by looking for String "hs traffic"
[!] Found String at ref: 0015abf8
[!] Instruction used there: LEA RCX,[0x10fa49]
[!] Found String at ref: 0015ac2b
[!] Instruction used there: LEA RCX,[0x10fa49]
[!] Analyzing instruction at reference address: LEA RCX,[0x10fa49]
[!] Reference stored in register: RCX
[!] Using infos for analysis: CALL 0x00156e90
[!] analysis (0): CALL 0x00156e90
[*] String (Register RCX) used as 3th argument in function call at address: 0x0015ac09 (invoking FUN_00156E90)
[*] HKDF function identified: FUN_00156E90
Function: FUN_00156e90


[*] HKDF-Function identified with label: FUN_00156E90 (FUN_00156e90)
[*] HKDF-Function signature: undefined FUN_00156e90(void)
[*] String (Register RCX) used as 3th argument in function call at address: 0x0015ac09 (invoking FUN_00156E90)
[*] Function offset (Ghidra): 00156E90 (0x00156E90)
[*] Function offset (IDA with base 0x0): 00056E90 (0x00056E90)
[*] Byte pattern for frida: 55 41 57 41 56 41 55 41 54 53 48 81 EC C8 00 00 00 4D 89 CE 4C 89 C3 49 89 CC 49 89 F5 49 89 FF 64 48 8B 04 25 28 00 00 00 48 89 84 24 C0 00 00 00 48 85 D2 74 67


....
```

To target Java based TLS implementations run the following command:
```bash
java -jar target/tlskeyhunterforjava-1.0-SNAPSHOT.jar <target jar file>
```

#### Debug Mode:

If issues occur, enable debug output with:

```bash
docker run --rm -v "$(pwd)/binary":/usr/local/src/binaries -v "$(pwd)/results":/host_output -e DEBUG_RUN=true tlskeyhunter
```

### Using Ghidra Headless Analyzer

Execute directly via the provided shell script:

```bash
./ghidra_analysis.sh <binary-path> <output-path>
```


## Research Paper

For full methodological details, experimental results, and analysis, refer to our paper: **"All Your TLS Keys Are Belong to Us: A Novel Approach to Live Memory Forensic Key Extraction"**.


## Note

This project is intended for academic and research purposes only. Commercial use is prohibited.

