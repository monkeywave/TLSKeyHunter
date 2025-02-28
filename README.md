# TLSKeyHunter

This repository contains the artifacts and implementation details for the research paper **"All Your TLS Keys Are Belong to Us: A Novel Approach to Live Memory Forensic Key Extraction"**. Below is an overview of the repository structure and how to utilize the provided tools.

---

## Repository Overview

### Folder Structure

- **`ground_truth`**  
  Contains the ground truth data used to validate the accuracy and reliability of our key extraction methodology. This includes pre-computed cryptographic material and expected outcomes for controlled test cases.

- **`real_world_examples`**  
  Includes binaries and applications evaluated in our research. These real-world examples demonstrate TLS key extraction across diverse environments and implementations.

- **`tlsKeyExtraction`**  
  Hooking scripts leveraging **Frida** to intercept the TLS key derivation process. These scripts dynamically trace memory operations to extract keys during runtime.

---

## Docker Deployment

We provide a Docker container for easy setup and execution of **TLSKeyHunter**. The container pre-configures the environment to generate the **Key-Derivation Fingerprint (KDF)** required for the hooking scripts.

### Quick Start
1. **Build the Docker image**:
   ```bash
   docker build -t tlskeyhunter .
   ```
2. **Run the container**:
   ```bash
   docker build -t tlskeyhunter .
   ```
3. Follow the in-container documentation to execute the tool and generate Key-Derivation Fingerprints.


## Research Paper

For full methodological details, experimental results, and analysis, refer to our paper: **"All Your TLS Keys Are Belong to Us: A Novel Approach to Live Memory Forensic Key Extraction"**.


## Note

This project is intended for academic and research purposes only. Commercial use is prohibited.

