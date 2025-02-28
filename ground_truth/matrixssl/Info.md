# Extracting the Client_Random
The `ssl` structure is composed of two main substructures: `sslRec` and `sslSec`.
The `sslSec`structure contains the Client_Random.

## Overview
- `ssl` [(complete definition)](https://github.com/BlobbyBob/matrixssl/blob/effeb14219ab9b9560ddf0ea56f939a1aa8f1d71/matrixssl/matrixssllib.h#L1132)
    - `sslRec` [(complete definition)](https://github.com/BlobbyBob/matrixssl/blob/effeb14219ab9b9560ddf0ea56f939a1aa8f1d71/matrixssl/matrixssllib.h#L805)
    - `sslSec` [(complete definition)](https://github.com/BlobbyBob/matrixssl/blob/effeb14219ab9b9560ddf0ea56f939a1aa8f1d71/matrixssl/matrixssllib.h#L825)
        - `unsigned char clientRandom[SSL_HS_RANDOM_SIZE]`
