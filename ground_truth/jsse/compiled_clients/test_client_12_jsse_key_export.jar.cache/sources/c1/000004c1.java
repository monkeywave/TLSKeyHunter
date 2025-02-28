package org.bouncycastle.crypto.generators;

import org.bouncycastle.crypto.Digest;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/generators/KDF1BytesGenerator.class */
public class KDF1BytesGenerator extends BaseKDFBytesGenerator {
    public KDF1BytesGenerator(Digest digest) {
        super(0, digest);
    }
}