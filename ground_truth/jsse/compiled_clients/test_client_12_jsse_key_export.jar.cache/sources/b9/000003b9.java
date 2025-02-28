package org.bouncycastle.crypto;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/SkippingCipher.class */
public interface SkippingCipher {
    long skip(long j);

    long seekTo(long j);

    long getPosition();
}