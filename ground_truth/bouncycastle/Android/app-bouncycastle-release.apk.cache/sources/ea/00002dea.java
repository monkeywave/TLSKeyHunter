package org.bouncycastle.tls.crypto;

import java.math.BigInteger;

/* loaded from: classes2.dex */
public interface TlsSRP6VerifierGenerator {
    BigInteger generateVerifier(byte[] bArr, byte[] bArr2, byte[] bArr3);
}