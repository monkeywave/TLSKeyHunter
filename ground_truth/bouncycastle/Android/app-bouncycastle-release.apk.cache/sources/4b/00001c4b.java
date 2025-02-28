package org.bouncycastle.crypto;

/* loaded from: classes.dex */
public interface EncapsulatedSecretExtractor {
    byte[] extractSecret(byte[] bArr);

    int getEncapsulationLength();
}