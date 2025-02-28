package org.bouncycastle.jcajce.spec;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class KEMKDFSpec {
    private final AlgorithmIdentifier kdfAlgorithm;
    private final String keyAlgorithmName;
    private final int keySizeInBits;
    private final byte[] otherInfo;

    /* JADX INFO: Access modifiers changed from: protected */
    public KEMKDFSpec(AlgorithmIdentifier algorithmIdentifier, byte[] bArr, String str, int i) {
        this.keyAlgorithmName = str;
        this.keySizeInBits = i;
        this.kdfAlgorithm = algorithmIdentifier;
        this.otherInfo = bArr;
    }

    public AlgorithmIdentifier getKdfAlgorithm() {
        return this.kdfAlgorithm;
    }

    public String getKeyAlgorithmName() {
        return this.keyAlgorithmName;
    }

    public int getKeySize() {
        return this.keySizeInBits;
    }

    public byte[] getOtherInfo() {
        return Arrays.clone(this.otherInfo);
    }
}