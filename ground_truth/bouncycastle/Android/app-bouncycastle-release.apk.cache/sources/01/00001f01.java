package org.bouncycastle.crypto.util;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/* loaded from: classes2.dex */
public abstract class PBKDFConfig {
    private final ASN1ObjectIdentifier algorithm;

    /* JADX INFO: Access modifiers changed from: protected */
    public PBKDFConfig(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        this.algorithm = aSN1ObjectIdentifier;
    }

    public ASN1ObjectIdentifier getAlgorithm() {
        return this.algorithm;
    }
}