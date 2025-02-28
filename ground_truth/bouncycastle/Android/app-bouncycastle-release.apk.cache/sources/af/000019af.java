package org.bouncycastle.asn1;

/* loaded from: classes.dex */
public class DERNumericString extends ASN1NumericString {
    public DERNumericString(String str) {
        this(str, false);
    }

    public DERNumericString(String str, boolean z) {
        super(str, z);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DERNumericString(byte[] bArr, boolean z) {
        super(bArr, z);
    }
}