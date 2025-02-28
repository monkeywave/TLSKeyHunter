package org.bouncycastle.asn1;

/* loaded from: classes.dex */
public class DERPrintableString extends ASN1PrintableString {
    public DERPrintableString(String str) {
        this(str, false);
    }

    public DERPrintableString(String str, boolean z) {
        super(str, z);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DERPrintableString(byte[] bArr, boolean z) {
        super(bArr, z);
    }
}