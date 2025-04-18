package org.bouncycastle.jce;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.KeyUsage;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/X509KeyUsage.class */
public class X509KeyUsage extends ASN1Object {
    public static final int digitalSignature = 128;
    public static final int nonRepudiation = 64;
    public static final int keyEncipherment = 32;
    public static final int dataEncipherment = 16;
    public static final int keyAgreement = 8;
    public static final int keyCertSign = 4;
    public static final int cRLSign = 2;
    public static final int encipherOnly = 1;
    public static final int decipherOnly = 32768;
    private int usage;

    public X509KeyUsage(int i) {
        this.usage = 0;
        this.usage = i;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return new KeyUsage(this.usage).toASN1Primitive();
    }
}