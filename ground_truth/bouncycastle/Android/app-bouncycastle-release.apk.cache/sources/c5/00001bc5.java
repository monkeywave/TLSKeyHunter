package org.bouncycastle.asn1.x509;

import kotlin.UByte;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;

/* loaded from: classes.dex */
public class KeyUsage extends ASN1Object {
    public static final int cRLSign = 2;
    public static final int dataEncipherment = 16;
    public static final int decipherOnly = 32768;
    public static final int digitalSignature = 128;
    public static final int encipherOnly = 1;
    public static final int keyAgreement = 8;
    public static final int keyCertSign = 4;
    public static final int keyEncipherment = 32;
    public static final int nonRepudiation = 64;
    private ASN1BitString bitString;

    public KeyUsage(int i) {
        this.bitString = new DERBitString(i);
    }

    private KeyUsage(ASN1BitString aSN1BitString) {
        this.bitString = aSN1BitString;
    }

    public static KeyUsage fromExtensions(Extensions extensions) {
        return getInstance(Extensions.getExtensionParsedValue(extensions, Extension.keyUsage));
    }

    public static KeyUsage getInstance(Object obj) {
        if (obj instanceof KeyUsage) {
            return (KeyUsage) obj;
        }
        if (obj != null) {
            return new KeyUsage(ASN1BitString.getInstance(obj));
        }
        return null;
    }

    public byte[] getBytes() {
        return this.bitString.getBytes();
    }

    public int getPadBits() {
        return this.bitString.getPadBits();
    }

    public boolean hasUsages(int i) {
        return (this.bitString.intValue() & i) == i;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return this.bitString;
    }

    public String toString() {
        StringBuilder sb;
        int i;
        byte[] bytes = this.bitString.getBytes();
        if (bytes.length == 1) {
            sb = new StringBuilder("KeyUsage: 0x");
            i = bytes[0] & UByte.MAX_VALUE;
        } else {
            sb = new StringBuilder("KeyUsage: 0x");
            i = (bytes[0] & UByte.MAX_VALUE) | ((bytes[1] & UByte.MAX_VALUE) << 8);
        }
        return sb.append(Integer.toHexString(i)).toString();
    }
}