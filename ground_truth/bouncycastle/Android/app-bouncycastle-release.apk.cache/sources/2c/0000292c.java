package org.bouncycastle.pqc.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class FalconPrivateKey extends ASN1Object {

    /* renamed from: F */
    private byte[] f1178F;

    /* renamed from: f */
    private byte[] f1179f;

    /* renamed from: g */
    private byte[] f1180g;
    private FalconPublicKey publicKey;
    private int version;

    public FalconPrivateKey(int i, byte[] bArr, byte[] bArr2, byte[] bArr3) {
        this(i, bArr, bArr2, bArr3, null);
    }

    public FalconPrivateKey(int i, byte[] bArr, byte[] bArr2, byte[] bArr3, FalconPublicKey falconPublicKey) {
        this.version = i;
        this.f1179f = bArr;
        this.f1180g = bArr2;
        this.f1178F = bArr3;
        this.publicKey = falconPublicKey;
    }

    private FalconPrivateKey(ASN1Sequence aSN1Sequence) {
        int intValueExact = ASN1Integer.getInstance(aSN1Sequence.getObjectAt(0)).intValueExact();
        this.version = intValueExact;
        if (intValueExact != 0) {
            throw new IllegalArgumentException("unrecognized version");
        }
        this.f1179f = Arrays.clone(ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(1)).getOctets());
        this.f1180g = Arrays.clone(ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(2)).getOctets());
        this.f1178F = Arrays.clone(ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(3)).getOctets());
        if (aSN1Sequence.size() == 5) {
            this.publicKey = FalconPublicKey.getInstance(aSN1Sequence.getObjectAt(4));
        }
    }

    public static FalconPrivateKey getInstance(Object obj) {
        if (obj instanceof FalconPrivateKey) {
            return (FalconPrivateKey) obj;
        }
        if (obj != null) {
            return new FalconPrivateKey(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public byte[] getF() {
        return Arrays.clone(this.f1178F);
    }

    public byte[] getG() {
        return Arrays.clone(this.f1180g);
    }

    public FalconPublicKey getPublicKey() {
        return this.publicKey;
    }

    public int getVersion() {
        return this.version;
    }

    public byte[] getf() {
        return Arrays.clone(this.f1179f);
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        aSN1EncodableVector.add(new ASN1Integer(this.version));
        aSN1EncodableVector.add(new DEROctetString(this.f1179f));
        aSN1EncodableVector.add(new DEROctetString(this.f1180g));
        aSN1EncodableVector.add(new DEROctetString(this.f1178F));
        if (this.publicKey != null) {
            aSN1EncodableVector.add(new FalconPublicKey(this.publicKey.getH()));
        }
        return new DERSequence(aSN1EncodableVector);
    }
}