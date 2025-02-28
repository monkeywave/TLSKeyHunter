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
public class SPHINCSPLUSPrivateKey extends ASN1Object {
    private SPHINCSPLUSPublicKey PublicKey;
    private byte[] skprf;
    private byte[] skseed;
    private int version;

    public SPHINCSPLUSPrivateKey(int i, byte[] bArr, byte[] bArr2) {
        this(i, bArr, bArr2, null);
    }

    public SPHINCSPLUSPrivateKey(int i, byte[] bArr, byte[] bArr2, SPHINCSPLUSPublicKey sPHINCSPLUSPublicKey) {
        this.version = i;
        this.skseed = bArr;
        this.skprf = bArr2;
        this.PublicKey = sPHINCSPLUSPublicKey;
    }

    public SPHINCSPLUSPrivateKey(ASN1Sequence aSN1Sequence) {
        int intValueExact = ASN1Integer.getInstance(aSN1Sequence.getObjectAt(0)).intValueExact();
        this.version = intValueExact;
        if (intValueExact != 0) {
            throw new IllegalArgumentException("unrecognized version");
        }
        this.skseed = Arrays.clone(ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(1)).getOctets());
        this.skprf = Arrays.clone(ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(2)).getOctets());
        if (aSN1Sequence.size() == 4) {
            this.PublicKey = SPHINCSPLUSPublicKey.getInstance(aSN1Sequence.getObjectAt(3));
        }
    }

    public static SPHINCSPLUSPrivateKey getInstance(Object obj) {
        if (obj instanceof SPHINCSPLUSPrivateKey) {
            return (SPHINCSPLUSPrivateKey) obj;
        }
        if (obj != null) {
            return new SPHINCSPLUSPrivateKey(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public SPHINCSPLUSPublicKey getPublicKey() {
        return this.PublicKey;
    }

    public byte[] getSkprf() {
        return Arrays.clone(this.skprf);
    }

    public byte[] getSkseed() {
        return Arrays.clone(this.skseed);
    }

    public int getVersion() {
        return this.version;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        aSN1EncodableVector.add(new ASN1Integer(this.version));
        aSN1EncodableVector.add(new DEROctetString(this.skseed));
        aSN1EncodableVector.add(new DEROctetString(this.skprf));
        if (this.PublicKey != null) {
            aSN1EncodableVector.add(new SPHINCSPLUSPublicKey(this.PublicKey.getPkseed(), this.PublicKey.getPkroot()));
        }
        return new DERSequence(aSN1EncodableVector);
    }
}