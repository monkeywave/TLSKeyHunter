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
public class KyberPrivateKey extends ASN1Object {
    private byte[] hpk;
    private byte[] nonce;
    private KyberPublicKey publicKey;

    /* renamed from: s */
    private byte[] f1182s;
    private int version;

    public KyberPrivateKey(int i, byte[] bArr, byte[] bArr2, byte[] bArr3) {
        this(i, bArr, bArr2, bArr3, null);
    }

    public KyberPrivateKey(int i, byte[] bArr, byte[] bArr2, byte[] bArr3, KyberPublicKey kyberPublicKey) {
        this.version = i;
        this.f1182s = bArr;
        this.publicKey = kyberPublicKey;
        this.hpk = bArr2;
        this.nonce = bArr3;
    }

    private KyberPrivateKey(ASN1Sequence aSN1Sequence) {
        int i = 0;
        int intValueExact = ASN1Integer.getInstance(aSN1Sequence.getObjectAt(0)).intValueExact();
        this.version = intValueExact;
        if (intValueExact != 0) {
            throw new IllegalArgumentException("unrecognized version");
        }
        this.f1182s = Arrays.clone(ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(1)).getOctets());
        if (aSN1Sequence.size() == 5) {
            this.publicKey = KyberPublicKey.getInstance(aSN1Sequence.getObjectAt(2));
        } else {
            i = 1;
        }
        this.hpk = Arrays.clone(ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(3 - i)).getOctets());
        this.nonce = Arrays.clone(ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(4 - i)).getOctets());
    }

    public static KyberPrivateKey getInstance(Object obj) {
        if (obj instanceof KyberPrivateKey) {
            return (KyberPrivateKey) obj;
        }
        if (obj != null) {
            return new KyberPrivateKey(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public byte[] getHpk() {
        return Arrays.clone(this.hpk);
    }

    public byte[] getNonce() {
        return Arrays.clone(this.nonce);
    }

    public KyberPublicKey getPublicKey() {
        return this.publicKey;
    }

    public byte[] getS() {
        return Arrays.clone(this.f1182s);
    }

    public int getVersion() {
        return this.version;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        aSN1EncodableVector.add(new ASN1Integer(this.version));
        aSN1EncodableVector.add(new DEROctetString(this.f1182s));
        if (this.publicKey != null) {
            aSN1EncodableVector.add(new KyberPublicKey(this.publicKey.getT(), this.publicKey.getRho()));
        }
        aSN1EncodableVector.add(new DEROctetString(this.hpk));
        aSN1EncodableVector.add(new DEROctetString(this.nonce));
        return new DERSequence(aSN1EncodableVector);
    }
}