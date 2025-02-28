package org.bouncycastle.asn1.cryptopro;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

/* loaded from: classes.dex */
public class GOST3410PublicKeyAlgParameters extends ASN1Object {
    private ASN1ObjectIdentifier digestParamSet;
    private ASN1ObjectIdentifier encryptionParamSet;
    private ASN1ObjectIdentifier publicKeyParamSet;

    public GOST3410PublicKeyAlgParameters(ASN1ObjectIdentifier aSN1ObjectIdentifier, ASN1ObjectIdentifier aSN1ObjectIdentifier2) {
        this.publicKeyParamSet = aSN1ObjectIdentifier;
        this.digestParamSet = aSN1ObjectIdentifier2;
        this.encryptionParamSet = null;
    }

    public GOST3410PublicKeyAlgParameters(ASN1ObjectIdentifier aSN1ObjectIdentifier, ASN1ObjectIdentifier aSN1ObjectIdentifier2, ASN1ObjectIdentifier aSN1ObjectIdentifier3) {
        this.publicKeyParamSet = aSN1ObjectIdentifier;
        this.digestParamSet = aSN1ObjectIdentifier2;
        this.encryptionParamSet = aSN1ObjectIdentifier3;
    }

    /* JADX WARN: Code restructure failed: missing block: B:15:0x004b, code lost:
        if (r4.size() > 1) goto L5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:5:0x001b, code lost:
        if (r4.size() > 1) goto L5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:6:0x001d, code lost:
        r3.digestParamSet = org.bouncycastle.asn1.ASN1ObjectIdentifier.getInstance(r4.getObjectAt(1));
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    private GOST3410PublicKeyAlgParameters(org.bouncycastle.asn1.ASN1Sequence r4) {
        /*
            r3 = this;
            r3.<init>()
            r0 = 0
            org.bouncycastle.asn1.ASN1Encodable r0 = r4.getObjectAt(r0)
            org.bouncycastle.asn1.ASN1ObjectIdentifier r0 = org.bouncycastle.asn1.ASN1ObjectIdentifier.getInstance(r0)
            r3.publicKeyParamSet = r0
            org.bouncycastle.asn1.ASN1ObjectIdentifier r1 = org.bouncycastle.internal.asn1.rosstandart.RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA
            boolean r0 = r0.equals(r1)
            r1 = 1
            if (r0 == 0) goto L28
            int r0 = r4.size()
            if (r0 <= r1) goto L54
        L1d:
            org.bouncycastle.asn1.ASN1Encodable r0 = r4.getObjectAt(r1)
            org.bouncycastle.asn1.ASN1ObjectIdentifier r0 = org.bouncycastle.asn1.ASN1ObjectIdentifier.getInstance(r0)
            r3.digestParamSet = r0
            goto L54
        L28:
            org.bouncycastle.asn1.ASN1ObjectIdentifier r0 = r3.publicKeyParamSet
            org.bouncycastle.asn1.ASN1ObjectIdentifier r2 = org.bouncycastle.internal.asn1.rosstandart.RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetB
            boolean r0 = r0.equals(r2)
            if (r0 != 0) goto L4e
            org.bouncycastle.asn1.ASN1ObjectIdentifier r0 = r3.publicKeyParamSet
            org.bouncycastle.asn1.ASN1ObjectIdentifier r2 = org.bouncycastle.internal.asn1.rosstandart.RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetC
            boolean r0 = r0.equals(r2)
            if (r0 != 0) goto L4e
            org.bouncycastle.asn1.ASN1ObjectIdentifier r0 = r3.publicKeyParamSet
            org.bouncycastle.asn1.ASN1ObjectIdentifier r2 = org.bouncycastle.internal.asn1.rosstandart.RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetD
            boolean r0 = r0.equals(r2)
            if (r0 == 0) goto L47
            goto L4e
        L47:
            int r0 = r4.size()
            if (r0 <= r1) goto L54
            goto L1d
        L4e:
            int r0 = r4.size()
            if (r0 > r1) goto L64
        L54:
            int r0 = r4.size()
            r1 = 2
            if (r0 <= r1) goto L63
            org.bouncycastle.asn1.ASN1Encodable r4 = r4.getObjectAt(r1)
            org.bouncycastle.asn1.ASN1ObjectIdentifier r4 = (org.bouncycastle.asn1.ASN1ObjectIdentifier) r4
            r3.encryptionParamSet = r4
        L63:
            return
        L64:
            java.lang.IllegalArgumentException r4 = new java.lang.IllegalArgumentException
            java.lang.String r0 = "digestParamSet expected to be absent"
            r4.<init>(r0)
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters.<init>(org.bouncycastle.asn1.ASN1Sequence):void");
    }

    public static GOST3410PublicKeyAlgParameters getInstance(Object obj) {
        if (obj instanceof GOST3410PublicKeyAlgParameters) {
            return (GOST3410PublicKeyAlgParameters) obj;
        }
        if (obj != null) {
            return new GOST3410PublicKeyAlgParameters(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public static GOST3410PublicKeyAlgParameters getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        return getInstance(ASN1Sequence.getInstance(aSN1TaggedObject, z));
    }

    public ASN1ObjectIdentifier getDigestParamSet() {
        return this.digestParamSet;
    }

    public ASN1ObjectIdentifier getEncryptionParamSet() {
        return this.encryptionParamSet;
    }

    public ASN1ObjectIdentifier getPublicKeyParamSet() {
        return this.publicKeyParamSet;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(3);
        aSN1EncodableVector.add(this.publicKeyParamSet);
        ASN1ObjectIdentifier aSN1ObjectIdentifier = this.digestParamSet;
        if (aSN1ObjectIdentifier != null) {
            aSN1EncodableVector.add(aSN1ObjectIdentifier);
        }
        ASN1ObjectIdentifier aSN1ObjectIdentifier2 = this.encryptionParamSet;
        if (aSN1ObjectIdentifier2 != null) {
            aSN1EncodableVector.add(aSN1ObjectIdentifier2);
        }
        return new DERSequence(aSN1EncodableVector);
    }
}