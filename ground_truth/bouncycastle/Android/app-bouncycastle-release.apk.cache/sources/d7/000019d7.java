package org.bouncycastle.asn1.p006bc;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.x509.Certificate;

/* renamed from: org.bouncycastle.asn1.bc.EncryptedPrivateKeyData */
/* loaded from: classes.dex */
public class EncryptedPrivateKeyData extends ASN1Object {
    private final Certificate[] certificateChain;
    private final EncryptedPrivateKeyInfo encryptedPrivateKeyInfo;

    private EncryptedPrivateKeyData(ASN1Sequence aSN1Sequence) {
        int i = 0;
        this.encryptedPrivateKeyInfo = EncryptedPrivateKeyInfo.getInstance(aSN1Sequence.getObjectAt(0));
        ASN1Sequence aSN1Sequence2 = ASN1Sequence.getInstance(aSN1Sequence.getObjectAt(1));
        this.certificateChain = new Certificate[aSN1Sequence2.size()];
        while (true) {
            Certificate[] certificateArr = this.certificateChain;
            if (i == certificateArr.length) {
                return;
            }
            certificateArr[i] = Certificate.getInstance(aSN1Sequence2.getObjectAt(i));
            i++;
        }
    }

    public EncryptedPrivateKeyData(EncryptedPrivateKeyInfo encryptedPrivateKeyInfo, Certificate[] certificateArr) {
        this.encryptedPrivateKeyInfo = encryptedPrivateKeyInfo;
        Certificate[] certificateArr2 = new Certificate[certificateArr.length];
        this.certificateChain = certificateArr2;
        System.arraycopy(certificateArr, 0, certificateArr2, 0, certificateArr.length);
    }

    public static EncryptedPrivateKeyData getInstance(Object obj) {
        if (obj instanceof EncryptedPrivateKeyData) {
            return (EncryptedPrivateKeyData) obj;
        }
        if (obj != null) {
            return new EncryptedPrivateKeyData(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public Certificate[] getCertificateChain() {
        Certificate[] certificateArr = this.certificateChain;
        Certificate[] certificateArr2 = new Certificate[certificateArr.length];
        System.arraycopy(certificateArr, 0, certificateArr2, 0, certificateArr.length);
        return certificateArr2;
    }

    public EncryptedPrivateKeyInfo getEncryptedPrivateKeyInfo() {
        return this.encryptedPrivateKeyInfo;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(2);
        aSN1EncodableVector.add(this.encryptedPrivateKeyInfo);
        aSN1EncodableVector.add(new DERSequence(this.certificateChain));
        return new DERSequence(aSN1EncodableVector);
    }
}