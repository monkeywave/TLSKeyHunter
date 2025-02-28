package org.bouncycastle.asn1.p000bc;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Arrays;

/* renamed from: org.bouncycastle.asn1.bc.EncryptedSecretKeyData */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/bc/EncryptedSecretKeyData.class */
public class EncryptedSecretKeyData extends ASN1Object {
    private final AlgorithmIdentifier keyEncryptionAlgorithm;
    private final ASN1OctetString encryptedKeyData;

    public EncryptedSecretKeyData(AlgorithmIdentifier algorithmIdentifier, byte[] bArr) {
        this.keyEncryptionAlgorithm = algorithmIdentifier;
        this.encryptedKeyData = new DEROctetString(Arrays.clone(bArr));
    }

    private EncryptedSecretKeyData(ASN1Sequence aSN1Sequence) {
        this.keyEncryptionAlgorithm = AlgorithmIdentifier.getInstance(aSN1Sequence.getObjectAt(0));
        this.encryptedKeyData = ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(1));
    }

    public static EncryptedSecretKeyData getInstance(Object obj) {
        if (obj instanceof EncryptedSecretKeyData) {
            return (EncryptedSecretKeyData) obj;
        }
        if (obj != null) {
            return new EncryptedSecretKeyData(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public AlgorithmIdentifier getKeyEncryptionAlgorithm() {
        return this.keyEncryptionAlgorithm;
    }

    public byte[] getEncryptedKeyData() {
        return Arrays.clone(this.encryptedKeyData.getOctets());
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(2);
        aSN1EncodableVector.add(this.keyEncryptionAlgorithm);
        aSN1EncodableVector.add(this.encryptedKeyData);
        return new DERSequence(aSN1EncodableVector);
    }
}