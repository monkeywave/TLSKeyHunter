package org.bouncycastle.jcajce;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.PublicKey;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.p006bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.p006bc.ExternalValue;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.util.MessageDigestUtils;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class ExternalPublicKey implements PublicKey {
    private final byte[] digest;
    private final AlgorithmIdentifier digestAlg;
    private final GeneralName location;

    public ExternalPublicKey(PublicKey publicKey, GeneralName generalName, MessageDigest messageDigest) {
        this(generalName, MessageDigestUtils.getDigestAlgID(messageDigest.getAlgorithm()), messageDigest.digest(publicKey.getEncoded()));
    }

    public ExternalPublicKey(ExternalValue externalValue) {
        this(externalValue.getLocation(), externalValue.getHashAlg(), externalValue.getHashValue());
    }

    public ExternalPublicKey(GeneralName generalName, AlgorithmIdentifier algorithmIdentifier, byte[] bArr) {
        this.location = generalName;
        this.digestAlg = algorithmIdentifier;
        this.digest = Arrays.clone(bArr);
    }

    @Override // java.security.Key
    public String getAlgorithm() {
        return "ExternalKey";
    }

    @Override // java.security.Key
    public byte[] getEncoded() {
        try {
            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(BCObjectIdentifiers.external_value), new ExternalValue(this.location, this.digestAlg, this.digest)).getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            throw new IllegalStateException("unable to encode composite key: " + e.getMessage());
        }
    }

    @Override // java.security.Key
    public String getFormat() {
        return "X.509";
    }
}