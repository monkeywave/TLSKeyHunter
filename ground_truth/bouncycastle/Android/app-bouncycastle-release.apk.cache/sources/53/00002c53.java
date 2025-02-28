package org.bouncycastle.pqc.jcajce.provider.util;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.p009x9.X9ObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.jcajce.spec.KEMKDFSpec;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class KdfUtil {
    static Digest getDigest(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
        if (aSN1ObjectIdentifier.equals((ASN1Primitive) NISTObjectIdentifiers.id_sha256)) {
            return new SHA256Digest();
        }
        if (aSN1ObjectIdentifier.equals((ASN1Primitive) NISTObjectIdentifiers.id_sha512)) {
            return new SHA512Digest();
        }
        if (aSN1ObjectIdentifier.equals((ASN1Primitive) NISTObjectIdentifiers.id_shake128)) {
            return new SHAKEDigest(128);
        }
        if (aSN1ObjectIdentifier.equals((ASN1Primitive) NISTObjectIdentifiers.id_shake256)) {
            return new SHAKEDigest(256);
        }
        throw new IllegalArgumentException("unrecognized digest OID: " + aSN1ObjectIdentifier);
    }

    public static byte[] makeKeyBytes(KEMKDFSpec kEMKDFSpec, byte[] bArr) {
        DerivationFunction concatenationKDFGenerator;
        if (kEMKDFSpec == null) {
            try {
                int length = bArr.length;
                System.arraycopy(bArr, 0, new byte[length], 0, length);
            } finally {
                Arrays.clear(bArr);
            }
        }
        AlgorithmIdentifier kdfAlgorithm = kEMKDFSpec.getKdfAlgorithm();
        byte[] otherInfo = kEMKDFSpec.getOtherInfo();
        int keySize = (kEMKDFSpec.getKeySize() + 7) / 8;
        byte[] bArr2 = new byte[keySize];
        if (kdfAlgorithm == null) {
            System.arraycopy(bArr, 0, bArr2, 0, (kEMKDFSpec.getKeySize() + 7) / 8);
        } else {
            if (X9ObjectIdentifiers.id_kdf_kdf2.equals((ASN1Primitive) kdfAlgorithm.getAlgorithm())) {
                concatenationKDFGenerator = new KDF2BytesGenerator(getDigest(AlgorithmIdentifier.getInstance(kdfAlgorithm.getParameters()).getAlgorithm()));
                concatenationKDFGenerator.init(new KDFParameters(bArr, otherInfo));
            } else if (X9ObjectIdentifiers.id_kdf_kdf3.equals((ASN1Primitive) kdfAlgorithm.getAlgorithm())) {
                concatenationKDFGenerator = new ConcatenationKDFGenerator(getDigest(AlgorithmIdentifier.getInstance(kdfAlgorithm.getParameters()).getAlgorithm()));
                concatenationKDFGenerator.init(new KDFParameters(bArr, otherInfo));
            } else if (!NISTObjectIdentifiers.id_shake256.equals((ASN1Primitive) kdfAlgorithm.getAlgorithm())) {
                throw new IllegalStateException("Unrecognized KDF: " + kdfAlgorithm.getAlgorithm());
            } else {
                SHAKEDigest sHAKEDigest = new SHAKEDigest(256);
                sHAKEDigest.update(bArr, 0, bArr.length);
                sHAKEDigest.update(otherInfo, 0, otherInfo.length);
                sHAKEDigest.doFinal(bArr2, 0, keySize);
            }
            concatenationKDFGenerator.generateBytes(bArr2, 0, keySize);
        }
        return bArr2;
    }
}