package org.bouncycastle.pqc.crypto.ntru;

import java.security.SecureRandom;
import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.util.SecretWithEncapsulationImpl;
import org.bouncycastle.pqc.math.ntru.Polynomial;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUParameterSet;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class NTRUKEMGenerator implements EncapsulatedSecretGenerator {
    private final SecureRandom random;

    public NTRUKEMGenerator(SecureRandom secureRandom) {
        this.random = secureRandom;
    }

    @Override // org.bouncycastle.crypto.EncapsulatedSecretGenerator
    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter asymmetricKeyParameter) {
        NTRUPublicKeyParameters nTRUPublicKeyParameters = (NTRUPublicKeyParameters) asymmetricKeyParameter;
        NTRUParameterSet nTRUParameterSet = nTRUPublicKeyParameters.getParameters().parameterSet;
        NTRUSampling nTRUSampling = new NTRUSampling(nTRUParameterSet);
        NTRUOWCPA ntruowcpa = new NTRUOWCPA(nTRUParameterSet);
        int owcpaMsgBytes = nTRUParameterSet.owcpaMsgBytes();
        byte[] bArr = new byte[owcpaMsgBytes];
        byte[] bArr2 = new byte[nTRUParameterSet.sampleRmBytes()];
        this.random.nextBytes(bArr2);
        PolynomialPair sampleRm = nTRUSampling.sampleRm(bArr2);
        Polynomial m19r = sampleRm.m19r();
        Polynomial m20m = sampleRm.m20m();
        byte[] s3ToBytes = m19r.s3ToBytes(nTRUParameterSet.owcpaMsgBytes());
        System.arraycopy(s3ToBytes, 0, bArr, 0, s3ToBytes.length);
        byte[] s3ToBytes2 = m20m.s3ToBytes(owcpaMsgBytes - nTRUParameterSet.packTrinaryBytes());
        System.arraycopy(s3ToBytes2, 0, bArr, nTRUParameterSet.packTrinaryBytes(), s3ToBytes2.length);
        SHA3Digest sHA3Digest = new SHA3Digest(256);
        sHA3Digest.update(bArr, 0, owcpaMsgBytes);
        byte[] bArr3 = new byte[sHA3Digest.getDigestSize()];
        sHA3Digest.doFinal(bArr3, 0);
        m19r.z3ToZq();
        byte[] encrypt = ntruowcpa.encrypt(m19r, m20m, nTRUPublicKeyParameters.publicKey);
        byte[] copyOfRange = Arrays.copyOfRange(bArr3, 0, nTRUParameterSet.sharedKeyBytes());
        Arrays.clear(bArr3);
        return new SecretWithEncapsulationImpl(copyOfRange, encrypt);
    }
}