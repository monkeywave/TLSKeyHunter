package org.bouncycastle.pqc.crypto.ntru;

import org.bouncycastle.pqc.math.ntru.HPSPolynomial;
import org.bouncycastle.pqc.math.ntru.Polynomial;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHPSParameterSet;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHRSSParameterSet;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUParameterSet;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
class NTRUOWCPA {
    private final NTRUParameterSet params;
    private final NTRUSampling sampling;

    public NTRUOWCPA(NTRUParameterSet nTRUParameterSet) {
        this.params = nTRUParameterSet;
        this.sampling = new NTRUSampling(nTRUParameterSet);
    }

    private int checkCiphertext(byte[] bArr) {
        return (((~((short) (bArr[this.params.ntruCiphertextBytes() - 1] & (255 << (8 - ((this.params.logQ() * this.params.packDegree()) & 7)))))) + 1) >>> 15) & 1;
    }

    private int checkM(HPSPolynomial hPSPolynomial) {
        short s = 0;
        short s2 = 0;
        for (int i = 0; i < this.params.m1n() - 1; i++) {
            s = (short) (s + (hPSPolynomial.coeffs[i] & 1));
            s2 = (short) (s2 + (hPSPolynomial.coeffs[i] & 2));
        }
        return (((~(((s2 >>> 1) ^ s) | (((NTRUHPSParameterSet) this.params).weight() ^ s2))) + 1) >>> 31) & 1;
    }

    private int checkR(Polynomial polynomial) {
        int i = 0;
        for (int i2 = 0; i2 < this.params.m1n() - 1; i2++) {
            short s = polynomial.coeffs[i2];
            i = i | ((s + 1) & (this.params.m0q() - 4)) | ((s + 2) & 4);
        }
        return (((~(polynomial.coeffs[this.params.m1n() - 1] | i)) + 1) >>> 31) & 1;
    }

    public OWCPADecryptResult decrypt(byte[] bArr, byte[] bArr2) {
        int owcpaMsgBytes = this.params.owcpaMsgBytes();
        byte[] bArr3 = new byte[owcpaMsgBytes];
        Polynomial createPolynomial = this.params.createPolynomial();
        Polynomial createPolynomial2 = this.params.createPolynomial();
        Polynomial createPolynomial3 = this.params.createPolynomial();
        Polynomial createPolynomial4 = this.params.createPolynomial();
        createPolynomial.rqSumZeroFromBytes(bArr);
        createPolynomial2.s3FromBytes(bArr2);
        createPolynomial2.z3ToZq();
        createPolynomial3.rqMul(createPolynomial, createPolynomial2);
        createPolynomial2.rqToS3(createPolynomial3);
        createPolynomial3.s3FromBytes(Arrays.copyOfRange(bArr2, this.params.packTrinaryBytes(), bArr2.length));
        createPolynomial4.s3Mul(createPolynomial2, createPolynomial3);
        byte[] s3ToBytes = createPolynomial4.s3ToBytes(owcpaMsgBytes - this.params.packTrinaryBytes());
        int checkCiphertext = checkCiphertext(bArr);
        if (this.params instanceof NTRUHPSParameterSet) {
            checkCiphertext |= checkM((HPSPolynomial) createPolynomial4);
        }
        createPolynomial2.lift(createPolynomial4);
        for (int i = 0; i < this.params.m1n(); i++) {
            createPolynomial.coeffs[i] = (short) (createPolynomial.coeffs[i] - createPolynomial2.coeffs[i]);
        }
        createPolynomial3.sqFromBytes(Arrays.copyOfRange(bArr2, this.params.packTrinaryBytes() * 2, bArr2.length));
        createPolynomial4.sqMul(createPolynomial, createPolynomial3);
        int checkR = checkCiphertext | checkR(createPolynomial4);
        createPolynomial4.trinaryZqToZ3();
        byte[] s3ToBytes2 = createPolynomial4.s3ToBytes(this.params.owcpaMsgBytes());
        System.arraycopy(s3ToBytes2, 0, bArr3, 0, s3ToBytes2.length);
        System.arraycopy(s3ToBytes, 0, bArr3, this.params.packTrinaryBytes(), s3ToBytes.length);
        return new OWCPADecryptResult(bArr3, checkR);
    }

    public byte[] encrypt(Polynomial polynomial, Polynomial polynomial2, byte[] bArr) {
        Polynomial createPolynomial = this.params.createPolynomial();
        Polynomial createPolynomial2 = this.params.createPolynomial();
        createPolynomial.rqSumZeroFromBytes(bArr);
        createPolynomial2.rqMul(polynomial, createPolynomial);
        createPolynomial.lift(polynomial2);
        for (int i = 0; i < this.params.m1n(); i++) {
            short[] sArr = createPolynomial2.coeffs;
            sArr[i] = (short) (sArr[i] + createPolynomial.coeffs[i]);
        }
        return createPolynomial2.rqSumZeroToBytes(this.params.ntruCiphertextBytes());
    }

    public OWCPAKeyPair keypair(byte[] bArr) {
        int owcpaSecretKeyBytes = this.params.owcpaSecretKeyBytes();
        byte[] bArr2 = new byte[owcpaSecretKeyBytes];
        int m1n = this.params.m1n();
        this.params.m0q();
        Polynomial createPolynomial = this.params.createPolynomial();
        Polynomial createPolynomial2 = this.params.createPolynomial();
        Polynomial createPolynomial3 = this.params.createPolynomial();
        PolynomialPair sampleFg = this.sampling.sampleFg(bArr);
        Polynomial m22f = sampleFg.m22f();
        Polynomial m21g = sampleFg.m21g();
        createPolynomial.s3Inv(m22f);
        byte[] s3ToBytes = m22f.s3ToBytes(this.params.owcpaMsgBytes());
        System.arraycopy(s3ToBytes, 0, bArr2, 0, s3ToBytes.length);
        byte[] s3ToBytes2 = createPolynomial.s3ToBytes(owcpaSecretKeyBytes - this.params.packTrinaryBytes());
        System.arraycopy(s3ToBytes2, 0, bArr2, this.params.packTrinaryBytes(), s3ToBytes2.length);
        m22f.z3ToZq();
        m21g.z3ToZq();
        if (this.params instanceof NTRUHRSSParameterSet) {
            for (int i = m1n - 1; i > 0; i--) {
                m21g.coeffs[i] = (short) ((m21g.coeffs[i - 1] - m21g.coeffs[i]) * 3);
            }
            m21g.coeffs[0] = (short) (-(m21g.coeffs[0] * 3));
        } else {
            for (int i2 = 0; i2 < m1n; i2++) {
                m21g.coeffs[i2] = (short) (m21g.coeffs[i2] * 3);
            }
        }
        createPolynomial.rqMul(m21g, m22f);
        createPolynomial2.rqInv(createPolynomial);
        createPolynomial3.rqMul(createPolynomial2, m22f);
        createPolynomial.sqMul(createPolynomial3, m22f);
        byte[] sqToBytes = createPolynomial.sqToBytes(owcpaSecretKeyBytes - (this.params.packTrinaryBytes() * 2));
        System.arraycopy(sqToBytes, 0, bArr2, this.params.packTrinaryBytes() * 2, sqToBytes.length);
        createPolynomial3.rqMul(createPolynomial2, m21g);
        createPolynomial.rqMul(createPolynomial3, m21g);
        return new OWCPAKeyPair(createPolynomial.rqSumZeroToBytes(this.params.owcpaPublicKeyBytes()), bArr2);
    }
}