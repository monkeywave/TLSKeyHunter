package org.bouncycastle.pqc.crypto.mceliece;

import java.security.SecureRandom;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;
import org.bouncycastle.pqc.crypto.MessageEncryptor;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.pqc.math.linearalgebra.GF2Vector;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/mceliece/McElieceFujisakiCipher.class */
public class McElieceFujisakiCipher implements MessageEncryptor {
    public static final String OID = "1.3.6.1.4.1.8301.3.1.3.4.2.1";
    private static final String DEFAULT_PRNG_NAME = "SHA1PRNG";
    private Digest messDigest;

    /* renamed from: sr */
    private SecureRandom f865sr;

    /* renamed from: n */
    private int f866n;

    /* renamed from: k */
    private int f867k;

    /* renamed from: t */
    private int f868t;
    McElieceCCA2KeyParameters key;
    private boolean forEncryption;

    @Override // org.bouncycastle.pqc.crypto.MessageEncryptor
    public void init(boolean z, CipherParameters cipherParameters) {
        this.forEncryption = z;
        if (!z) {
            this.key = (McElieceCCA2PrivateKeyParameters) cipherParameters;
            initCipherDecrypt((McElieceCCA2PrivateKeyParameters) this.key);
        } else if (!(cipherParameters instanceof ParametersWithRandom)) {
            this.f865sr = CryptoServicesRegistrar.getSecureRandom();
            this.key = (McElieceCCA2PublicKeyParameters) cipherParameters;
            initCipherEncrypt((McElieceCCA2PublicKeyParameters) this.key);
        } else {
            ParametersWithRandom parametersWithRandom = (ParametersWithRandom) cipherParameters;
            this.f865sr = parametersWithRandom.getRandom();
            this.key = (McElieceCCA2PublicKeyParameters) parametersWithRandom.getParameters();
            initCipherEncrypt((McElieceCCA2PublicKeyParameters) this.key);
        }
    }

    public int getKeySize(McElieceCCA2KeyParameters mcElieceCCA2KeyParameters) throws IllegalArgumentException {
        if (mcElieceCCA2KeyParameters instanceof McElieceCCA2PublicKeyParameters) {
            return ((McElieceCCA2PublicKeyParameters) mcElieceCCA2KeyParameters).getN();
        }
        if (mcElieceCCA2KeyParameters instanceof McElieceCCA2PrivateKeyParameters) {
            return ((McElieceCCA2PrivateKeyParameters) mcElieceCCA2KeyParameters).getN();
        }
        throw new IllegalArgumentException("unsupported type");
    }

    private void initCipherEncrypt(McElieceCCA2PublicKeyParameters mcElieceCCA2PublicKeyParameters) {
        this.messDigest = Utils.getDigest(mcElieceCCA2PublicKeyParameters.getDigest());
        this.f866n = mcElieceCCA2PublicKeyParameters.getN();
        this.f867k = mcElieceCCA2PublicKeyParameters.getK();
        this.f868t = mcElieceCCA2PublicKeyParameters.getT();
    }

    private void initCipherDecrypt(McElieceCCA2PrivateKeyParameters mcElieceCCA2PrivateKeyParameters) {
        this.messDigest = Utils.getDigest(mcElieceCCA2PrivateKeyParameters.getDigest());
        this.f866n = mcElieceCCA2PrivateKeyParameters.getN();
        this.f868t = mcElieceCCA2PrivateKeyParameters.getT();
    }

    @Override // org.bouncycastle.pqc.crypto.MessageEncryptor
    public byte[] messageEncrypt(byte[] bArr) {
        if (this.forEncryption) {
            GF2Vector gF2Vector = new GF2Vector(this.f867k, this.f865sr);
            byte[] encoded = gF2Vector.getEncoded();
            byte[] concatenate = ByteUtils.concatenate(encoded, bArr);
            this.messDigest.update(concatenate, 0, concatenate.length);
            byte[] bArr2 = new byte[this.messDigest.getDigestSize()];
            this.messDigest.doFinal(bArr2, 0);
            byte[] encoded2 = McElieceCCA2Primitives.encryptionPrimitive((McElieceCCA2PublicKeyParameters) this.key, gF2Vector, Conversions.encode(this.f866n, this.f868t, bArr2)).getEncoded();
            DigestRandomGenerator digestRandomGenerator = new DigestRandomGenerator(new SHA1Digest());
            digestRandomGenerator.addSeedMaterial(encoded);
            byte[] bArr3 = new byte[bArr.length];
            digestRandomGenerator.nextBytes(bArr3);
            for (int i = 0; i < bArr.length; i++) {
                int i2 = i;
                bArr3[i2] = (byte) (bArr3[i2] ^ bArr[i]);
            }
            return ByteUtils.concatenate(encoded2, bArr3);
        }
        throw new IllegalStateException("cipher initialised for decryption");
    }

    @Override // org.bouncycastle.pqc.crypto.MessageEncryptor
    public byte[] messageDecrypt(byte[] bArr) throws InvalidCipherTextException {
        if (this.forEncryption) {
            throw new IllegalStateException("cipher initialised for decryption");
        }
        int i = (this.f866n + 7) >> 3;
        int length = bArr.length - i;
        byte[][] split = ByteUtils.split(bArr, i);
        byte[] bArr2 = split[0];
        byte[] bArr3 = split[1];
        GF2Vector[] decryptionPrimitive = McElieceCCA2Primitives.decryptionPrimitive((McElieceCCA2PrivateKeyParameters) this.key, GF2Vector.OS2VP(this.f866n, bArr2));
        byte[] encoded = decryptionPrimitive[0].getEncoded();
        GF2Vector gF2Vector = decryptionPrimitive[1];
        DigestRandomGenerator digestRandomGenerator = new DigestRandomGenerator(new SHA1Digest());
        digestRandomGenerator.addSeedMaterial(encoded);
        byte[] bArr4 = new byte[length];
        digestRandomGenerator.nextBytes(bArr4);
        for (int i2 = 0; i2 < length; i2++) {
            int i3 = i2;
            bArr4[i3] = (byte) (bArr4[i3] ^ bArr3[i2]);
        }
        byte[] concatenate = ByteUtils.concatenate(encoded, bArr4);
        byte[] bArr5 = new byte[this.messDigest.getDigestSize()];
        this.messDigest.update(concatenate, 0, concatenate.length);
        this.messDigest.doFinal(bArr5, 0);
        if (Conversions.encode(this.f866n, this.f868t, bArr5).equals(gF2Vector)) {
            return bArr4;
        }
        throw new InvalidCipherTextException("Bad Padding: invalid ciphertext");
    }
}