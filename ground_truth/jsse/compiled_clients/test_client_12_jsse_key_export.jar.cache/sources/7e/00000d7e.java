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
import org.bouncycastle.pqc.math.linearalgebra.IntegerFunctions;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/mceliece/McElieceKobaraImaiCipher.class */
public class McElieceKobaraImaiCipher implements MessageEncryptor {
    public static final String OID = "1.3.6.1.4.1.8301.3.1.3.4.2.3";
    private static final String DEFAULT_PRNG_NAME = "SHA1PRNG";
    public static final byte[] PUBLIC_CONSTANT = "a predetermined public constant".getBytes();
    private Digest messDigest;

    /* renamed from: sr */
    private SecureRandom f872sr;
    McElieceCCA2KeyParameters key;

    /* renamed from: n */
    private int f873n;

    /* renamed from: k */
    private int f874k;

    /* renamed from: t */
    private int f875t;
    private boolean forEncryption;

    @Override // org.bouncycastle.pqc.crypto.MessageEncryptor
    public void init(boolean z, CipherParameters cipherParameters) {
        this.forEncryption = z;
        if (!z) {
            this.key = (McElieceCCA2PrivateKeyParameters) cipherParameters;
            initCipherDecrypt((McElieceCCA2PrivateKeyParameters) this.key);
        } else if (!(cipherParameters instanceof ParametersWithRandom)) {
            this.f872sr = CryptoServicesRegistrar.getSecureRandom();
            this.key = (McElieceCCA2PublicKeyParameters) cipherParameters;
            initCipherEncrypt((McElieceCCA2PublicKeyParameters) this.key);
        } else {
            ParametersWithRandom parametersWithRandom = (ParametersWithRandom) cipherParameters;
            this.f872sr = parametersWithRandom.getRandom();
            this.key = (McElieceCCA2PublicKeyParameters) parametersWithRandom.getParameters();
            initCipherEncrypt((McElieceCCA2PublicKeyParameters) this.key);
        }
    }

    public int getKeySize(McElieceCCA2KeyParameters mcElieceCCA2KeyParameters) {
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
        this.f873n = mcElieceCCA2PublicKeyParameters.getN();
        this.f874k = mcElieceCCA2PublicKeyParameters.getK();
        this.f875t = mcElieceCCA2PublicKeyParameters.getT();
    }

    private void initCipherDecrypt(McElieceCCA2PrivateKeyParameters mcElieceCCA2PrivateKeyParameters) {
        this.messDigest = Utils.getDigest(mcElieceCCA2PrivateKeyParameters.getDigest());
        this.f873n = mcElieceCCA2PrivateKeyParameters.getN();
        this.f874k = mcElieceCCA2PrivateKeyParameters.getK();
        this.f875t = mcElieceCCA2PrivateKeyParameters.getT();
    }

    @Override // org.bouncycastle.pqc.crypto.MessageEncryptor
    public byte[] messageEncrypt(byte[] bArr) {
        if (this.forEncryption) {
            int digestSize = this.messDigest.getDigestSize();
            int i = this.f874k >> 3;
            int bitLength = (IntegerFunctions.binomial(this.f873n, this.f875t).bitLength() - 1) >> 3;
            int length = ((i + bitLength) - digestSize) - PUBLIC_CONSTANT.length;
            if (bArr.length > length) {
                length = bArr.length;
            }
            int length2 = length + PUBLIC_CONSTANT.length;
            int i2 = ((length2 + digestSize) - i) - bitLength;
            byte[] bArr2 = new byte[length2];
            System.arraycopy(bArr, 0, bArr2, 0, bArr.length);
            System.arraycopy(PUBLIC_CONSTANT, 0, bArr2, length, PUBLIC_CONSTANT.length);
            byte[] bArr3 = new byte[digestSize];
            this.f872sr.nextBytes(bArr3);
            DigestRandomGenerator digestRandomGenerator = new DigestRandomGenerator(new SHA1Digest());
            digestRandomGenerator.addSeedMaterial(bArr3);
            byte[] bArr4 = new byte[length2];
            digestRandomGenerator.nextBytes(bArr4);
            for (int i3 = length2 - 1; i3 >= 0; i3--) {
                int i4 = i3;
                bArr4[i4] = (byte) (bArr4[i4] ^ bArr2[i3]);
            }
            byte[] bArr5 = new byte[this.messDigest.getDigestSize()];
            this.messDigest.update(bArr4, 0, bArr4.length);
            this.messDigest.doFinal(bArr5, 0);
            for (int i5 = digestSize - 1; i5 >= 0; i5--) {
                int i6 = i5;
                bArr5[i6] = (byte) (bArr5[i6] ^ bArr3[i5]);
            }
            byte[] concatenate = ByteUtils.concatenate(bArr5, bArr4);
            byte[] bArr6 = new byte[0];
            if (i2 > 0) {
                bArr6 = new byte[i2];
                System.arraycopy(concatenate, 0, bArr6, 0, i2);
            }
            byte[] bArr7 = new byte[bitLength];
            System.arraycopy(concatenate, i2, bArr7, 0, bitLength);
            byte[] bArr8 = new byte[i];
            System.arraycopy(concatenate, i2 + bitLength, bArr8, 0, i);
            byte[] encoded = McElieceCCA2Primitives.encryptionPrimitive((McElieceCCA2PublicKeyParameters) this.key, GF2Vector.OS2VP(this.f874k, bArr8), Conversions.encode(this.f873n, this.f875t, bArr7)).getEncoded();
            return i2 > 0 ? ByteUtils.concatenate(bArr6, encoded) : encoded;
        }
        throw new IllegalStateException("cipher initialised for decryption");
    }

    @Override // org.bouncycastle.pqc.crypto.MessageEncryptor
    public byte[] messageDecrypt(byte[] bArr) throws InvalidCipherTextException {
        byte[] bArr2;
        byte[] bArr3;
        if (this.forEncryption) {
            throw new IllegalStateException("cipher initialised for decryption");
        }
        int i = this.f873n >> 3;
        if (bArr.length < i) {
            throw new InvalidCipherTextException("Bad Padding: Ciphertext too short.");
        }
        int digestSize = this.messDigest.getDigestSize();
        int i2 = this.f874k >> 3;
        int bitLength = (IntegerFunctions.binomial(this.f873n, this.f875t).bitLength() - 1) >> 3;
        int length = bArr.length - i;
        if (length > 0) {
            byte[][] split = ByteUtils.split(bArr, length);
            bArr2 = split[0];
            bArr3 = split[1];
        } else {
            bArr2 = new byte[0];
            bArr3 = bArr;
        }
        GF2Vector[] decryptionPrimitive = McElieceCCA2Primitives.decryptionPrimitive((McElieceCCA2PrivateKeyParameters) this.key, GF2Vector.OS2VP(this.f873n, bArr3));
        byte[] encoded = decryptionPrimitive[0].getEncoded();
        GF2Vector gF2Vector = decryptionPrimitive[1];
        if (encoded.length > i2) {
            encoded = ByteUtils.subArray(encoded, 0, i2);
        }
        byte[] decode = Conversions.decode(this.f873n, this.f875t, gF2Vector);
        if (decode.length < bitLength) {
            byte[] bArr4 = new byte[bitLength];
            System.arraycopy(decode, 0, bArr4, bitLength - decode.length, decode.length);
            decode = bArr4;
        }
        byte[] concatenate = ByteUtils.concatenate(ByteUtils.concatenate(bArr2, decode), encoded);
        int length2 = concatenate.length - digestSize;
        byte[][] split2 = ByteUtils.split(concatenate, digestSize);
        byte[] bArr5 = split2[0];
        byte[] bArr6 = split2[1];
        byte[] bArr7 = new byte[this.messDigest.getDigestSize()];
        this.messDigest.update(bArr6, 0, bArr6.length);
        this.messDigest.doFinal(bArr7, 0);
        for (int i3 = digestSize - 1; i3 >= 0; i3--) {
            int i4 = i3;
            bArr7[i4] = (byte) (bArr7[i4] ^ bArr5[i3]);
        }
        DigestRandomGenerator digestRandomGenerator = new DigestRandomGenerator(new SHA1Digest());
        digestRandomGenerator.addSeedMaterial(bArr7);
        byte[] bArr8 = new byte[length2];
        digestRandomGenerator.nextBytes(bArr8);
        for (int i5 = length2 - 1; i5 >= 0; i5--) {
            int i6 = i5;
            bArr8[i6] = (byte) (bArr8[i6] ^ bArr6[i5]);
        }
        if (bArr8.length < length2) {
            throw new InvalidCipherTextException("Bad Padding: invalid ciphertext");
        }
        byte[][] split3 = ByteUtils.split(bArr8, length2 - PUBLIC_CONSTANT.length);
        byte[] bArr9 = split3[0];
        if (ByteUtils.equals(split3[1], PUBLIC_CONSTANT)) {
            return bArr9;
        }
        throw new InvalidCipherTextException("Bad Padding: invalid ciphertext");
    }
}