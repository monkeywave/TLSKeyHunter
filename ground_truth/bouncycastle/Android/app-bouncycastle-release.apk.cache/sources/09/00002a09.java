package org.bouncycastle.pqc.crypto.mlkem;

import java.security.SecureRandom;
import org.bouncycastle.pqc.crypto.mlkem.Symmetric;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.util.Arrays;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class MLKEMEngine {
    private static final int KyberEta2 = 2;
    private static final int KyberIndCpaMsgBytes = 32;
    public static final int KyberN = 256;
    public static final int KyberPolyBytes = 384;
    public static final int KyberQ = 3329;
    public static final int KyberQinv = 62209;
    private static final int KyberSharedSecretBytes = 32;
    public static final int KyberSymBytes = 32;
    private final int CryptoBytes;
    private final int CryptoCipherTextBytes;
    private final int CryptoPublicKeyBytes;
    private final int CryptoSecretKeyBytes;
    private final int KyberCipherTextBytes;
    private final int KyberEta1;
    private final int KyberIndCpaBytes;
    private final int KyberIndCpaPublicKeyBytes;
    private final int KyberIndCpaSecretKeyBytes;
    private final int KyberK;
    private final int KyberPolyCompressedBytes;
    private final int KyberPolyVecBytes;
    private final int KyberPolyVecCompressedBytes;
    private final int KyberPublicKeyBytes;
    private final int KyberSecretKeyBytes;
    private MLKEMIndCpa indCpa;
    private SecureRandom random;
    private final int sessionKeyLength;
    private final Symmetric symmetric;

    public MLKEMEngine(int i) {
        int i2;
        this.KyberK = i;
        if (i == 2) {
            this.KyberEta1 = 3;
        } else if (i != 3) {
            if (i != 4) {
                throw new IllegalArgumentException("K: " + i + " is not supported for Crystals Kyber");
            }
            this.KyberEta1 = 2;
            this.KyberPolyCompressedBytes = CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256;
            i2 = i * 352;
            this.KyberPolyVecCompressedBytes = i2;
            this.sessionKeyLength = 32;
            int i3 = i * KyberPolyBytes;
            this.KyberPolyVecBytes = i3;
            int i4 = i3 + 32;
            this.KyberIndCpaPublicKeyBytes = i4;
            this.KyberIndCpaSecretKeyBytes = i3;
            int i5 = this.KyberPolyVecCompressedBytes + this.KyberPolyCompressedBytes;
            this.KyberIndCpaBytes = i5;
            this.KyberPublicKeyBytes = i4;
            int i6 = i3 + i4 + 64;
            this.KyberSecretKeyBytes = i6;
            this.KyberCipherTextBytes = i5;
            this.CryptoBytes = 32;
            this.CryptoSecretKeyBytes = i6;
            this.CryptoPublicKeyBytes = i4;
            this.CryptoCipherTextBytes = i5;
            this.symmetric = new Symmetric.ShakeSymmetric();
            this.indCpa = new MLKEMIndCpa(this);
        } else {
            this.KyberEta1 = 2;
        }
        this.KyberPolyCompressedBytes = 128;
        i2 = i * 320;
        this.KyberPolyVecCompressedBytes = i2;
        this.sessionKeyLength = 32;
        int i32 = i * KyberPolyBytes;
        this.KyberPolyVecBytes = i32;
        int i42 = i32 + 32;
        this.KyberIndCpaPublicKeyBytes = i42;
        this.KyberIndCpaSecretKeyBytes = i32;
        int i52 = this.KyberPolyVecCompressedBytes + this.KyberPolyCompressedBytes;
        this.KyberIndCpaBytes = i52;
        this.KyberPublicKeyBytes = i42;
        int i62 = i32 + i42 + 64;
        this.KyberSecretKeyBytes = i62;
        this.KyberCipherTextBytes = i52;
        this.CryptoBytes = 32;
        this.CryptoSecretKeyBytes = i62;
        this.CryptoPublicKeyBytes = i42;
        this.CryptoCipherTextBytes = i52;
        this.symmetric = new Symmetric.ShakeSymmetric();
        this.indCpa = new MLKEMIndCpa(this);
    }

    private void cmov(byte[] bArr, byte[] bArr2, int i, boolean z) {
        if (z) {
            System.arraycopy(bArr2, 0, bArr, 0, i);
        } else {
            System.arraycopy(bArr, 0, bArr, 0, i);
        }
    }

    public static int getKyberEta2() {
        return 2;
    }

    public static int getKyberIndCpaMsgBytes() {
        return 32;
    }

    public byte[][] generateKemKeyPair() {
        byte[] bArr = new byte[32];
        byte[] bArr2 = new byte[32];
        this.random.nextBytes(bArr);
        this.random.nextBytes(bArr2);
        return generateKemKeyPairInternal(bArr, bArr2);
    }

    public byte[][] generateKemKeyPairInternal(byte[] bArr, byte[] bArr2) {
        byte[][] generateKeyPair = this.indCpa.generateKeyPair(bArr);
        int i = this.KyberIndCpaSecretKeyBytes;
        byte[] bArr3 = new byte[i];
        System.arraycopy(generateKeyPair[1], 0, bArr3, 0, i);
        byte[] bArr4 = new byte[32];
        this.symmetric.hash_h(bArr4, generateKeyPair[0], 0);
        int i2 = this.KyberIndCpaPublicKeyBytes;
        byte[] bArr5 = new byte[i2];
        System.arraycopy(generateKeyPair[0], 0, bArr5, 0, i2);
        int i3 = i2 - 32;
        return new byte[][]{Arrays.copyOfRange(bArr5, 0, i3), Arrays.copyOfRange(bArr5, i3, i2), bArr3, bArr4, bArr2, Arrays.concatenate(bArr, bArr2)};
    }

    public int getCryptoBytes() {
        return this.CryptoBytes;
    }

    public int getCryptoCipherTextBytes() {
        return this.CryptoCipherTextBytes;
    }

    public int getCryptoPublicKeyBytes() {
        return this.CryptoPublicKeyBytes;
    }

    public int getCryptoSecretKeyBytes() {
        return this.CryptoSecretKeyBytes;
    }

    public int getKyberCipherTextBytes() {
        return this.KyberCipherTextBytes;
    }

    public int getKyberEta1() {
        return this.KyberEta1;
    }

    public int getKyberIndCpaBytes() {
        return this.KyberIndCpaBytes;
    }

    public int getKyberIndCpaPublicKeyBytes() {
        return this.KyberIndCpaPublicKeyBytes;
    }

    public int getKyberIndCpaSecretKeyBytes() {
        return this.KyberIndCpaSecretKeyBytes;
    }

    public int getKyberK() {
        return this.KyberK;
    }

    public int getKyberPolyCompressedBytes() {
        return this.KyberPolyCompressedBytes;
    }

    public int getKyberPolyVecBytes() {
        return this.KyberPolyVecBytes;
    }

    public int getKyberPolyVecCompressedBytes() {
        return this.KyberPolyVecCompressedBytes;
    }

    public int getKyberPublicKeyBytes() {
        return this.KyberPublicKeyBytes;
    }

    public int getKyberSecretKeyBytes() {
        return this.KyberSecretKeyBytes;
    }

    public void getRandomBytes(byte[] bArr) {
        this.random.nextBytes(bArr);
    }

    public Symmetric getSymmetric() {
        return this.symmetric;
    }

    public void init(SecureRandom secureRandom) {
        this.random = secureRandom;
    }

    public byte[] kemDecrypt(byte[] bArr, byte[] bArr2) {
        return kemDecryptInternal(bArr, bArr2);
    }

    public byte[] kemDecryptInternal(byte[] bArr, byte[] bArr2) {
        byte[] bArr3 = new byte[64];
        byte[] bArr4 = new byte[64];
        byte[] copyOfRange = Arrays.copyOfRange(bArr, this.KyberIndCpaSecretKeyBytes, bArr.length);
        System.arraycopy(this.indCpa.decrypt(bArr, bArr2), 0, bArr3, 0, 32);
        System.arraycopy(bArr, this.KyberSecretKeyBytes - 64, bArr3, 32, 32);
        this.symmetric.hash_g(bArr4, bArr3);
        byte[] bArr5 = new byte[this.KyberCipherTextBytes + 32];
        System.arraycopy(bArr, this.KyberSecretKeyBytes - 32, bArr5, 0, 32);
        System.arraycopy(bArr2, 0, bArr5, 32, this.KyberCipherTextBytes);
        this.symmetric.kdf(bArr5, bArr5);
        cmov(bArr4, bArr5, 32, !Arrays.constantTimeAreEqual(bArr2, this.indCpa.encrypt(copyOfRange, Arrays.copyOfRange(bArr3, 0, 32), Arrays.copyOfRange(bArr4, 32, 64))));
        return Arrays.copyOfRange(bArr4, 0, this.sessionKeyLength);
    }

    public byte[][] kemEncrypt(byte[] bArr, byte[] bArr2) {
        if (bArr.length == this.KyberIndCpaPublicKeyBytes) {
            PolyVec polyVec = new PolyVec(this);
            if (Arrays.areEqual(this.indCpa.packPublicKey(polyVec, this.indCpa.unpackPublicKey(polyVec, bArr)), bArr)) {
                return kemEncryptInternal(bArr, bArr2);
            }
            throw new IllegalArgumentException("Input validation: Modulus check failed for ml-kem encapsulation");
        }
        throw new IllegalArgumentException("Input validation Error: Type check failed for ml-kem encapsulation");
    }

    public byte[][] kemEncryptInternal(byte[] bArr, byte[] bArr2) {
        byte[] bArr3 = new byte[64];
        byte[] bArr4 = new byte[64];
        System.arraycopy(bArr2, 0, bArr3, 0, 32);
        this.symmetric.hash_h(bArr3, bArr, 32);
        this.symmetric.hash_g(bArr4, bArr3);
        byte[] encrypt = this.indCpa.encrypt(bArr, Arrays.copyOfRange(bArr3, 0, 32), Arrays.copyOfRange(bArr4, 32, 64));
        int i = this.sessionKeyLength;
        byte[] bArr5 = new byte[i];
        System.arraycopy(bArr4, 0, bArr5, 0, i);
        return new byte[][]{bArr5, encrypt};
    }
}