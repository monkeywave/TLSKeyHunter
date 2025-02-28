package org.bouncycastle.pqc.crypto.sphincs;

import kotlin.UByte;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.sphincs.Tree;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class SPHINCS256Signer implements MessageSigner {
    private final HashFunctions hashFunctions;
    private byte[] keyData;

    public SPHINCS256Signer(Digest digest, Digest digest2) {
        if (digest.getDigestSize() != 32) {
            throw new IllegalArgumentException("n-digest needs to produce 32 bytes of output");
        }
        if (digest2.getDigestSize() != 64) {
            throw new IllegalArgumentException("2n-digest needs to produce 64 bytes of output");
        }
        this.hashFunctions = new HashFunctions(digest, digest2);
    }

    static void compute_authpath_wots(HashFunctions hashFunctions, byte[] bArr, byte[] bArr2, int i, Tree.leafaddr leafaddrVar, byte[] bArr3, byte[] bArr4, int i2) {
        Tree.leafaddr leafaddrVar2 = new Tree.leafaddr(leafaddrVar);
        byte[] bArr5 = new byte[2048];
        byte[] bArr6 = new byte[1024];
        byte[] bArr7 = new byte[68608];
        leafaddrVar2.subleaf = 0L;
        while (leafaddrVar2.subleaf < 32) {
            Seed.get_seed(hashFunctions, bArr6, (int) (leafaddrVar2.subleaf * 32), bArr3, leafaddrVar2);
            leafaddrVar2.subleaf++;
        }
        Wots wots = new Wots();
        leafaddrVar2.subleaf = 0L;
        while (leafaddrVar2.subleaf < 32) {
            wots.wots_pkgen(hashFunctions, bArr7, (int) (leafaddrVar2.subleaf * 2144), bArr6, (int) (leafaddrVar2.subleaf * 32), bArr4, 0);
            leafaddrVar2.subleaf++;
        }
        leafaddrVar2.subleaf = 0L;
        while (leafaddrVar2.subleaf < 32) {
            Tree.l_tree(hashFunctions, bArr5, (int) ((leafaddrVar2.subleaf * 32) + 1024), bArr7, (int) (leafaddrVar2.subleaf * 2144), bArr4, 0);
            leafaddrVar2.subleaf++;
        }
        int i3 = 0;
        for (int i4 = 32; i4 > 0; i4 >>>= 1) {
            for (int i5 = 0; i5 < i4; i5 += 2) {
                hashFunctions.hash_2n_n_mask(bArr5, ((i4 >>> 1) * 32) + ((i5 >>> 1) * 32), bArr5, (i4 * 32) + (i5 * 32), bArr4, (i3 + 7) * 64);
            }
            i3++;
        }
        int i6 = (int) leafaddrVar.subleaf;
        for (int i7 = 0; i7 < i2; i7++) {
            System.arraycopy(bArr5, ((32 >>> i7) * 32) + (((i6 >>> i7) ^ 1) * 32), bArr2, i + (i7 * 32), 32);
        }
        System.arraycopy(bArr5, 32, bArr, 0, 32);
    }

    static void validate_authpath(HashFunctions hashFunctions, byte[] bArr, byte[] bArr2, int i, byte[] bArr3, int i2, byte[] bArr4, int i3) {
        byte[] bArr5 = new byte[64];
        if ((i & 1) != 0) {
            for (int i4 = 0; i4 < 32; i4++) {
                bArr5[i4 + 32] = bArr2[i4];
            }
            for (int i5 = 0; i5 < 32; i5++) {
                bArr5[i5] = bArr3[i2 + i5];
            }
        } else {
            for (int i6 = 0; i6 < 32; i6++) {
                bArr5[i6] = bArr2[i6];
            }
            for (int i7 = 0; i7 < 32; i7++) {
                bArr5[i7 + 32] = bArr3[i2 + i7];
            }
        }
        int i8 = i2 + 32;
        int i9 = 0;
        int i10 = i;
        while (i9 < i3 - 1) {
            int i11 = i10 >>> 1;
            if ((i11 & 1) != 0) {
                hashFunctions.hash_2n_n_mask(bArr5, 32, bArr5, 0, bArr4, (i9 + 7) * 64);
                for (int i12 = 0; i12 < 32; i12++) {
                    bArr5[i12] = bArr3[i8 + i12];
                }
            } else {
                hashFunctions.hash_2n_n_mask(bArr5, 0, bArr5, 0, bArr4, (i9 + 7) * 64);
                for (int i13 = 0; i13 < 32; i13++) {
                    bArr5[i13 + 32] = bArr3[i8 + i13];
                }
            }
            i8 += 32;
            i9++;
            i10 = i11;
        }
        hashFunctions.hash_2n_n_mask(bArr, 0, bArr5, 0, bArr4, (i3 + 6) * 64);
    }

    private void zerobytes(byte[] bArr, int i, int i2) {
        for (int i3 = 0; i3 != i2; i3++) {
            bArr[i + i3] = 0;
        }
    }

    byte[] crypto_sign(HashFunctions hashFunctions, byte[] bArr, byte[] bArr2) {
        long j;
        long j2;
        byte[] bArr3 = new byte[41000];
        byte[] bArr4 = new byte[32];
        byte[] bArr5 = new byte[64];
        long[] jArr = new long[8];
        byte[] bArr6 = new byte[32];
        byte[] bArr7 = new byte[32];
        byte[] bArr8 = new byte[1024];
        byte[] bArr9 = new byte[1088];
        for (int i = 0; i < 1088; i++) {
            bArr9[i] = bArr2[i];
        }
        System.arraycopy(bArr9, 1056, bArr3, 40968, 32);
        Digest messageHash = hashFunctions.getMessageHash();
        byte[] bArr10 = new byte[messageHash.getDigestSize()];
        messageHash.update(bArr3, 40968, 32);
        messageHash.update(bArr, 0, bArr.length);
        messageHash.doFinal(bArr10, 0);
        zerobytes(bArr3, 40968, 32);
        for (int i2 = 0; i2 != 8; i2++) {
            jArr[i2] = Pack.littleEndianToLong(bArr10, i2 * 8);
        }
        System.arraycopy(bArr10, 16, bArr4, 0, 32);
        System.arraycopy(bArr4, 0, bArr3, 39912, 32);
        Tree.leafaddr leafaddrVar = new Tree.leafaddr();
        leafaddrVar.level = 11;
        leafaddrVar.subtree = 0L;
        leafaddrVar.subleaf = 0L;
        System.arraycopy(bArr9, 32, bArr3, 39944, 1024);
        Tree.treehash(hashFunctions, bArr3, 40968, 5, bArr9, leafaddrVar, bArr3, 39944);
        Digest messageHash2 = hashFunctions.getMessageHash();
        messageHash2.update(bArr3, 39912, 1088);
        messageHash2.update(bArr, 0, bArr.length);
        messageHash2.doFinal(bArr5, 0);
        Tree.leafaddr leafaddrVar2 = new Tree.leafaddr();
        leafaddrVar2.level = 12;
        leafaddrVar2.subleaf = (int) (j & 31);
        leafaddrVar2.subtree = (jArr[0] & 1152921504606846975L) >>> 5;
        for (int i3 = 0; i3 < 32; i3++) {
            bArr3[i3] = bArr4[i3];
        }
        byte[] bArr11 = bArr8;
        System.arraycopy(bArr9, 32, bArr11, 0, 1024);
        for (int i4 = 0; i4 < 8; i4++) {
            bArr3[32 + i4] = (byte) ((j2 >>> (i4 * 8)) & 255);
        }
        Seed.get_seed(hashFunctions, bArr7, 0, bArr9, leafaddrVar2);
        new Horst();
        Wots wots = new Wots();
        int horst_sign = 40 + Horst.horst_sign(hashFunctions, bArr3, 40, bArr6, bArr7, bArr11, bArr5);
        int i5 = 0;
        for (int i6 = 12; i5 < i6; i6 = 12) {
            leafaddrVar2.level = i5;
            Seed.get_seed(hashFunctions, bArr7, 0, bArr9, leafaddrVar2);
            int i7 = horst_sign;
            int i8 = i5;
            byte[] bArr12 = bArr11;
            wots.wots_sign(hashFunctions, bArr3, horst_sign, bArr6, bArr7, bArr12);
            compute_authpath_wots(hashFunctions, bArr6, bArr3, i7 + 2144, leafaddrVar2, bArr9, bArr12, 5);
            horst_sign = i7 + 2304;
            leafaddrVar2.subleaf = (int) (leafaddrVar2.subtree & 31);
            leafaddrVar2.subtree >>>= 5;
            i5 = i8 + 1;
            bArr11 = bArr11;
        }
        zerobytes(bArr9, 0, 1088);
        return bArr3;
    }

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public byte[] generateSignature(byte[] bArr) {
        return crypto_sign(this.hashFunctions, bArr, this.keyData);
    }

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public void init(boolean z, CipherParameters cipherParameters) {
        if (!z) {
            this.keyData = ((SPHINCSPublicKeyParameters) cipherParameters).getKeyData();
        } else if (cipherParameters instanceof ParametersWithRandom) {
            this.keyData = ((SPHINCSPrivateKeyParameters) ((ParametersWithRandom) cipherParameters).getParameters()).getKeyData();
        } else {
            this.keyData = ((SPHINCSPrivateKeyParameters) cipherParameters).getKeyData();
        }
    }

    boolean verify(HashFunctions hashFunctions, byte[] bArr, byte[] bArr2, byte[] bArr3) {
        byte[] bArr4 = new byte[2144];
        byte[] bArr5 = new byte[32];
        byte[] bArr6 = new byte[32];
        byte[] bArr7 = new byte[41000];
        byte[] bArr8 = new byte[1056];
        if (bArr2.length == 41000) {
            byte[] bArr9 = new byte[64];
            for (int i = 0; i < 1056; i++) {
                bArr8[i] = bArr3[i];
            }
            byte[] bArr10 = new byte[32];
            for (int i2 = 0; i2 < 32; i2++) {
                bArr10[i2] = bArr2[i2];
            }
            System.arraycopy(bArr2, 0, bArr7, 0, 41000);
            Digest messageHash = hashFunctions.getMessageHash();
            messageHash.update(bArr10, 0, 32);
            messageHash.update(bArr8, 0, 1056);
            messageHash.update(bArr, 0, bArr.length);
            messageHash.doFinal(bArr9, 0);
            long j = 0;
            for (int i3 = 0; i3 < 8; i3++) {
                j ^= (bArr7[32 + i3] & UByte.MAX_VALUE) << (i3 * 8);
            }
            new Horst();
            Horst.horst_verify(hashFunctions, bArr6, bArr7, 40, bArr8, bArr9);
            Wots wots = new Wots();
            int i4 = 0;
            int i5 = 13352;
            while (i4 < 12) {
                int i6 = i5;
                wots.wots_verify(hashFunctions, bArr4, bArr7, i5, bArr6, bArr8);
                Tree.l_tree(hashFunctions, bArr5, 0, bArr4, 0, bArr8, 0);
                byte[] bArr11 = bArr8;
                byte[] bArr12 = bArr7;
                validate_authpath(hashFunctions, bArr6, bArr5, (int) (31 & j), bArr12, i6 + 2144, bArr11, 5);
                j >>= 5;
                i5 = i6 + 2304;
                i4++;
                bArr8 = bArr11;
                bArr7 = bArr12;
                bArr6 = bArr6;
                bArr5 = bArr5;
            }
            byte[] bArr13 = bArr8;
            byte[] bArr14 = bArr6;
            boolean z = true;
            for (int i7 = 0; i7 < 32; i7++) {
                z &= bArr14[i7] == bArr13[i7 + 1024];
            }
            return z;
        }
        throw new IllegalArgumentException("signature wrong size");
    }

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public boolean verifySignature(byte[] bArr, byte[] bArr2) {
        return verify(this.hashFunctions, bArr, bArr2, this.keyData);
    }
}