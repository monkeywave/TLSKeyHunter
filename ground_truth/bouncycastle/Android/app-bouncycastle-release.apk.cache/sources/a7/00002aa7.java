package org.bouncycastle.pqc.crypto.sphincs;

/* loaded from: classes2.dex */
class Tree {

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes2.dex */
    public static class leafaddr {
        int level;
        long subleaf;
        long subtree;

        public leafaddr() {
        }

        public leafaddr(leafaddr leafaddrVar) {
            this.level = leafaddrVar.level;
            this.subtree = leafaddrVar.subtree;
            this.subleaf = leafaddrVar.subleaf;
        }
    }

    Tree() {
    }

    static void gen_leaf_wots(HashFunctions hashFunctions, byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, leafaddr leafaddrVar) {
        byte[] bArr4 = new byte[32];
        byte[] bArr5 = new byte[2144];
        Wots wots = new Wots();
        Seed.get_seed(hashFunctions, bArr4, 0, bArr3, leafaddrVar);
        wots.wots_pkgen(hashFunctions, bArr5, 0, bArr4, 0, bArr2, i2);
        l_tree(hashFunctions, bArr, i, bArr5, 0, bArr2, i2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void l_tree(HashFunctions hashFunctions, byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, int i3) {
        int i4;
        int i5 = 67;
        for (int i6 = 0; i6 < 7; i6++) {
            int i7 = 0;
            while (true) {
                i4 = i5 >>> 1;
                if (i7 >= i4) {
                    break;
                }
                hashFunctions.hash_2n_n_mask(bArr2, i2 + (i7 * 32), bArr2, i2 + (i7 * 64), bArr3, i3 + (i6 * 64));
                i7++;
            }
            if ((i5 & 1) != 0) {
                System.arraycopy(bArr2, i2 + ((i5 - 1) * 32), bArr2, (i4 * 32) + i2, 32);
                i4++;
            }
            i5 = i4;
        }
        System.arraycopy(bArr2, i2, bArr, i, 32);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void treehash(HashFunctions hashFunctions, byte[] bArr, int i, int i2, byte[] bArr2, leafaddr leafaddrVar, byte[] bArr3, int i3) {
        leafaddr leafaddrVar2 = new leafaddr(leafaddrVar);
        int i4 = i2 + 1;
        byte[] bArr4 = new byte[i4 * 32];
        int[] iArr = new int[i4];
        int i5 = 1;
        int i6 = (int) (leafaddrVar2.subleaf + (1 << i2));
        int i7 = 0;
        while (leafaddrVar2.subleaf < i6) {
            gen_leaf_wots(hashFunctions, bArr4, i7 * 32, bArr3, i3, bArr2, leafaddrVar2);
            iArr[i7] = 0;
            int i8 = i7 + i5;
            while (i8 > i5) {
                int i9 = iArr[i8 - 1];
                int i10 = i8 - 2;
                if (i9 == iArr[i10]) {
                    int i11 = i10 * 32;
                    int i12 = i5;
                    int[] iArr2 = iArr;
                    hashFunctions.hash_2n_n_mask(bArr4, i11, bArr4, i11, bArr3, i3 + ((i9 + 7) * 64));
                    iArr2[i10] = iArr2[i10] + i12;
                    i8--;
                    i5 = i12;
                    i6 = i6;
                    iArr = iArr2;
                }
            }
            leafaddrVar2.subleaf++;
            i7 = i8;
            i5 = i5;
            i6 = i6;
            iArr = iArr;
        }
        for (int i13 = 0; i13 < 32; i13++) {
            bArr[i + i13] = bArr4[i13];
        }
    }
}