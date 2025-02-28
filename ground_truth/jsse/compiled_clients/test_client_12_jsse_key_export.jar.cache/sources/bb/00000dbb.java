package org.bouncycastle.pqc.crypto.sphincs;

import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.pqc.crypto.sphincs.Tree;
import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/sphincs/Seed.class */
class Seed {
    Seed() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void get_seed(HashFunctions hashFunctions, byte[] bArr, int i, byte[] bArr2, Tree.leafaddr leafaddrVar) {
        byte[] bArr3 = new byte[40];
        for (int i2 = 0; i2 < 32; i2++) {
            bArr3[i2] = bArr2[i2];
        }
        Pack.longToLittleEndian(leafaddrVar.level | (leafaddrVar.subtree << 4) | (leafaddrVar.subleaf << 59), bArr3, 32);
        hashFunctions.varlen_hash(bArr, i, bArr3, bArr3.length);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void prg(byte[] bArr, int i, long j, byte[] bArr2, int i2) {
        ChaChaEngine chaChaEngine = new ChaChaEngine(12);
        chaChaEngine.init(true, new ParametersWithIV(new KeyParameter(bArr2, i2, 32), new byte[8]));
        chaChaEngine.processBytes(bArr, i, (int) j, bArr, i);
    }
}