package org.bouncycastle.pqc.crypto.sphincsplus;

/* loaded from: classes2.dex */
class IndexedDigest {
    final byte[] digest;
    final int idx_leaf;
    final long idx_tree;

    /* JADX INFO: Access modifiers changed from: package-private */
    public IndexedDigest(long j, int i, byte[] bArr) {
        this.idx_tree = j;
        this.idx_leaf = i;
        this.digest = bArr;
    }
}