package org.bouncycastle.pqc.crypto.sphincsplus;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/sphincsplus/IndexedDigest.class */
class IndexedDigest {
    final long idx_tree;
    final int idx_leaf;
    final byte[] digest;

    /* JADX INFO: Access modifiers changed from: package-private */
    public IndexedDigest(long j, int i, byte[] bArr) {
        this.idx_tree = j;
        this.idx_leaf = i;
        this.digest = bArr;
    }
}