package org.bouncycastle.pqc.crypto.slhdsa;

/* loaded from: classes2.dex */
class NodeEntry {
    final int nodeHeight;
    final byte[] nodeValue;

    /* JADX INFO: Access modifiers changed from: package-private */
    public NodeEntry(byte[] bArr, int i) {
        this.nodeValue = bArr;
        this.nodeHeight = i;
    }
}