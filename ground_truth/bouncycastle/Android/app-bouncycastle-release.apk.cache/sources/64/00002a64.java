package org.bouncycastle.pqc.crypto.picnic;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class View {
    final byte[] communicatedBits;
    final int[] inputShare;
    final int[] outputShare;

    public View(PicnicEngine picnicEngine) {
        this.inputShare = new int[picnicEngine.stateSizeWords];
        this.communicatedBits = new byte[picnicEngine.andSizeBytes];
        this.outputShare = new int[picnicEngine.stateSizeWords];
    }
}