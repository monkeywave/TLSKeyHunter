package org.bouncycastle.pqc.crypto.picnic;

import java.lang.reflect.Array;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class Msg {
    byte[][] msgs;
    int pos = 0;
    int unopened = -1;

    public Msg(PicnicEngine picnicEngine) {
        this.msgs = (byte[][]) Array.newInstance(Byte.TYPE, picnicEngine.numMPCParties, picnicEngine.andSizeBytes);
    }
}