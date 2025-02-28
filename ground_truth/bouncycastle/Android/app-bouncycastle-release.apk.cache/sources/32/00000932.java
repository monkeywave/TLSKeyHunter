package androidx.emoji2.text.flatbuffer;

import java.nio.ByteBuffer;

/* loaded from: classes.dex */
public class Struct {

    /* renamed from: bb */
    protected ByteBuffer f87bb;
    protected int bb_pos;

    protected void __reset(int i, ByteBuffer byteBuffer) {
        this.f87bb = byteBuffer;
        if (byteBuffer != null) {
            this.bb_pos = i;
        } else {
            this.bb_pos = 0;
        }
    }

    public void __reset() {
        __reset(0, null);
    }
}