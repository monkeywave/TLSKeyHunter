package org.bouncycastle.pqc.crypto.qtesla;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/qtesla/IntSlicer.class */
final class IntSlicer {
    private final int[] values;
    private int base;

    IntSlicer(int[] iArr, int i) {
        this.values = iArr;
        this.base = i;
    }

    /* renamed from: at */
    final int m11at(int i) {
        return this.values[this.base + i];
    }

    /* renamed from: at */
    final int m10at(int i, int i2) {
        this.values[this.base + i] = i2;
        return i2;
    }

    /* renamed from: at */
    final int m9at(int i, long j) {
        int i2 = (int) j;
        this.values[this.base + i] = i2;
        return i2;
    }

    final IntSlicer from(int i) {
        return new IntSlicer(this.values, this.base + i);
    }

    final void incBase(int i) {
        this.base += i;
    }

    final IntSlicer copy() {
        return new IntSlicer(this.values, this.base);
    }
}