package org.bouncycastle.pqc.legacy.math.linearalgebra;

/* loaded from: classes2.dex */
public abstract class GF2nElement implements GFElement {
    protected int mDegree;
    protected GF2nField mField;

    abstract void assignOne();

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract void assignZero();

    @Override // org.bouncycastle.pqc.legacy.math.linearalgebra.GFElement
    public abstract Object clone();

    public final GF2nElement convert(GF2nField gF2nField) {
        return this.mField.convert(this, gF2nField);
    }

    public final GF2nField getField() {
        return this.mField;
    }

    public abstract GF2nElement increase();

    public abstract void increaseThis();

    public abstract GF2nElement solveQuadraticEquation() throws RuntimeException;

    public abstract GF2nElement square();

    public abstract GF2nElement squareRoot();

    public abstract void squareRootThis();

    public abstract void squareThis();

    @Override // org.bouncycastle.pqc.legacy.math.linearalgebra.GFElement
    public final GFElement subtract(GFElement gFElement) {
        return add(gFElement);
    }

    @Override // org.bouncycastle.pqc.legacy.math.linearalgebra.GFElement
    public final void subtractFromThis(GFElement gFElement) {
        addToThis(gFElement);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract boolean testBit(int i);

    public abstract boolean testRightmostBit();

    public abstract int trace();
}