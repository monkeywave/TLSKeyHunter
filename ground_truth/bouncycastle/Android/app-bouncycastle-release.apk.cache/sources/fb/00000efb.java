package com.google.android.material.color.utilities;

/* loaded from: classes.dex */
public final class ViewingConditions {
    public static final ViewingConditions DEFAULT = defaultWithBackgroundLstar(50.0d);

    /* renamed from: aw */
    private final double f193aw;

    /* renamed from: c */
    private final double f194c;

    /* renamed from: fl */
    private final double f195fl;
    private final double flRoot;

    /* renamed from: n */
    private final double f196n;
    private final double nbb;

    /* renamed from: nc */
    private final double f197nc;
    private final double ncb;
    private final double[] rgbD;

    /* renamed from: z */
    private final double f198z;

    public double getAw() {
        return this.f193aw;
    }

    public double getN() {
        return this.f196n;
    }

    public double getNbb() {
        return this.nbb;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public double getNcb() {
        return this.ncb;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public double getC() {
        return this.f194c;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public double getNc() {
        return this.f197nc;
    }

    public double[] getRgbD() {
        return this.rgbD;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public double getFl() {
        return this.f195fl;
    }

    public double getFlRoot() {
        return this.flRoot;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public double getZ() {
        return this.f198z;
    }

    public static ViewingConditions make(double[] dArr, double d, double d2, double d3, boolean z) {
        double lerp;
        double max = Math.max(0.1d, d2);
        double[][] dArr2 = Cam16.XYZ_TO_CAM16RGB;
        double d4 = dArr[0];
        double[] dArr3 = dArr2[0];
        double d5 = dArr[1];
        double d6 = dArr[2];
        double d7 = (dArr3[0] * d4) + (dArr3[1] * d5) + (dArr3[2] * d6);
        double[] dArr4 = dArr2[1];
        double d8 = (dArr4[0] * d4) + (dArr4[1] * d5) + (dArr4[2] * d6);
        double[] dArr5 = dArr2[2];
        double d9 = (d4 * dArr5[0]) + (d5 * dArr5[1]) + (d6 * dArr5[2]);
        double d10 = (d3 / 10.0d) + 0.8d;
        if (d10 >= 0.9d) {
            lerp = MathUtils.lerp(0.59d, 0.69d, (d10 - 0.9d) * 10.0d);
        } else {
            lerp = MathUtils.lerp(0.525d, 0.59d, (d10 - 0.8d) * 10.0d);
        }
        double d11 = lerp;
        double clampDouble = MathUtils.clampDouble(0.0d, 1.0d, z ? 1.0d : (1.0d - (Math.exp(((-d) - 42.0d) / 92.0d) * 0.2777777777777778d)) * d10);
        double[] dArr6 = {(((100.0d / d7) * clampDouble) + 1.0d) - clampDouble, (((100.0d / d8) * clampDouble) + 1.0d) - clampDouble, (((100.0d / d9) * clampDouble) + 1.0d) - clampDouble};
        double d12 = 5.0d * d;
        double d13 = 1.0d / (d12 + 1.0d);
        double d14 = d13 * d13 * d13 * d13;
        double d15 = 1.0d - d14;
        double cbrt = (d14 * d) + (0.1d * d15 * d15 * Math.cbrt(d12));
        double yFromLstar = ColorUtils.yFromLstar(max) / dArr[1];
        double sqrt = Math.sqrt(yFromLstar) + 1.48d;
        double pow = 0.725d / Math.pow(yFromLstar, 0.2d);
        double[] dArr7 = {Math.pow(((dArr6[0] * cbrt) * d7) / 100.0d, 0.42d), Math.pow(((dArr6[1] * cbrt) * d8) / 100.0d, 0.42d), Math.pow(((dArr6[2] * cbrt) * d9) / 100.0d, 0.42d)};
        double d16 = dArr7[0];
        double d17 = (d16 * 400.0d) / (d16 + 27.13d);
        double d18 = dArr7[1];
        double d19 = (d18 * 400.0d) / (d18 + 27.13d);
        double d20 = dArr7[2];
        double[] dArr8 = {d17, d19, (400.0d * d20) / (d20 + 27.13d)};
        return new ViewingConditions(yFromLstar, ((dArr8[0] * 2.0d) + dArr8[1] + (dArr8[2] * 0.05d)) * pow, pow, pow, d11, d10, dArr6, cbrt, Math.pow(cbrt, 0.25d), sqrt);
    }

    public static ViewingConditions defaultWithBackgroundLstar(double d) {
        return make(ColorUtils.whitePointD65(), (ColorUtils.yFromLstar(50.0d) * 63.66197723675813d) / 100.0d, d, 2.0d, false);
    }

    private ViewingConditions(double d, double d2, double d3, double d4, double d5, double d6, double[] dArr, double d7, double d8, double d9) {
        this.f196n = d;
        this.f193aw = d2;
        this.nbb = d3;
        this.ncb = d4;
        this.f194c = d5;
        this.f197nc = d6;
        this.rgbD = dArr;
        this.f195fl = d7;
        this.flRoot = d8;
        this.f198z = d9;
    }
}