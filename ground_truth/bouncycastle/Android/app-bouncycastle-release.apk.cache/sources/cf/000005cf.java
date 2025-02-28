package androidx.core.graphics;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata(m174d1 = {"\u0000\u0016\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0007\n\u0002\b\u000b\n\u0002\u0010\u0014\n\u0000\u001a\"\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\b\b\u0002\u0010\u0004\u001a\u00020\u00032\b\b\u0002\u0010\u0005\u001a\u00020\u0003\u001a\u001a\u0010\u0006\u001a\u00020\u00012\b\b\u0002\u0010\u0007\u001a\u00020\u00032\b\b\u0002\u0010\b\u001a\u00020\u0003\u001a\u001a\u0010\t\u001a\u00020\u00012\b\b\u0002\u0010\n\u001a\u00020\u00032\b\b\u0002\u0010\u000b\u001a\u00020\u0003\u001a\u0015\u0010\f\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\r\u001a\u00020\u0001H\u0086\n\u001a\r\u0010\u000e\u001a\u00020\u000f*\u00020\u0001H\u0086\b¨\u0006\u0010"}, m173d2 = {"rotationMatrix", "Landroid/graphics/Matrix;", "degrees", "", "px", "py", "scaleMatrix", "sx", "sy", "translationMatrix", "tx", "ty", "times", "m", "values", "", "core-ktx_release"}, m172k = 2, m171mv = {1, 7, 1}, m169xi = 48)
/* renamed from: androidx.core.graphics.MatrixKt */
/* loaded from: classes.dex */
public final class Matrix {
    public static final android.graphics.Matrix times(android.graphics.Matrix matrix, android.graphics.Matrix m) {
        Intrinsics.checkNotNullParameter(matrix, "<this>");
        Intrinsics.checkNotNullParameter(m, "m");
        android.graphics.Matrix matrix2 = new android.graphics.Matrix(matrix);
        matrix2.preConcat(m);
        return matrix2;
    }

    public static final float[] values(android.graphics.Matrix matrix) {
        Intrinsics.checkNotNullParameter(matrix, "<this>");
        float[] fArr = new float[9];
        matrix.getValues(fArr);
        return fArr;
    }

    public static /* synthetic */ android.graphics.Matrix translationMatrix$default(float f, float f2, int i, Object obj) {
        if ((i & 1) != 0) {
            f = 0.0f;
        }
        if ((i & 2) != 0) {
            f2 = 0.0f;
        }
        return translationMatrix(f, f2);
    }

    public static final android.graphics.Matrix translationMatrix(float f, float f2) {
        android.graphics.Matrix matrix = new android.graphics.Matrix();
        matrix.setTranslate(f, f2);
        return matrix;
    }

    public static /* synthetic */ android.graphics.Matrix scaleMatrix$default(float f, float f2, int i, Object obj) {
        if ((i & 1) != 0) {
            f = 1.0f;
        }
        if ((i & 2) != 0) {
            f2 = 1.0f;
        }
        return scaleMatrix(f, f2);
    }

    public static final android.graphics.Matrix scaleMatrix(float f, float f2) {
        android.graphics.Matrix matrix = new android.graphics.Matrix();
        matrix.setScale(f, f2);
        return matrix;
    }

    public static /* synthetic */ android.graphics.Matrix rotationMatrix$default(float f, float f2, float f3, int i, Object obj) {
        if ((i & 2) != 0) {
            f2 = 0.0f;
        }
        if ((i & 4) != 0) {
            f3 = 0.0f;
        }
        return rotationMatrix(f, f2, f3);
    }

    public static final android.graphics.Matrix rotationMatrix(float f, float f2, float f3) {
        android.graphics.Matrix matrix = new android.graphics.Matrix();
        matrix.setRotate(f, f2, f3);
        return matrix;
    }
}