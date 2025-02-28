package androidx.core.graphics;

import android.graphics.PointF;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata(m174d1 = {"\u0000\u0016\n\u0000\n\u0002\u0010\b\n\u0002\u0018\u0002\n\u0002\u0010\u0007\n\u0002\u0018\u0002\n\u0002\b\t\u001a\r\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\u0086\n\u001a\r\u0010\u0000\u001a\u00020\u0003*\u00020\u0004H\u0086\n\u001a\r\u0010\u0005\u001a\u00020\u0001*\u00020\u0002H\u0086\n\u001a\r\u0010\u0005\u001a\u00020\u0003*\u00020\u0004H\u0086\n\u001a\u0015\u0010\u0006\u001a\u00020\u0002*\u00020\u00022\u0006\u0010\u0007\u001a\u00020\u0002H\u0086\n\u001a\u0015\u0010\u0006\u001a\u00020\u0002*\u00020\u00022\u0006\u0010\b\u001a\u00020\u0001H\u0086\n\u001a\u0015\u0010\u0006\u001a\u00020\u0004*\u00020\u00042\u0006\u0010\u0007\u001a\u00020\u0004H\u0086\n\u001a\u0015\u0010\u0006\u001a\u00020\u0004*\u00020\u00042\u0006\u0010\b\u001a\u00020\u0003H\u0086\n\u001a\u0015\u0010\t\u001a\u00020\u0002*\u00020\u00022\u0006\u0010\u0007\u001a\u00020\u0002H\u0086\n\u001a\u0015\u0010\t\u001a\u00020\u0002*\u00020\u00022\u0006\u0010\b\u001a\u00020\u0001H\u0086\n\u001a\u0015\u0010\t\u001a\u00020\u0004*\u00020\u00042\u0006\u0010\u0007\u001a\u00020\u0004H\u0086\n\u001a\u0015\u0010\t\u001a\u00020\u0004*\u00020\u00042\u0006\u0010\b\u001a\u00020\u0003H\u0086\n\u001a\r\u0010\n\u001a\u00020\u0002*\u00020\u0004H\u0086\b\u001a\r\u0010\u000b\u001a\u00020\u0004*\u00020\u0002H\u0086\b\u001a\r\u0010\f\u001a\u00020\u0002*\u00020\u0002H\u0086\n\u001a\r\u0010\f\u001a\u00020\u0004*\u00020\u0004H\u0086\n¨\u0006\r"}, m173d2 = {"component1", "", "Landroid/graphics/Point;", "", "Landroid/graphics/PointF;", "component2", "minus", "p", "xy", "plus", "toPoint", "toPointF", "unaryMinus", "core-ktx_release"}, m172k = 2, m171mv = {1, 7, 1}, m169xi = 48)
/* renamed from: androidx.core.graphics.PointKt */
/* loaded from: classes.dex */
public final class Point {
    public static final int component1(android.graphics.Point point) {
        Intrinsics.checkNotNullParameter(point, "<this>");
        return point.x;
    }

    public static final int component2(android.graphics.Point point) {
        Intrinsics.checkNotNullParameter(point, "<this>");
        return point.y;
    }

    public static final float component1(PointF pointF) {
        Intrinsics.checkNotNullParameter(pointF, "<this>");
        return pointF.x;
    }

    public static final float component2(PointF pointF) {
        Intrinsics.checkNotNullParameter(pointF, "<this>");
        return pointF.y;
    }

    public static final android.graphics.Point plus(android.graphics.Point point, android.graphics.Point p) {
        Intrinsics.checkNotNullParameter(point, "<this>");
        Intrinsics.checkNotNullParameter(p, "p");
        android.graphics.Point point2 = new android.graphics.Point(point.x, point.y);
        point2.offset(p.x, p.y);
        return point2;
    }

    public static final PointF plus(PointF pointF, PointF p) {
        Intrinsics.checkNotNullParameter(pointF, "<this>");
        Intrinsics.checkNotNullParameter(p, "p");
        PointF pointF2 = new PointF(pointF.x, pointF.y);
        pointF2.offset(p.x, p.y);
        return pointF2;
    }

    public static final android.graphics.Point plus(android.graphics.Point point, int i) {
        Intrinsics.checkNotNullParameter(point, "<this>");
        android.graphics.Point point2 = new android.graphics.Point(point.x, point.y);
        point2.offset(i, i);
        return point2;
    }

    public static final PointF plus(PointF pointF, float f) {
        Intrinsics.checkNotNullParameter(pointF, "<this>");
        PointF pointF2 = new PointF(pointF.x, pointF.y);
        pointF2.offset(f, f);
        return pointF2;
    }

    public static final android.graphics.Point minus(android.graphics.Point point, android.graphics.Point p) {
        Intrinsics.checkNotNullParameter(point, "<this>");
        Intrinsics.checkNotNullParameter(p, "p");
        android.graphics.Point point2 = new android.graphics.Point(point.x, point.y);
        point2.offset(-p.x, -p.y);
        return point2;
    }

    public static final PointF minus(PointF pointF, PointF p) {
        Intrinsics.checkNotNullParameter(pointF, "<this>");
        Intrinsics.checkNotNullParameter(p, "p");
        PointF pointF2 = new PointF(pointF.x, pointF.y);
        pointF2.offset(-p.x, -p.y);
        return pointF2;
    }

    public static final android.graphics.Point minus(android.graphics.Point point, int i) {
        Intrinsics.checkNotNullParameter(point, "<this>");
        android.graphics.Point point2 = new android.graphics.Point(point.x, point.y);
        int i2 = -i;
        point2.offset(i2, i2);
        return point2;
    }

    public static final PointF minus(PointF pointF, float f) {
        Intrinsics.checkNotNullParameter(pointF, "<this>");
        PointF pointF2 = new PointF(pointF.x, pointF.y);
        float f2 = -f;
        pointF2.offset(f2, f2);
        return pointF2;
    }

    public static final android.graphics.Point unaryMinus(android.graphics.Point point) {
        Intrinsics.checkNotNullParameter(point, "<this>");
        return new android.graphics.Point(-point.x, -point.y);
    }

    public static final PointF unaryMinus(PointF pointF) {
        Intrinsics.checkNotNullParameter(pointF, "<this>");
        return new PointF(-pointF.x, -pointF.y);
    }

    public static final PointF toPointF(android.graphics.Point point) {
        Intrinsics.checkNotNullParameter(point, "<this>");
        return new PointF(point);
    }

    public static final android.graphics.Point toPoint(PointF pointF) {
        Intrinsics.checkNotNullParameter(pointF, "<this>");
        return new android.graphics.Point((int) pointF.x, (int) pointF.y);
    }
}