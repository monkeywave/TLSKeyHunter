package androidx.core.graphics;

import android.graphics.Point;
import android.graphics.Rect;
import android.graphics.Region;
import android.graphics.RegionIterator;
import java.util.Iterator;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

@Metadata(m174d1 = {"\u00004\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010(\n\u0002\b\u0007\u001a\u0015\u0010\u0000\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0003H\u0086\f\u001a\u0015\u0010\u0000\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0001H\u0086\f\u001a\u0015\u0010\u0004\u001a\u00020\u0005*\u00020\u00012\u0006\u0010\u0006\u001a\u00020\u0007H\u0086\n\u001a3\u0010\b\u001a\u00020\t*\u00020\u00012!\u0010\n\u001a\u001d\u0012\u0013\u0012\u00110\u0003¢\u0006\f\b\f\u0012\b\b\r\u0012\u0004\b\b(\u000e\u0012\u0004\u0012\u00020\t0\u000bH\u0086\bø\u0001\u0000\u001a\u0013\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\u00030\u0010*\u00020\u0001H\u0086\u0002\u001a\u0015\u0010\u0011\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0003H\u0086\n\u001a\u0015\u0010\u0011\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0001H\u0086\n\u001a\r\u0010\u0012\u001a\u00020\u0001*\u00020\u0001H\u0086\n\u001a\u0015\u0010\u0013\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0003H\u0086\f\u001a\u0015\u0010\u0013\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0001H\u0086\f\u001a\u0015\u0010\u0014\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0003H\u0086\n\u001a\u0015\u0010\u0014\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0001H\u0086\n\u001a\r\u0010\u0015\u001a\u00020\u0001*\u00020\u0001H\u0086\n\u001a\u0015\u0010\u0016\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0003H\u0086\f\u001a\u0015\u0010\u0016\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0001H\u0086\f\u0082\u0002\u0007\n\u0005\b\u009920\u0001¨\u0006\u0017"}, m173d2 = {"and", "Landroid/graphics/Region;", "r", "Landroid/graphics/Rect;", "contains", "", "p", "Landroid/graphics/Point;", "forEach", "", "action", "Lkotlin/Function1;", "Lkotlin/ParameterName;", "name", "rect", "iterator", "", "minus", "not", "or", "plus", "unaryMinus", "xor", "core-ktx_release"}, m172k = 2, m171mv = {1, 7, 1}, m169xi = 48)
/* renamed from: androidx.core.graphics.RegionKt */
/* loaded from: classes.dex */
public final class Region {
    public static final boolean contains(android.graphics.Region region, Point p) {
        Intrinsics.checkNotNullParameter(region, "<this>");
        Intrinsics.checkNotNullParameter(p, "p");
        return region.contains(p.x, p.y);
    }

    public static final android.graphics.Region plus(android.graphics.Region region, Rect r) {
        Intrinsics.checkNotNullParameter(region, "<this>");
        Intrinsics.checkNotNullParameter(r, "r");
        android.graphics.Region region2 = new android.graphics.Region(region);
        region2.union(r);
        return region2;
    }

    public static final android.graphics.Region plus(android.graphics.Region region, android.graphics.Region r) {
        Intrinsics.checkNotNullParameter(region, "<this>");
        Intrinsics.checkNotNullParameter(r, "r");
        android.graphics.Region region2 = new android.graphics.Region(region);
        region2.op(r, Region.Op.UNION);
        return region2;
    }

    public static final android.graphics.Region minus(android.graphics.Region region, Rect r) {
        Intrinsics.checkNotNullParameter(region, "<this>");
        Intrinsics.checkNotNullParameter(r, "r");
        android.graphics.Region region2 = new android.graphics.Region(region);
        region2.op(r, Region.Op.DIFFERENCE);
        return region2;
    }

    public static final android.graphics.Region minus(android.graphics.Region region, android.graphics.Region r) {
        Intrinsics.checkNotNullParameter(region, "<this>");
        Intrinsics.checkNotNullParameter(r, "r");
        android.graphics.Region region2 = new android.graphics.Region(region);
        region2.op(r, Region.Op.DIFFERENCE);
        return region2;
    }

    public static final android.graphics.Region unaryMinus(android.graphics.Region region) {
        Intrinsics.checkNotNullParameter(region, "<this>");
        android.graphics.Region region2 = new android.graphics.Region(region.getBounds());
        region2.op(region, Region.Op.DIFFERENCE);
        return region2;
    }

    public static final android.graphics.Region and(android.graphics.Region region, Rect r) {
        Intrinsics.checkNotNullParameter(region, "<this>");
        Intrinsics.checkNotNullParameter(r, "r");
        android.graphics.Region region2 = new android.graphics.Region(region);
        region2.op(r, Region.Op.INTERSECT);
        return region2;
    }

    public static final android.graphics.Region and(android.graphics.Region region, android.graphics.Region r) {
        Intrinsics.checkNotNullParameter(region, "<this>");
        Intrinsics.checkNotNullParameter(r, "r");
        android.graphics.Region region2 = new android.graphics.Region(region);
        region2.op(r, Region.Op.INTERSECT);
        return region2;
    }

    public static final android.graphics.Region xor(android.graphics.Region region, Rect r) {
        Intrinsics.checkNotNullParameter(region, "<this>");
        Intrinsics.checkNotNullParameter(r, "r");
        android.graphics.Region region2 = new android.graphics.Region(region);
        region2.op(r, Region.Op.XOR);
        return region2;
    }

    public static final android.graphics.Region xor(android.graphics.Region region, android.graphics.Region r) {
        Intrinsics.checkNotNullParameter(region, "<this>");
        Intrinsics.checkNotNullParameter(r, "r");
        android.graphics.Region region2 = new android.graphics.Region(region);
        region2.op(r, Region.Op.XOR);
        return region2;
    }

    public static final void forEach(android.graphics.Region region, Function1<? super Rect, Unit> action) {
        Intrinsics.checkNotNullParameter(region, "<this>");
        Intrinsics.checkNotNullParameter(action, "action");
        RegionIterator regionIterator = new RegionIterator(region);
        while (true) {
            Rect rect = new Rect();
            if (!regionIterator.next(rect)) {
                return;
            }
            action.invoke(rect);
        }
    }

    public static final Iterator<Rect> iterator(android.graphics.Region region) {
        Intrinsics.checkNotNullParameter(region, "<this>");
        return new RegionKt$iterator$1(region);
    }

    public static final android.graphics.Region not(android.graphics.Region region) {
        Intrinsics.checkNotNullParameter(region, "<this>");
        android.graphics.Region region2 = new android.graphics.Region(region.getBounds());
        region2.op(region, Region.Op.DIFFERENCE);
        return region2;
    }

    /* renamed from: or */
    public static final android.graphics.Region m284or(android.graphics.Region region, Rect r) {
        Intrinsics.checkNotNullParameter(region, "<this>");
        Intrinsics.checkNotNullParameter(r, "r");
        android.graphics.Region region2 = new android.graphics.Region(region);
        region2.union(r);
        return region2;
    }

    /* renamed from: or */
    public static final android.graphics.Region m283or(android.graphics.Region region, android.graphics.Region r) {
        Intrinsics.checkNotNullParameter(region, "<this>");
        Intrinsics.checkNotNullParameter(r, "r");
        android.graphics.Region region2 = new android.graphics.Region(region);
        region2.op(r, Region.Op.UNION);
        return region2;
    }
}