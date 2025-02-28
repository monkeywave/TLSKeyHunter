package androidx.core.util;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.ClosedRange;

@Metadata(m174d1 = {"\u0000\u0018\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000f\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0002\u001a7\u0010\u0000\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0001\"\u000e\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u0003*\b\u0012\u0004\u0012\u0002H\u00020\u00012\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0001H\u0087\f\u001a6\u0010\u0005\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0001\"\u000e\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u0003*\b\u0012\u0004\u0012\u0002H\u00020\u00012\u0006\u0010\u0006\u001a\u0002H\u0002H\u0087\n¢\u0006\u0002\u0010\u0007\u001a7\u0010\u0005\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0001\"\u000e\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u0003*\b\u0012\u0004\u0012\u0002H\u00020\u00012\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0001H\u0087\n\u001a0\u0010\b\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0001\"\u000e\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u0003*\u0002H\u00022\u0006\u0010\t\u001a\u0002H\u0002H\u0087\f¢\u0006\u0002\u0010\n\u001a(\u0010\u000b\u001a\b\u0012\u0004\u0012\u0002H\u00020\f\"\u000e\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u0003*\b\u0012\u0004\u0012\u0002H\u00020\u0001H\u0007\u001a(\u0010\r\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0001\"\u000e\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u0003*\b\u0012\u0004\u0012\u0002H\u00020\fH\u0007¨\u0006\u000e"}, m173d2 = {"and", "Landroid/util/Range;", "T", "", "other", "plus", "value", "(Landroid/util/Range;Ljava/lang/Comparable;)Landroid/util/Range;", "rangeTo", "that", "(Ljava/lang/Comparable;Ljava/lang/Comparable;)Landroid/util/Range;", "toClosedRange", "Lkotlin/ranges/ClosedRange;", "toRange", "core-ktx_release"}, m172k = 2, m171mv = {1, 7, 1}, m169xi = 48)
/* renamed from: androidx.core.util.RangeKt */
/* loaded from: classes.dex */
public final class Range {
    public static final <T extends Comparable<? super T>> android.util.Range<T> rangeTo(T t, T that) {
        Intrinsics.checkNotNullParameter(t, "<this>");
        Intrinsics.checkNotNullParameter(that, "that");
        return new android.util.Range<>(t, that);
    }

    public static final <T extends Comparable<? super T>> android.util.Range<T> plus(android.util.Range<T> range, T value) {
        Intrinsics.checkNotNullParameter(range, "<this>");
        Intrinsics.checkNotNullParameter(value, "value");
        android.util.Range<T> extend = range.extend((android.util.Range<T>) value);
        Intrinsics.checkNotNullExpressionValue(extend, "extend(value)");
        return extend;
    }

    public static final <T extends Comparable<? super T>> android.util.Range<T> plus(android.util.Range<T> range, android.util.Range<T> other) {
        Intrinsics.checkNotNullParameter(range, "<this>");
        Intrinsics.checkNotNullParameter(other, "other");
        android.util.Range<T> extend = range.extend(other);
        Intrinsics.checkNotNullExpressionValue(extend, "extend(other)");
        return extend;
    }

    public static final <T extends Comparable<? super T>> android.util.Range<T> and(android.util.Range<T> range, android.util.Range<T> other) {
        Intrinsics.checkNotNullParameter(range, "<this>");
        Intrinsics.checkNotNullParameter(other, "other");
        android.util.Range<T> intersect = range.intersect(other);
        Intrinsics.checkNotNullExpressionValue(intersect, "intersect(other)");
        return intersect;
    }

    public static final <T extends Comparable<? super T>> ClosedRange<T> toClosedRange(final android.util.Range<T> range) {
        Intrinsics.checkNotNullParameter(range, "<this>");
        return (ClosedRange) new ClosedRange<T>() { // from class: androidx.core.util.RangeKt$toClosedRange$1
            /* JADX WARN: Incorrect types in method signature: (TT;)Z */
            @Override // kotlin.ranges.ClosedRange
            public boolean contains(Comparable comparable) {
                return ClosedRange.DefaultImpls.contains(this, comparable);
            }

            @Override // kotlin.ranges.ClosedRange
            public boolean isEmpty() {
                return ClosedRange.DefaultImpls.isEmpty(this);
            }

            /* JADX WARN: Incorrect return type in method signature: ()TT; */
            /* JADX WARN: Type inference failed for: r0v1, types: [java.lang.Comparable] */
            @Override // kotlin.ranges.ClosedRange
            public Comparable getEndInclusive() {
                return range.getUpper();
            }

            /* JADX WARN: Incorrect return type in method signature: ()TT; */
            /* JADX WARN: Type inference failed for: r0v1, types: [java.lang.Comparable] */
            @Override // kotlin.ranges.ClosedRange
            public Comparable getStart() {
                return range.getLower();
            }
        };
    }

    public static final <T extends Comparable<? super T>> android.util.Range<T> toRange(ClosedRange<T> closedRange) {
        Intrinsics.checkNotNullParameter(closedRange, "<this>");
        return new android.util.Range<>(closedRange.getStart(), closedRange.getEndInclusive());
    }
}