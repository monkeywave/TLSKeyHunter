package kotlin.collections;

import java.util.Iterator;
import kotlin.Metadata;
import kotlin.jvm.internal.ArrayIteratorsKt;
import kotlin.jvm.internal.markers.KMarkers;

/* compiled from: Iterables.kt */
@Metadata(m174d1 = {"\u0000\u0011\n\u0000\n\u0002\u0010\u001c\n\u0000\n\u0002\u0010(\n\u0000*\u0001\u0000\b\n\u0018\u00002\b\u0012\u0004\u0012\u00028\u00000\u0001J\u000f\u0010\u0002\u001a\b\u0012\u0004\u0012\u00028\u00000\u0003H\u0096\u0002¨\u0006\u0004¸\u0006\u0000"}, m173d2 = {"kotlin/collections/CollectionsKt__IterablesKt$Iterable$1", "", "iterator", "", "kotlin-stdlib"}, m172k = 1, m171mv = {1, 8, 0}, m169xi = 48)
/* loaded from: classes.dex */
public final class ArraysKt___ArraysKt$asIterable$$inlined$Iterable$7 implements Iterable<Double>, KMarkers {
    final /* synthetic */ double[] $this_asIterable$inlined;

    public ArraysKt___ArraysKt$asIterable$$inlined$Iterable$7(double[] dArr) {
        this.$this_asIterable$inlined = dArr;
    }

    @Override // java.lang.Iterable
    public Iterator<Double> iterator() {
        return ArrayIteratorsKt.iterator(this.$this_asIterable$inlined);
    }
}