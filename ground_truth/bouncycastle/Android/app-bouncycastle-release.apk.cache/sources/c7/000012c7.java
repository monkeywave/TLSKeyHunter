package kotlin.collections;

import java.util.Iterator;
import kotlin.Metadata;
import kotlin.jvm.internal.ArrayIteratorKt;
import kotlin.jvm.internal.markers.KMarkers;

/* JADX INFO: Add missing generic type declarations: [T] */
@Metadata(m174d1 = {"\u0000\u0011\n\u0000\n\u0002\u0010\u001c\n\u0000\n\u0002\u0010(\n\u0000*\u0001\u0000\b\n\u0018\u00002\b\u0012\u0004\u0012\u00028\u00000\u0001J\u000f\u0010\u0002\u001a\b\u0012\u0004\u0012\u00028\u00000\u0003H\u0096\u0002¨\u0006\u0004¸\u0006\u0000"}, m173d2 = {"kotlin/collections/CollectionsKt__IterablesKt$Iterable$1", "", "iterator", "", "kotlin-stdlib"}, m172k = 1, m171mv = {1, 8, 0}, m169xi = 48)
/* renamed from: kotlin.collections.ArraysKt___ArraysKt$asIterable$$inlined$Iterable$1 */
/* loaded from: classes.dex */
public final class Iterables<T> implements Iterable<T>, KMarkers {
    final /* synthetic */ Object[] $this_asIterable$inlined;

    public Iterables(Object[] objArr) {
        this.$this_asIterable$inlined = objArr;
    }

    @Override // java.lang.Iterable
    public Iterator<T> iterator() {
        return ArrayIteratorKt.iterator(this.$this_asIterable$inlined);
    }
}