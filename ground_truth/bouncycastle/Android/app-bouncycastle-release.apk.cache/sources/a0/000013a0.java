package kotlin.enums;

import kotlin.Metadata;
import kotlin.jvm.functions.Functions;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: EnumEntries.kt */
@Metadata(m174d1 = {"\u0000\u001a\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0010\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0011\n\u0002\b\u0003\u001a2\u0010\u0000\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0001\"\u000e\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u00032\u0012\u0010\u0004\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u0002H\u00020\u00060\u0005H\u0001\u001a1\u0010\u0000\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0001\"\u000e\b\u0000\u0010\u0002*\b\u0012\u0004\u0012\u0002H\u00020\u00032\f\u0010\u0007\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0006H\u0001¢\u0006\u0002\u0010\b¨\u0006\t"}, m173d2 = {"enumEntries", "Lkotlin/enums/EnumEntries;", "E", "", "entriesProvider", "Lkotlin/Function0;", "", "entries", "([Ljava/lang/Enum;)Lkotlin/enums/EnumEntries;", "kotlin-stdlib"}, m172k = 2, m171mv = {1, 8, 0}, m169xi = 48)
/* loaded from: classes.dex */
public final class EnumEntriesKt {
    public static final <E extends Enum<E>> EnumEntries<E> enumEntries(Functions<E[]> entriesProvider) {
        Intrinsics.checkNotNullParameter(entriesProvider, "entriesProvider");
        return new EnumEntriesList(entriesProvider);
    }

    public static final <E extends Enum<E>> EnumEntries<E> enumEntries(final E[] entries) {
        Intrinsics.checkNotNullParameter(entries, "entries");
        EnumEntriesList enumEntriesList = new EnumEntriesList(new Functions<E[]>() { // from class: kotlin.enums.EnumEntriesKt$enumEntries$1
            /* JADX INFO: Access modifiers changed from: package-private */
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Incorrect types in method signature: ([TE;)V */
            {
                super(0);
            }

            /* JADX WARN: Incorrect return type in method signature: ()[TE; */
            @Override // kotlin.jvm.functions.Functions
            public final Enum[] invoke() {
                return entries;
            }
        });
        enumEntriesList.size();
        return enumEntriesList;
    }
}