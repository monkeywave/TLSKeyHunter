package androidx.core.content.p002pm;

import java.util.ArrayList;
import java.util.List;

/* renamed from: androidx.core.content.pm.ShortcutInfoCompatSaver */
/* loaded from: classes.dex */
public abstract class ShortcutInfoCompatSaver<T> {
    public abstract T addShortcuts(List<ShortcutInfoCompat> list);

    public abstract T removeAllShortcuts();

    public abstract T removeShortcuts(List<String> list);

    public List<ShortcutInfoCompat> getShortcuts() throws Exception {
        return new ArrayList();
    }

    /* renamed from: androidx.core.content.pm.ShortcutInfoCompatSaver$NoopImpl */
    /* loaded from: classes.dex */
    public static class NoopImpl extends ShortcutInfoCompatSaver<Void> {
        @Override // androidx.core.content.p002pm.ShortcutInfoCompatSaver
        /* renamed from: addShortcuts  reason: avoid collision after fix types in other method */
        public Void addShortcuts2(List<ShortcutInfoCompat> list) {
            return null;
        }

        @Override // androidx.core.content.p002pm.ShortcutInfoCompatSaver
        public Void removeAllShortcuts() {
            return null;
        }

        @Override // androidx.core.content.p002pm.ShortcutInfoCompatSaver
        /* renamed from: removeShortcuts  reason: avoid collision after fix types in other method */
        public Void removeShortcuts2(List<String> list) {
            return null;
        }

        @Override // androidx.core.content.p002pm.ShortcutInfoCompatSaver
        public /* bridge */ /* synthetic */ Void addShortcuts(List list) {
            return addShortcuts2((List<ShortcutInfoCompat>) list);
        }

        @Override // androidx.core.content.p002pm.ShortcutInfoCompatSaver
        public /* bridge */ /* synthetic */ Void removeShortcuts(List list) {
            return removeShortcuts2((List<String>) list);
        }
    }
}