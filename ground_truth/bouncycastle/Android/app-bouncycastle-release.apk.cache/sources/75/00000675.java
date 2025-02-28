package androidx.core.p003os;

import android.os.LocaleList;
import java.util.Locale;

/* renamed from: androidx.core.os.LocaleListPlatformWrapper */
/* loaded from: classes.dex */
final class LocaleListPlatformWrapper implements LocaleListInterface {
    private final LocaleList mLocaleList;

    /* JADX INFO: Access modifiers changed from: package-private */
    public LocaleListPlatformWrapper(Object obj) {
        this.mLocaleList = (LocaleList) obj;
    }

    @Override // androidx.core.p003os.LocaleListInterface
    public Object getLocaleList() {
        return this.mLocaleList;
    }

    @Override // androidx.core.p003os.LocaleListInterface
    public Locale get(int i) {
        return this.mLocaleList.get(i);
    }

    @Override // androidx.core.p003os.LocaleListInterface
    public boolean isEmpty() {
        return this.mLocaleList.isEmpty();
    }

    @Override // androidx.core.p003os.LocaleListInterface
    public int size() {
        return this.mLocaleList.size();
    }

    @Override // androidx.core.p003os.LocaleListInterface
    public int indexOf(Locale locale) {
        return this.mLocaleList.indexOf(locale);
    }

    public boolean equals(Object obj) {
        return this.mLocaleList.equals(((LocaleListInterface) obj).getLocaleList());
    }

    public int hashCode() {
        return this.mLocaleList.hashCode();
    }

    public String toString() {
        return this.mLocaleList.toString();
    }

    @Override // androidx.core.p003os.LocaleListInterface
    public String toLanguageTags() {
        return this.mLocaleList.toLanguageTags();
    }

    @Override // androidx.core.p003os.LocaleListInterface
    public Locale getFirstMatch(String[] strArr) {
        return this.mLocaleList.getFirstMatch(strArr);
    }
}