package androidx.activity;

import androidx.lifecycle.LifecycleOwner;
import kotlin.Metadata;

/* compiled from: OnBackPressedDispatcherOwner.kt */
@Metadata(m174d1 = {"\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\bf\u0018\u00002\u00020\u0001R\u0012\u0010\u0002\u001a\u00020\u0003X¦\u0004¢\u0006\u0006\u001a\u0004\b\u0004\u0010\u0005ø\u0001\u0000\u0082\u0002\u0006\n\u0004\b!0\u0001¨\u0006\u0006À\u0006\u0001"}, m173d2 = {"Landroidx/activity/OnBackPressedDispatcherOwner;", "Landroidx/lifecycle/LifecycleOwner;", "onBackPressedDispatcher", "Landroidx/activity/OnBackPressedDispatcher;", "getOnBackPressedDispatcher", "()Landroidx/activity/OnBackPressedDispatcher;", "activity_release"}, m172k = 1, m171mv = {1, 8, 0}, m169xi = 48)
/* loaded from: classes.dex */
public interface OnBackPressedDispatcherOwner extends LifecycleOwner {
    OnBackPressedDispatcher getOnBackPressedDispatcher();
}