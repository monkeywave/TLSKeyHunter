package androidx.lifecycle;

import android.os.Bundle;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.viewmodel.CreationExtras;
import androidx.savedstate.SavedStateRegistry;
import androidx.savedstate.SavedStateRegistryOwner;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: AbstractSavedStateViewModelFactory.kt */
@Metadata(m174d1 = {"\u0000Z\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\b&\u0018\u0000 \u001f2\u00020\u00012\u00020\u0002:\u0001\u001fB\u0007\b\u0016¢\u0006\u0002\u0010\u0003B\u0019\b\u0016\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\b\u0010\u0006\u001a\u0004\u0018\u00010\u0007¢\u0006\u0002\u0010\bJ%\u0010\r\u001a\u0002H\u000e\"\b\b\u0000\u0010\u000e*\u00020\u000f2\f\u0010\u0010\u001a\b\u0012\u0004\u0012\u0002H\u000e0\u0011H\u0016¢\u0006\u0002\u0010\u0012J-\u0010\r\u001a\u0002H\u000e\"\b\b\u0000\u0010\u000e*\u00020\u000f2\f\u0010\u0010\u001a\b\u0012\u0004\u0012\u0002H\u000e0\u00112\u0006\u0010\u0013\u001a\u00020\u0014H\u0016¢\u0006\u0002\u0010\u0015J-\u0010\r\u001a\u0002H\u000e\"\b\b\u0000\u0010\u000e*\u00020\u000f2\u0006\u0010\u0016\u001a\u00020\u00172\f\u0010\u0010\u001a\b\u0012\u0004\u0012\u0002H\u000e0\u0011H\u0002¢\u0006\u0002\u0010\u0018J5\u0010\r\u001a\u0002H\u000e\"\b\b\u0000\u0010\u000e*\u00020\u000f2\u0006\u0010\u0016\u001a\u00020\u00172\f\u0010\u0010\u001a\b\u0012\u0004\u0012\u0002H\u000e0\u00112\u0006\u0010\u0019\u001a\u00020\u001aH$¢\u0006\u0002\u0010\u001bJ\u0010\u0010\u001c\u001a\u00020\u001d2\u0006\u0010\u001e\u001a\u00020\u000fH\u0017R\u0010\u0010\u0006\u001a\u0004\u0018\u00010\u0007X\u0082\u000e¢\u0006\u0002\n\u0000R\u0010\u0010\t\u001a\u0004\u0018\u00010\nX\u0082\u000e¢\u0006\u0002\n\u0000R\u0010\u0010\u000b\u001a\u0004\u0018\u00010\fX\u0082\u000e¢\u0006\u0002\n\u0000¨\u0006 "}, m173d2 = {"Landroidx/lifecycle/AbstractSavedStateViewModelFactory;", "Landroidx/lifecycle/ViewModelProvider$OnRequeryFactory;", "Landroidx/lifecycle/ViewModelProvider$Factory;", "()V", "owner", "Landroidx/savedstate/SavedStateRegistryOwner;", "defaultArgs", "Landroid/os/Bundle;", "(Landroidx/savedstate/SavedStateRegistryOwner;Landroid/os/Bundle;)V", "lifecycle", "Landroidx/lifecycle/Lifecycle;", "savedStateRegistry", "Landroidx/savedstate/SavedStateRegistry;", "create", "T", "Landroidx/lifecycle/ViewModel;", "modelClass", "Ljava/lang/Class;", "(Ljava/lang/Class;)Landroidx/lifecycle/ViewModel;", "extras", "Landroidx/lifecycle/viewmodel/CreationExtras;", "(Ljava/lang/Class;Landroidx/lifecycle/viewmodel/CreationExtras;)Landroidx/lifecycle/ViewModel;", "key", "", "(Ljava/lang/String;Ljava/lang/Class;)Landroidx/lifecycle/ViewModel;", "handle", "Landroidx/lifecycle/SavedStateHandle;", "(Ljava/lang/String;Ljava/lang/Class;Landroidx/lifecycle/SavedStateHandle;)Landroidx/lifecycle/ViewModel;", "onRequery", "", "viewModel", "Companion", "lifecycle-viewmodel-savedstate_release"}, m172k = 1, m171mv = {1, 8, 0}, m169xi = 48)
/* loaded from: classes.dex */
public abstract class AbstractSavedStateViewModelFactory extends ViewModelProvider.OnRequeryFactory implements ViewModelProvider.Factory {
    public static final Companion Companion = new Companion(null);
    public static final String TAG_SAVED_STATE_HANDLE_CONTROLLER = "androidx.lifecycle.savedstate.vm.tag";
    private Bundle defaultArgs;
    private Lifecycle lifecycle;
    private SavedStateRegistry savedStateRegistry;

    protected abstract <T extends ViewModel> T create(String str, Class<T> cls, SavedStateHandle savedStateHandle);

    public AbstractSavedStateViewModelFactory() {
    }

    public AbstractSavedStateViewModelFactory(SavedStateRegistryOwner owner, Bundle bundle) {
        Intrinsics.checkNotNullParameter(owner, "owner");
        this.savedStateRegistry = owner.getSavedStateRegistry();
        this.lifecycle = owner.getLifecycle();
        this.defaultArgs = bundle;
    }

    @Override // androidx.lifecycle.ViewModelProvider.Factory
    public <T extends ViewModel> T create(Class<T> modelClass, CreationExtras extras) {
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        Intrinsics.checkNotNullParameter(extras, "extras");
        String str = (String) extras.get(ViewModelProvider.NewInstanceFactory.VIEW_MODEL_KEY);
        if (str == null) {
            throw new IllegalStateException("VIEW_MODEL_KEY must always be provided by ViewModelProvider");
        }
        if (this.savedStateRegistry != null) {
            return (T) create(str, modelClass);
        }
        return (T) create(str, modelClass, SavedStateHandleSupport.createSavedStateHandle(extras));
    }

    private final <T extends ViewModel> T create(String str, Class<T> cls) {
        SavedStateRegistry savedStateRegistry = this.savedStateRegistry;
        Intrinsics.checkNotNull(savedStateRegistry);
        Lifecycle lifecycle = this.lifecycle;
        Intrinsics.checkNotNull(lifecycle);
        SavedStateHandleController create = LegacySavedStateHandleController.create(savedStateRegistry, lifecycle, str, this.defaultArgs);
        T t = (T) create(str, cls, create.getHandle());
        t.setTagIfAbsent("androidx.lifecycle.savedstate.vm.tag", create);
        return t;
    }

    @Override // androidx.lifecycle.ViewModelProvider.Factory
    public <T extends ViewModel> T create(Class<T> modelClass) {
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        String canonicalName = modelClass.getCanonicalName();
        if (canonicalName == null) {
            throw new IllegalArgumentException("Local and anonymous classes can not be ViewModels");
        }
        if (this.lifecycle == null) {
            throw new UnsupportedOperationException("AbstractSavedStateViewModelFactory constructed with empty constructor supports only calls to create(modelClass: Class<T>, extras: CreationExtras).");
        }
        return (T) create(canonicalName, modelClass);
    }

    @Override // androidx.lifecycle.ViewModelProvider.OnRequeryFactory
    public void onRequery(ViewModel viewModel) {
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        SavedStateRegistry savedStateRegistry = this.savedStateRegistry;
        if (savedStateRegistry != null) {
            Intrinsics.checkNotNull(savedStateRegistry);
            Lifecycle lifecycle = this.lifecycle;
            Intrinsics.checkNotNull(lifecycle);
            LegacySavedStateHandleController.attachHandleIfNeeded(viewModel, savedStateRegistry, lifecycle);
        }
    }

    /* compiled from: AbstractSavedStateViewModelFactory.kt */
    @Metadata(m174d1 = {"\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0000\b\u0080\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002R\u000e\u0010\u0003\u001a\u00020\u0004X\u0080T¢\u0006\u0002\n\u0000¨\u0006\u0005"}, m173d2 = {"Landroidx/lifecycle/AbstractSavedStateViewModelFactory$Companion;", "", "()V", "TAG_SAVED_STATE_HANDLE_CONTROLLER", "", "lifecycle-viewmodel-savedstate_release"}, m172k = 1, m171mv = {1, 8, 0}, m169xi = 48)
    /* loaded from: classes.dex */
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }
}