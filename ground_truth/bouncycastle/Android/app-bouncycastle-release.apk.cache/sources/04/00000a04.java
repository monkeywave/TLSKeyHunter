package androidx.lifecycle;

import androidx.arch.core.executor.ArchTaskExecutor;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: ComputableLiveData.kt */
@Metadata(m174d1 = {"\u00000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0010\u0002\n\u0000\b'\u0018\u0000*\u0004\b\u0000\u0010\u00012\u00020\u0002B\u0011\b\u0007\u0012\b\b\u0002\u0010\u0003\u001a\u00020\u0004¢\u0006\u0002\u0010\u0005J\r\u0010\u0019\u001a\u00028\u0000H%¢\u0006\u0002\u0010\u001aJ\b\u0010\u001b\u001a\u00020\u001cH\u0016R\u0016\u0010\u0006\u001a\n\u0012\u0006\u0012\u0004\u0018\u00018\u00000\u0007X\u0082\u0004¢\u0006\u0002\n\u0000R\u0014\u0010\b\u001a\u00020\tX\u0080\u0004¢\u0006\b\n\u0000\u001a\u0004\b\n\u0010\u000bR\u0014\u0010\u0003\u001a\u00020\u0004X\u0080\u0004¢\u0006\b\n\u0000\u001a\u0004\b\f\u0010\rR\u0014\u0010\u000e\u001a\u00020\tX\u0080\u0004¢\u0006\b\n\u0000\u001a\u0004\b\u000f\u0010\u000bR\u0016\u0010\u0010\u001a\u00020\u00118\u0000X\u0081\u0004¢\u0006\b\n\u0000\u0012\u0004\b\u0012\u0010\u0013R\u001c\u0010\u0014\u001a\n\u0012\u0006\u0012\u0004\u0018\u00018\u00000\u0007X\u0096\u0004¢\u0006\b\n\u0000\u001a\u0004\b\u0015\u0010\u0016R\u0016\u0010\u0017\u001a\u00020\u00118\u0000X\u0081\u0004¢\u0006\b\n\u0000\u0012\u0004\b\u0018\u0010\u0013¨\u0006\u001d"}, m173d2 = {"Landroidx/lifecycle/ComputableLiveData;", "T", "", "executor", "Ljava/util/concurrent/Executor;", "(Ljava/util/concurrent/Executor;)V", "_liveData", "Landroidx/lifecycle/LiveData;", "computing", "Ljava/util/concurrent/atomic/AtomicBoolean;", "getComputing$lifecycle_livedata_release", "()Ljava/util/concurrent/atomic/AtomicBoolean;", "getExecutor$lifecycle_livedata_release", "()Ljava/util/concurrent/Executor;", "invalid", "getInvalid$lifecycle_livedata_release", "invalidationRunnable", "Ljava/lang/Runnable;", "getInvalidationRunnable$lifecycle_livedata_release$annotations", "()V", "liveData", "getLiveData", "()Landroidx/lifecycle/LiveData;", "refreshRunnable", "getRefreshRunnable$lifecycle_livedata_release$annotations", "compute", "()Ljava/lang/Object;", "invalidate", "", "lifecycle-livedata_release"}, m172k = 1, m171mv = {1, 8, 0}, m169xi = 48)
/* loaded from: classes.dex */
public abstract class ComputableLiveData<T> {
    private final LiveData<T> _liveData;
    private final AtomicBoolean computing;
    private final Executor executor;
    private final AtomicBoolean invalid;
    public final Runnable invalidationRunnable;
    private final LiveData<T> liveData;
    public final Runnable refreshRunnable;

    /* renamed from: $r8$lambda$3YPDTAMNTCGT-z9DkpLbjudOC6w */
    public static /* synthetic */ void m322$r8$lambda$3YPDTAMNTCGTz9DkpLbjudOC6w(ComputableLiveData computableLiveData) {
        refreshRunnable$lambda$0(computableLiveData);
    }

    public static /* synthetic */ void $r8$lambda$7oABH0_b7KfpQ6DlyqjjKM5jdaU(ComputableLiveData computableLiveData) {
        invalidationRunnable$lambda$1(computableLiveData);
    }

    public ComputableLiveData() {
        this(null, 1, null);
    }

    public static /* synthetic */ void getInvalidationRunnable$lifecycle_livedata_release$annotations() {
    }

    public static /* synthetic */ void getRefreshRunnable$lifecycle_livedata_release$annotations() {
    }

    protected abstract T compute();

    public ComputableLiveData(Executor executor) {
        Intrinsics.checkNotNullParameter(executor, "executor");
        this.executor = executor;
        LiveData<T> liveData = new LiveData<T>(this) { // from class: androidx.lifecycle.ComputableLiveData$_liveData$1
            final /* synthetic */ ComputableLiveData<T> this$0;

            /* JADX INFO: Access modifiers changed from: package-private */
            {
                this.this$0 = this;
            }

            @Override // androidx.lifecycle.LiveData
            protected void onActive() {
                this.this$0.getExecutor$lifecycle_livedata_release().execute(this.this$0.refreshRunnable);
            }
        };
        this._liveData = liveData;
        this.liveData = liveData;
        this.invalid = new AtomicBoolean(true);
        this.computing = new AtomicBoolean(false);
        this.refreshRunnable = new Runnable() { // from class: androidx.lifecycle.ComputableLiveData$$ExternalSyntheticLambda0
            @Override // java.lang.Runnable
            public final void run() {
                ComputableLiveData.m322$r8$lambda$3YPDTAMNTCGTz9DkpLbjudOC6w(ComputableLiveData.this);
            }
        };
        this.invalidationRunnable = new Runnable() { // from class: androidx.lifecycle.ComputableLiveData$$ExternalSyntheticLambda1
            @Override // java.lang.Runnable
            public final void run() {
                ComputableLiveData.$r8$lambda$7oABH0_b7KfpQ6DlyqjjKM5jdaU(ComputableLiveData.this);
            }
        };
    }

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public /* synthetic */ ComputableLiveData(java.util.concurrent.Executor r1, int r2, kotlin.jvm.internal.DefaultConstructorMarker r3) {
        /*
            r0 = this;
            r2 = r2 & 1
            if (r2 == 0) goto Ld
            java.util.concurrent.Executor r1 = androidx.arch.core.executor.ArchTaskExecutor.getIOThreadExecutor()
            java.lang.String r2 = "getIOThreadExecutor()"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r1, r2)
        Ld:
            r0.<init>(r1)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.lifecycle.ComputableLiveData.<init>(java.util.concurrent.Executor, int, kotlin.jvm.internal.DefaultConstructorMarker):void");
    }

    public final Executor getExecutor$lifecycle_livedata_release() {
        return this.executor;
    }

    public LiveData<T> getLiveData() {
        return this.liveData;
    }

    public final AtomicBoolean getInvalid$lifecycle_livedata_release() {
        return this.invalid;
    }

    public final AtomicBoolean getComputing$lifecycle_livedata_release() {
        return this.computing;
    }

    public static final void refreshRunnable$lambda$0(ComputableLiveData this$0) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        do {
            boolean z = false;
            if (this$0.computing.compareAndSet(false, true)) {
                T t = null;
                boolean z2 = false;
                while (this$0.invalid.compareAndSet(true, false)) {
                    try {
                        t = (T) this$0.compute();
                        z2 = true;
                    } catch (Throwable th) {
                        this$0.computing.set(false);
                        throw th;
                    }
                }
                if (z2) {
                    this$0.getLiveData().postValue(t);
                }
                this$0.computing.set(false);
                z = z2;
            }
            if (!z) {
                return;
            }
        } while (this$0.invalid.get());
    }

    public static final void invalidationRunnable$lambda$1(ComputableLiveData this$0) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        boolean hasActiveObservers = this$0.getLiveData().hasActiveObservers();
        if (this$0.invalid.compareAndSet(false, true) && hasActiveObservers) {
            this$0.executor.execute(this$0.refreshRunnable);
        }
    }

    public void invalidate() {
        ArchTaskExecutor.getInstance().executeOnMainThread(this.invalidationRunnable);
    }
}