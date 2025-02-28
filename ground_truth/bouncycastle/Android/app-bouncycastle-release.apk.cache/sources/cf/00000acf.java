package androidx.profileinstaller;

import android.content.Context;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.view.Choreographer;
import androidx.profileinstaller.ProfileInstallerInitializer;
import androidx.startup.Initializer;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* loaded from: classes.dex */
public class ProfileInstallerInitializer implements Initializer<Result> {
    private static final int DELAY_MS = 5000;

    /* loaded from: classes.dex */
    public static class Result {
    }

    @Override // androidx.startup.Initializer
    public Result create(Context context) {
        delayAfterFirstFrame(context.getApplicationContext());
        return new Result();
    }

    void delayAfterFirstFrame(final Context context) {
        Choreographer16Impl.postFrameCallback(new Runnable() { // from class: androidx.profileinstaller.ProfileInstallerInitializer$$ExternalSyntheticLambda1
            @Override // java.lang.Runnable
            public final void run() {
                ProfileInstallerInitializer.this.m257xfbd6c934(context);
            }
        });
    }

    /* renamed from: installAfterDelay */
    public void m257xfbd6c934(final Context context) {
        Handler handler;
        if (Build.VERSION.SDK_INT >= 28) {
            handler = Handler28Impl.createAsync(Looper.getMainLooper());
        } else {
            handler = new Handler(Looper.getMainLooper());
        }
        handler.postDelayed(new Runnable() { // from class: androidx.profileinstaller.ProfileInstallerInitializer$$ExternalSyntheticLambda0
            @Override // java.lang.Runnable
            public final void run() {
                ProfileInstallerInitializer.lambda$installAfterDelay$1(context);
            }
        }, new Random().nextInt(Math.max(1000, 1)) + DELAY_MS);
    }

    public static /* synthetic */ void lambda$installAfterDelay$1(Context context) {
        writeInBackground(context);
    }

    @Override // androidx.startup.Initializer
    public List<Class<? extends Initializer<?>>> dependencies() {
        return Collections.emptyList();
    }

    public static void writeInBackground(final Context context) {
        new ThreadPoolExecutor(0, 1, 0L, TimeUnit.MILLISECONDS, new LinkedBlockingQueue()).execute(new Runnable() { // from class: androidx.profileinstaller.ProfileInstallerInitializer$$ExternalSyntheticLambda2
            @Override // java.lang.Runnable
            public final void run() {
                ProfileInstallerInitializer.lambda$writeInBackground$2(context);
            }
        });
    }

    public static /* synthetic */ void lambda$writeInBackground$2(Context context) {
        ProfileInstaller.writeProfile(context);
    }

    /* loaded from: classes.dex */
    public static class Choreographer16Impl {
        private Choreographer16Impl() {
        }

        public static /* synthetic */ void lambda$postFrameCallback$0(Runnable runnable, long j) {
            runnable.run();
        }

        public static void postFrameCallback(final Runnable runnable) {
            Choreographer.getInstance().postFrameCallback(new Choreographer.FrameCallback() { // from class: androidx.profileinstaller.ProfileInstallerInitializer$Choreographer16Impl$$ExternalSyntheticLambda0
                @Override // android.view.Choreographer.FrameCallback
                public final void doFrame(long j) {
                    ProfileInstallerInitializer.Choreographer16Impl.lambda$postFrameCallback$0(runnable, j);
                }
            });
        }
    }

    /* loaded from: classes.dex */
    public static class Handler28Impl {
        private Handler28Impl() {
        }

        public static Handler createAsync(Looper looper) {
            return Handler.createAsync(looper);
        }
    }
}