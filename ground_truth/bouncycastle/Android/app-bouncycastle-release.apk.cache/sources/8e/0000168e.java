package kotlinx.coroutines;

import java.util.concurrent.CancellationException;
import kotlin.Metadata;

@Metadata(m174d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\u0018\u00002\u00060\u0001j\u0002`\u00022\b\u0012\u0004\u0012\u00020\u00000\u0003B\u000f\b\u0010\u0012\u0006\u0010\u0004\u001a\u00020\u0005¢\u0006\u0002\u0010\u0006B\u0019\b\u0000\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\b\u0010\u0007\u001a\u0004\u0018\u00010\b¢\u0006\u0002\u0010\tJ\b\u0010\n\u001a\u00020\u0000H\u0016R\u0012\u0010\u0007\u001a\u0004\u0018\u00010\b8\u0000X\u0081\u0004¢\u0006\u0002\n\u0000¨\u0006\u000b"}, m173d2 = {"Lkotlinx/coroutines/TimeoutCancellationException;", "Ljava/util/concurrent/CancellationException;", "Lkotlinx/coroutines/CancellationException;", "Lkotlinx/coroutines/CopyableThrowable;", "message", "", "(Ljava/lang/String;)V", "coroutine", "Lkotlinx/coroutines/Job;", "(Ljava/lang/String;Lkotlinx/coroutines/Job;)V", "createCopy", "kotlinx-coroutines-core"}, m172k = 1, m171mv = {1, 6, 0}, m169xi = 48)
/* renamed from: kotlinx.coroutines.TimeoutCancellationException */
/* loaded from: classes.dex */
public final class Timeout extends CancellationException implements CopyableThrowable<Timeout> {
    public final transient Job coroutine;

    public Timeout(String str, Job job) {
        super(str);
        this.coroutine = job;
    }

    public Timeout(String str) {
        this(str, null);
    }

    @Override // kotlinx.coroutines.CopyableThrowable
    public Timeout createCopy() {
        String message = getMessage();
        if (message == null) {
            message = "";
        }
        Timeout timeout = new Timeout(message, this.coroutine);
        timeout.initCause(this);
        return timeout;
    }
}