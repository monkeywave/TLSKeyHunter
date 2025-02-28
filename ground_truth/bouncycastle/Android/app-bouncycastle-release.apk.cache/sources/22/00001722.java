package kotlinx.coroutines.channels;

import kotlin.Metadata;
import kotlin.Result;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlinx.coroutines.CancellableContinuation;
import kotlinx.coroutines.CancellableContinuationImplKt;
import kotlinx.coroutines.Debug;
import kotlinx.coroutines.DebugStrings;
import kotlinx.coroutines.internal.LockFreeLinkedListNode;
import kotlinx.coroutines.internal.Symbol;

/* compiled from: AbstractChannel.kt */
@Metadata(m174d1 = {"\u00002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\b\u0010\u0018\u0000*\u0004\b\u0000\u0010\u00012\u00020\u0002B\u001b\u0012\u0006\u0010\u0003\u001a\u00028\u0000\u0012\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u00020\u00060\u0005¢\u0006\u0002\u0010\u0007J\b\u0010\u000b\u001a\u00020\u0006H\u0016J\u0014\u0010\f\u001a\u00020\u00062\n\u0010\r\u001a\u0006\u0012\u0002\b\u00030\u000eH\u0016J\b\u0010\u000f\u001a\u00020\u0010H\u0016J\u0014\u0010\u0011\u001a\u0004\u0018\u00010\u00122\b\u0010\u0013\u001a\u0004\u0018\u00010\u0014H\u0016R\u0016\u0010\u0004\u001a\b\u0012\u0004\u0012\u00020\u00060\u00058\u0006X\u0087\u0004¢\u0006\u0002\n\u0000R\u0016\u0010\u0003\u001a\u00028\u0000X\u0096\u0004¢\u0006\n\n\u0002\u0010\n\u001a\u0004\b\b\u0010\t¨\u0006\u0015"}, m173d2 = {"Lkotlinx/coroutines/channels/SendElement;", "E", "Lkotlinx/coroutines/channels/Send;", "pollResult", "cont", "Lkotlinx/coroutines/CancellableContinuation;", "", "(Ljava/lang/Object;Lkotlinx/coroutines/CancellableContinuation;)V", "getPollResult", "()Ljava/lang/Object;", "Ljava/lang/Object;", "completeResumeSend", "resumeSendClosed", "closed", "Lkotlinx/coroutines/channels/Closed;", "toString", "", "tryResumeSend", "Lkotlinx/coroutines/internal/Symbol;", "otherOp", "Lkotlinx/coroutines/internal/LockFreeLinkedListNode$PrepareOp;", "kotlinx-coroutines-core"}, m172k = 1, m171mv = {1, 6, 0}, m169xi = 48)
/* loaded from: classes.dex */
public class SendElement<E> extends Send {
    public final CancellableContinuation<Unit> cont;
    private final E pollResult;

    @Override // kotlinx.coroutines.channels.Send
    public E getPollResult() {
        return this.pollResult;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public SendElement(E e, CancellableContinuation<? super Unit> cancellableContinuation) {
        this.pollResult = e;
        this.cont = cancellableContinuation;
    }

    @Override // kotlinx.coroutines.channels.Send
    public Symbol tryResumeSend(LockFreeLinkedListNode.PrepareOp prepareOp) {
        Object tryResume = this.cont.tryResume(Unit.INSTANCE, prepareOp != null ? prepareOp.desc : null);
        if (tryResume == null) {
            return null;
        }
        if (!Debug.getASSERTIONS_ENABLED() || tryResume == CancellableContinuationImplKt.RESUME_TOKEN) {
            if (prepareOp != null) {
                prepareOp.finishPrepare();
            }
            return CancellableContinuationImplKt.RESUME_TOKEN;
        }
        throw new AssertionError();
    }

    @Override // kotlinx.coroutines.channels.Send
    public void completeResumeSend() {
        this.cont.completeResume(CancellableContinuationImplKt.RESUME_TOKEN);
    }

    @Override // kotlinx.coroutines.channels.Send
    public void resumeSendClosed(Closed<?> closed) {
        Result.Companion companion = Result.Companion;
        this.cont.resumeWith(Result.m337constructorimpl(ResultKt.createFailure(closed.getSendException())));
    }

    @Override // kotlinx.coroutines.internal.LockFreeLinkedListNode
    public String toString() {
        return DebugStrings.getClassSimpleName(this) + '@' + DebugStrings.getHexAddress(this) + '(' + getPollResult() + ')';
    }
}