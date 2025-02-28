package kotlin.time;

import androidx.constraintlayout.core.motion.utils.TypedValues;
import kotlin.Metadata;
import kotlin.time.Duration;

@Metadata(m174d1 = {"\u0000\u0018\n\u0000\n\u0002\u0010\t\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0012\n\u0002\u0010\u000b\n\u0000\u001a*\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u0001H\u0002ø\u0001\u0000¢\u0006\u0004\b\u0006\u0010\u0007\u001a\"\u0010\b\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0004H\u0000ø\u0001\u0000¢\u0006\u0004\b\t\u0010\n\u001a\"\u0010\u000b\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0004H\u0002ø\u0001\u0000¢\u0006\u0004\b\f\u0010\n\u001a \u0010\r\u001a\u00020\u00042\u0006\u0010\u000e\u001a\u00020\u00012\u0006\u0010\u000f\u001a\u00020\u0001H\u0000ø\u0001\u0000¢\u0006\u0002\u0010\n\u001a \u0010\u0010\u001a\u00020\u00042\u0006\u0010\u0011\u001a\u00020\u00012\u0006\u0010\u0012\u001a\u00020\u0001H\u0002ø\u0001\u0000¢\u0006\u0002\u0010\n\u001a \u0010\u0013\u001a\u00020\u00042\u0006\u0010\u0014\u001a\u00020\u00012\u0006\u0010\u0015\u001a\u00020\u0001H\u0000ø\u0001\u0000¢\u0006\u0002\u0010\n\u001a\r\u0010\u0016\u001a\u00020\u0017*\u00020\u0001H\u0082\b\u0082\u0002\u0004\n\u0002\b\u0019¨\u0006\u0018"}, m173d2 = {"checkInfiniteSumDefined", "", "longNs", TypedValues.TransitionType.S_DURATION, "Lkotlin/time/Duration;", "durationNs", "checkInfiniteSumDefined-PjuGub4", "(JJJ)J", "saturatingAdd", "saturatingAdd-pTJri5U", "(JJ)J", "saturatingAddInHalves", "saturatingAddInHalves-pTJri5U", "saturatingDiff", "valueNs", "originNs", "saturatingFiniteDiff", "value1Ns", "value2Ns", "saturatingOriginsDiff", "origin1Ns", "origin2Ns", "isSaturated", "", "kotlin-stdlib"}, m172k = 2, m171mv = {1, 8, 0}, m169xi = 48)
/* renamed from: kotlin.time.LongSaturatedMathKt */
/* loaded from: classes.dex */
public final class longSaturatedMath {
    private static final boolean isSaturated(long j) {
        return ((j - 1) | 1) == Long.MAX_VALUE;
    }

    /* renamed from: saturatingAdd-pTJri5U  reason: not valid java name */
    public static final long m1791saturatingAddpTJri5U(long j, long j2) {
        long m1683getInWholeNanosecondsimpl = Duration.m1683getInWholeNanosecondsimpl(j2);
        if (((j - 1) | 1) == Long.MAX_VALUE) {
            return m1790checkInfiniteSumDefinedPjuGub4(j, j2, m1683getInWholeNanosecondsimpl);
        }
        if ((1 | (m1683getInWholeNanosecondsimpl - 1)) == Long.MAX_VALUE) {
            return m1792saturatingAddInHalvespTJri5U(j, j2);
        }
        long j3 = j + m1683getInWholeNanosecondsimpl;
        return ((j ^ j3) & (m1683getInWholeNanosecondsimpl ^ j3)) < 0 ? j < 0 ? Long.MIN_VALUE : Long.MAX_VALUE : j3;
    }

    /* renamed from: checkInfiniteSumDefined-PjuGub4  reason: not valid java name */
    private static final long m1790checkInfiniteSumDefinedPjuGub4(long j, long j2, long j3) {
        if (!Duration.m1695isInfiniteimpl(j2) || (j ^ j3) >= 0) {
            return j;
        }
        throw new IllegalArgumentException("Summing infinities of different signs");
    }

    /* renamed from: saturatingAddInHalves-pTJri5U  reason: not valid java name */
    private static final long m1792saturatingAddInHalvespTJri5U(long j, long j2) {
        long m1666divUwyO8pc = Duration.m1666divUwyO8pc(j2, 2);
        if (((Duration.m1683getInWholeNanosecondsimpl(m1666divUwyO8pc) - 1) | 1) == Long.MAX_VALUE) {
            return (long) (j + Duration.m1706toDoubleimpl(j2, DurationUnitJvm.NANOSECONDS));
        }
        return m1791saturatingAddpTJri5U(m1791saturatingAddpTJri5U(j, m1666divUwyO8pc), Duration.m1698minusLRDsOJo(j2, m1666divUwyO8pc));
    }

    public static final long saturatingDiff(long j, long j2) {
        if ((1 | (j2 - 1)) == Long.MAX_VALUE) {
            return Duration.m1715unaryMinusUwyO8pc(DurationKt.toDuration(j2, DurationUnitJvm.DAYS));
        }
        return saturatingFiniteDiff(j, j2);
    }

    public static final long saturatingOriginsDiff(long j, long j2) {
        if (((j2 - 1) | 1) == Long.MAX_VALUE) {
            if (j == j2) {
                return Duration.Companion.m1765getZEROUwyO8pc();
            }
            return Duration.m1715unaryMinusUwyO8pc(DurationKt.toDuration(j2, DurationUnitJvm.DAYS));
        } else if ((1 | (j - 1)) == Long.MAX_VALUE) {
            return DurationKt.toDuration(j, DurationUnitJvm.DAYS);
        } else {
            return saturatingFiniteDiff(j, j2);
        }
    }

    private static final long saturatingFiniteDiff(long j, long j2) {
        long j3 = j - j2;
        if (((j3 ^ j) & (~(j3 ^ j2))) < 0) {
            long j4 = (long) DurationKt.NANOS_IN_MILLIS;
            long j5 = (j % j4) - (j2 % j4);
            Duration.Companion companion = Duration.Companion;
            long duration = DurationKt.toDuration((j / j4) - (j2 / j4), DurationUnitJvm.MILLISECONDS);
            Duration.Companion companion2 = Duration.Companion;
            return Duration.m1699plusLRDsOJo(duration, DurationKt.toDuration(j5, DurationUnitJvm.NANOSECONDS));
        }
        Duration.Companion companion3 = Duration.Companion;
        return DurationKt.toDuration(j3, DurationUnitJvm.NANOSECONDS);
    }
}