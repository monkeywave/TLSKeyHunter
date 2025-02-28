package kotlin.time;

import androidx.constraintlayout.core.motion.utils.TypedValues;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.time.ComparableTimeMark;
import kotlin.time.Duration;
import kotlin.time.TimeSource;

/* compiled from: TimeSources.kt */
@Metadata(m174d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\t\n\u0002\b\u0002\b'\u0018\u00002\u00020\u0001:\u0001\u000bB\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J\b\u0010\u0007\u001a\u00020\bH\u0016J\b\u0010\t\u001a\u00020\nH$R\u0014\u0010\u0002\u001a\u00020\u0003X\u0084\u0004¢\u0006\b\n\u0000\u001a\u0004\b\u0005\u0010\u0006¨\u0006\f"}, m173d2 = {"Lkotlin/time/AbstractLongTimeSource;", "Lkotlin/time/TimeSource$WithComparableMarks;", "unit", "Lkotlin/time/DurationUnit;", "(Lkotlin/time/DurationUnit;)V", "getUnit", "()Lkotlin/time/DurationUnit;", "markNow", "Lkotlin/time/ComparableTimeMark;", "read", "", "LongTimeMark", "kotlin-stdlib"}, m172k = 1, m171mv = {1, 8, 0}, m169xi = 48)
/* loaded from: classes.dex */
public abstract class AbstractLongTimeSource implements TimeSource.WithComparableMarks {
    private final DurationUnitJvm unit;

    protected abstract long read();

    public AbstractLongTimeSource(DurationUnitJvm unit) {
        Intrinsics.checkNotNullParameter(unit, "unit");
        this.unit = unit;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final DurationUnitJvm getUnit() {
        return this.unit;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* compiled from: TimeSources.kt */
    @Metadata(m174d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\t\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\b\n\u0002\b\b\n\u0002\u0010\u000e\n\u0000\b\u0002\u0018\u00002\u00020\u0001B \u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\u0006\u0010\u0006\u001a\u00020\u0007ø\u0001\u0000¢\u0006\u0002\u0010\bJ\u0015\u0010\n\u001a\u00020\u0007H\u0000ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b\u000b\u0010\fJ\u0015\u0010\r\u001a\u00020\u0007H\u0016ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b\u000e\u0010\fJ\u0013\u0010\u000f\u001a\u00020\u00102\b\u0010\u0011\u001a\u0004\u0018\u00010\u0012H\u0096\u0002J\b\u0010\u0013\u001a\u00020\u0014H\u0016J\u001e\u0010\u0015\u001a\u00020\u00072\u0006\u0010\u0011\u001a\u00020\u0001H\u0096\u0002ø\u0001\u0001ø\u0001\u0000¢\u0006\u0004\b\u0016\u0010\u0017J\u001b\u0010\u0018\u001a\u00020\u00012\u0006\u0010\u0019\u001a\u00020\u0007H\u0096\u0002ø\u0001\u0000¢\u0006\u0004\b\u001a\u0010\u001bJ\b\u0010\u001c\u001a\u00020\u001dH\u0016R\u0016\u0010\u0006\u001a\u00020\u0007X\u0082\u0004ø\u0001\u0000ø\u0001\u0001¢\u0006\u0004\n\u0002\u0010\tR\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u0004¢\u0006\u0002\n\u0000\u0082\u0002\b\n\u0002\b\u0019\n\u0002\b!¨\u0006\u001e"}, m173d2 = {"Lkotlin/time/AbstractLongTimeSource$LongTimeMark;", "Lkotlin/time/ComparableTimeMark;", "startedAt", "", "timeSource", "Lkotlin/time/AbstractLongTimeSource;", TypedValues.CycleType.S_WAVE_OFFSET, "Lkotlin/time/Duration;", "(JLkotlin/time/AbstractLongTimeSource;JLkotlin/jvm/internal/DefaultConstructorMarker;)V", "J", "effectiveDuration", "effectiveDuration-UwyO8pc$kotlin_stdlib", "()J", "elapsedNow", "elapsedNow-UwyO8pc", "equals", "", "other", "", "hashCode", "", "minus", "minus-UwyO8pc", "(Lkotlin/time/ComparableTimeMark;)J", "plus", TypedValues.TransitionType.S_DURATION, "plus-LRDsOJo", "(J)Lkotlin/time/ComparableTimeMark;", "toString", "", "kotlin-stdlib"}, m172k = 1, m171mv = {1, 8, 0}, m169xi = 48)
    /* loaded from: classes.dex */
    public static final class LongTimeMark implements ComparableTimeMark {
        private final long offset;
        private final long startedAt;
        private final AbstractLongTimeSource timeSource;

        public /* synthetic */ LongTimeMark(long j, AbstractLongTimeSource abstractLongTimeSource, long j2, DefaultConstructorMarker defaultConstructorMarker) {
            this(j, abstractLongTimeSource, j2);
        }

        private LongTimeMark(long j, AbstractLongTimeSource timeSource, long j2) {
            Intrinsics.checkNotNullParameter(timeSource, "timeSource");
            this.startedAt = j;
            this.timeSource = timeSource;
            this.offset = j2;
        }

        @Override // java.lang.Comparable
        public int compareTo(ComparableTimeMark comparableTimeMark) {
            return ComparableTimeMark.DefaultImpls.compareTo(this, comparableTimeMark);
        }

        @Override // kotlin.time.TimeMark
        public boolean hasNotPassedNow() {
            return ComparableTimeMark.DefaultImpls.hasNotPassedNow(this);
        }

        @Override // kotlin.time.TimeMark
        public boolean hasPassedNow() {
            return ComparableTimeMark.DefaultImpls.hasPassedNow(this);
        }

        @Override // kotlin.time.TimeMark
        /* renamed from: minus-LRDsOJo */
        public ComparableTimeMark mo1653minusLRDsOJo(long j) {
            return ComparableTimeMark.DefaultImpls.m1658minusLRDsOJo(this, j);
        }

        @Override // kotlin.time.TimeMark
        /* renamed from: elapsedNow-UwyO8pc */
        public long mo1652elapsedNowUwyO8pc() {
            return Duration.m1695isInfiniteimpl(this.offset) ? Duration.m1715unaryMinusUwyO8pc(this.offset) : Duration.m1698minusLRDsOJo(DurationKt.toDuration(this.timeSource.read() - this.startedAt, this.timeSource.getUnit()), this.offset);
        }

        @Override // kotlin.time.TimeMark
        /* renamed from: plus-LRDsOJo */
        public ComparableTimeMark mo1655plusLRDsOJo(long j) {
            return new LongTimeMark(this.startedAt, this.timeSource, Duration.m1699plusLRDsOJo(this.offset, j), null);
        }

        @Override // kotlin.time.ComparableTimeMark
        /* renamed from: minus-UwyO8pc */
        public long mo1654minusUwyO8pc(ComparableTimeMark other) {
            Intrinsics.checkNotNullParameter(other, "other");
            if (other instanceof LongTimeMark) {
                LongTimeMark longTimeMark = (LongTimeMark) other;
                if (Intrinsics.areEqual(this.timeSource, longTimeMark.timeSource)) {
                    if (Duration.m1668equalsimpl0(this.offset, longTimeMark.offset) && Duration.m1695isInfiniteimpl(this.offset)) {
                        return Duration.Companion.m1765getZEROUwyO8pc();
                    }
                    long m1698minusLRDsOJo = Duration.m1698minusLRDsOJo(this.offset, longTimeMark.offset);
                    long duration = DurationKt.toDuration(this.startedAt - longTimeMark.startedAt, this.timeSource.getUnit());
                    return Duration.m1668equalsimpl0(duration, Duration.m1715unaryMinusUwyO8pc(m1698minusLRDsOJo)) ? Duration.Companion.m1765getZEROUwyO8pc() : Duration.m1699plusLRDsOJo(duration, m1698minusLRDsOJo);
                }
            }
            throw new IllegalArgumentException("Subtracting or comparing time marks from different time sources is not possible: " + this + " and " + other);
        }

        @Override // kotlin.time.ComparableTimeMark
        public boolean equals(Object obj) {
            return (obj instanceof LongTimeMark) && Intrinsics.areEqual(this.timeSource, ((LongTimeMark) obj).timeSource) && Duration.m1668equalsimpl0(mo1654minusUwyO8pc((ComparableTimeMark) obj), Duration.Companion.m1765getZEROUwyO8pc());
        }

        /* renamed from: effectiveDuration-UwyO8pc$kotlin_stdlib  reason: not valid java name */
        public final long m1656effectiveDurationUwyO8pc$kotlin_stdlib() {
            if (Duration.m1695isInfiniteimpl(this.offset)) {
                return this.offset;
            }
            DurationUnitJvm unit = this.timeSource.getUnit();
            if (unit.compareTo(DurationUnitJvm.MILLISECONDS) >= 0) {
                return Duration.m1699plusLRDsOJo(DurationKt.toDuration(this.startedAt, unit), this.offset);
            }
            long convertDurationUnit = DurationUnitKt.convertDurationUnit(1L, DurationUnitJvm.MILLISECONDS, unit);
            long j = this.startedAt;
            long j2 = j / convertDurationUnit;
            long j3 = j % convertDurationUnit;
            long j4 = this.offset;
            long m1684getInWholeSecondsimpl = Duration.m1684getInWholeSecondsimpl(j4);
            int m1686getNanosecondsComponentimpl = Duration.m1686getNanosecondsComponentimpl(j4);
            int i = m1686getNanosecondsComponentimpl / DurationKt.NANOS_IN_MILLIS;
            int i2 = m1686getNanosecondsComponentimpl % DurationKt.NANOS_IN_MILLIS;
            long duration = DurationKt.toDuration(j3, unit);
            Duration.Companion companion = Duration.Companion;
            long m1699plusLRDsOJo = Duration.m1699plusLRDsOJo(duration, DurationKt.toDuration(i2, DurationUnitJvm.NANOSECONDS));
            Duration.Companion companion2 = Duration.Companion;
            long m1699plusLRDsOJo2 = Duration.m1699plusLRDsOJo(m1699plusLRDsOJo, DurationKt.toDuration(j2 + i, DurationUnitJvm.MILLISECONDS));
            Duration.Companion companion3 = Duration.Companion;
            return Duration.m1699plusLRDsOJo(m1699plusLRDsOJo2, DurationKt.toDuration(m1684getInWholeSecondsimpl, DurationUnitJvm.SECONDS));
        }

        @Override // kotlin.time.ComparableTimeMark
        public int hashCode() {
            return Duration.m1691hashCodeimpl(m1656effectiveDurationUwyO8pc$kotlin_stdlib());
        }

        public String toString() {
            return "LongTimeMark(" + this.startedAt + DurationUnitKt.shortName(this.timeSource.getUnit()) + " + " + ((Object) Duration.m1712toStringimpl(this.offset)) + " (=" + ((Object) Duration.m1712toStringimpl(m1656effectiveDurationUwyO8pc$kotlin_stdlib())) + "), " + this.timeSource + ')';
        }
    }

    @Override // kotlin.time.TimeSource
    public ComparableTimeMark markNow() {
        return new LongTimeMark(read(), this, Duration.Companion.m1765getZEROUwyO8pc(), null);
    }
}