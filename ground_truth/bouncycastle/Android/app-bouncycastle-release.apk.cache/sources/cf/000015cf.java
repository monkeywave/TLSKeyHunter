package kotlin.time;

import androidx.constraintlayout.core.motion.utils.TypedValues;
import kotlin.Deprecated;
import kotlin.DeprecatedSinceKotlin;
import kotlin.Metadata;
import kotlin.ReplaceWith;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.math.MathKt;
import kotlin.ranges.LongRange;
import kotlin.ranges.PrimitiveRanges;
import kotlin.ranges.RangesKt;
import kotlin.text.StringsKt;

/* compiled from: Duration.kt */
@Metadata(m174d1 = {"\u0000>\n\u0000\n\u0002\u0010\t\n\u0002\b\u0003\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0006\n\u0002\b*\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0010\f\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\b\u0004\u001a \u0010#\u001a\u00020\u00072\u0006\u0010$\u001a\u00020\u00012\u0006\u0010%\u001a\u00020\u0005H\u0002ø\u0001\u0000¢\u0006\u0002\u0010&\u001a\u0018\u0010'\u001a\u00020\u00072\u0006\u0010(\u001a\u00020\u0001H\u0002ø\u0001\u0000¢\u0006\u0002\u0010\u0010\u001a\u0018\u0010)\u001a\u00020\u00072\u0006\u0010*\u001a\u00020\u0001H\u0002ø\u0001\u0000¢\u0006\u0002\u0010\u0010\u001a\u0018\u0010+\u001a\u00020\u00072\u0006\u0010,\u001a\u00020\u0001H\u0002ø\u0001\u0000¢\u0006\u0002\u0010\u0010\u001a\u0018\u0010-\u001a\u00020\u00072\u0006\u0010.\u001a\u00020\u0001H\u0002ø\u0001\u0000¢\u0006\u0002\u0010\u0010\u001a\u0010\u0010/\u001a\u00020\u00012\u0006\u0010*\u001a\u00020\u0001H\u0002\u001a\u0010\u00100\u001a\u00020\u00012\u0006\u0010.\u001a\u00020\u0001H\u0002\u001a \u00101\u001a\u00020\u00072\u0006\u00102\u001a\u0002032\u0006\u00104\u001a\u000205H\u0002ø\u0001\u0000¢\u0006\u0002\u00106\u001a\u0010\u00107\u001a\u00020\u00012\u0006\u00102\u001a\u000203H\u0002\u001a)\u00108\u001a\u00020\u0005*\u0002032\u0006\u00109\u001a\u00020\u00052\u0012\u0010:\u001a\u000e\u0012\u0004\u0012\u00020<\u0012\u0004\u0012\u0002050;H\u0082\b\u001a)\u0010=\u001a\u000203*\u0002032\u0006\u00109\u001a\u00020\u00052\u0012\u0010:\u001a\u000e\u0012\u0004\u0012\u00020<\u0012\u0004\u0012\u0002050;H\u0082\b\u001a\u001f\u0010>\u001a\u00020\u0007*\u00020\b2\u0006\u0010?\u001a\u00020\u0007H\u0087\nø\u0001\u0000¢\u0006\u0004\b@\u0010A\u001a\u001f\u0010>\u001a\u00020\u0007*\u00020\u00052\u0006\u0010?\u001a\u00020\u0007H\u0087\nø\u0001\u0000¢\u0006\u0004\bB\u0010C\u001a\u001c\u0010D\u001a\u00020\u0007*\u00020\b2\u0006\u0010E\u001a\u00020FH\u0007ø\u0001\u0000¢\u0006\u0002\u0010G\u001a\u001c\u0010D\u001a\u00020\u0007*\u00020\u00052\u0006\u0010E\u001a\u00020FH\u0007ø\u0001\u0000¢\u0006\u0002\u0010H\u001a\u001c\u0010D\u001a\u00020\u0007*\u00020\u00012\u0006\u0010E\u001a\u00020FH\u0007ø\u0001\u0000¢\u0006\u0002\u0010I\"\u000e\u0010\u0000\u001a\u00020\u0001X\u0080T¢\u0006\u0002\n\u0000\"\u000e\u0010\u0002\u001a\u00020\u0001X\u0080T¢\u0006\u0002\n\u0000\"\u000e\u0010\u0003\u001a\u00020\u0001X\u0082T¢\u0006\u0002\n\u0000\"\u000e\u0010\u0004\u001a\u00020\u0005X\u0080T¢\u0006\u0002\n\u0000\"!\u0010\u0006\u001a\u00020\u0007*\u00020\b8FX\u0087\u0004ø\u0001\u0000¢\u0006\f\u0012\u0004\b\t\u0010\n\u001a\u0004\b\u000b\u0010\f\"!\u0010\u0006\u001a\u00020\u0007*\u00020\u00058FX\u0087\u0004ø\u0001\u0000¢\u0006\f\u0012\u0004\b\t\u0010\r\u001a\u0004\b\u000b\u0010\u000e\"!\u0010\u0006\u001a\u00020\u0007*\u00020\u00018FX\u0087\u0004ø\u0001\u0000¢\u0006\f\u0012\u0004\b\t\u0010\u000f\u001a\u0004\b\u000b\u0010\u0010\"!\u0010\u0011\u001a\u00020\u0007*\u00020\b8FX\u0087\u0004ø\u0001\u0000¢\u0006\f\u0012\u0004\b\u0012\u0010\n\u001a\u0004\b\u0013\u0010\f\"!\u0010\u0011\u001a\u00020\u0007*\u00020\u00058FX\u0087\u0004ø\u0001\u0000¢\u0006\f\u0012\u0004\b\u0012\u0010\r\u001a\u0004\b\u0013\u0010\u000e\"!\u0010\u0011\u001a\u00020\u0007*\u00020\u00018FX\u0087\u0004ø\u0001\u0000¢\u0006\f\u0012\u0004\b\u0012\u0010\u000f\u001a\u0004\b\u0013\u0010\u0010\"!\u0010\u0014\u001a\u00020\u0007*\u00020\b8FX\u0087\u0004ø\u0001\u0000¢\u0006\f\u0012\u0004\b\u0015\u0010\n\u001a\u0004\b\u0016\u0010\f\"!\u0010\u0014\u001a\u00020\u0007*\u00020\u00058FX\u0087\u0004ø\u0001\u0000¢\u0006\f\u0012\u0004\b\u0015\u0010\r\u001a\u0004\b\u0016\u0010\u000e\"!\u0010\u0014\u001a\u00020\u0007*\u00020\u00018FX\u0087\u0004ø\u0001\u0000¢\u0006\f\u0012\u0004\b\u0015\u0010\u000f\u001a\u0004\b\u0016\u0010\u0010\"!\u0010\u0017\u001a\u00020\u0007*\u00020\b8FX\u0087\u0004ø\u0001\u0000¢\u0006\f\u0012\u0004\b\u0018\u0010\n\u001a\u0004\b\u0019\u0010\f\"!\u0010\u0017\u001a\u00020\u0007*\u00020\u00058FX\u0087\u0004ø\u0001\u0000¢\u0006\f\u0012\u0004\b\u0018\u0010\r\u001a\u0004\b\u0019\u0010\u000e\"!\u0010\u0017\u001a\u00020\u0007*\u00020\u00018FX\u0087\u0004ø\u0001\u0000¢\u0006\f\u0012\u0004\b\u0018\u0010\u000f\u001a\u0004\b\u0019\u0010\u0010\"!\u0010\u001a\u001a\u00020\u0007*\u00020\b8FX\u0087\u0004ø\u0001\u0000¢\u0006\f\u0012\u0004\b\u001b\u0010\n\u001a\u0004\b\u001c\u0010\f\"!\u0010\u001a\u001a\u00020\u0007*\u00020\u00058FX\u0087\u0004ø\u0001\u0000¢\u0006\f\u0012\u0004\b\u001b\u0010\r\u001a\u0004\b\u001c\u0010\u000e\"!\u0010\u001a\u001a\u00020\u0007*\u00020\u00018FX\u0087\u0004ø\u0001\u0000¢\u0006\f\u0012\u0004\b\u001b\u0010\u000f\u001a\u0004\b\u001c\u0010\u0010\"!\u0010\u001d\u001a\u00020\u0007*\u00020\b8FX\u0087\u0004ø\u0001\u0000¢\u0006\f\u0012\u0004\b\u001e\u0010\n\u001a\u0004\b\u001f\u0010\f\"!\u0010\u001d\u001a\u00020\u0007*\u00020\u00058FX\u0087\u0004ø\u0001\u0000¢\u0006\f\u0012\u0004\b\u001e\u0010\r\u001a\u0004\b\u001f\u0010\u000e\"!\u0010\u001d\u001a\u00020\u0007*\u00020\u00018FX\u0087\u0004ø\u0001\u0000¢\u0006\f\u0012\u0004\b\u001e\u0010\u000f\u001a\u0004\b\u001f\u0010\u0010\"!\u0010 \u001a\u00020\u0007*\u00020\b8FX\u0087\u0004ø\u0001\u0000¢\u0006\f\u0012\u0004\b!\u0010\n\u001a\u0004\b\"\u0010\f\"!\u0010 \u001a\u00020\u0007*\u00020\u00058FX\u0087\u0004ø\u0001\u0000¢\u0006\f\u0012\u0004\b!\u0010\r\u001a\u0004\b\"\u0010\u000e\"!\u0010 \u001a\u00020\u0007*\u00020\u00018FX\u0087\u0004ø\u0001\u0000¢\u0006\f\u0012\u0004\b!\u0010\u000f\u001a\u0004\b\"\u0010\u0010\u0082\u0002\u0004\n\u0002\b\u0019¨\u0006J"}, m173d2 = {"MAX_MILLIS", "", "MAX_NANOS", "MAX_NANOS_IN_MILLIS", "NANOS_IN_MILLIS", "", "days", "Lkotlin/time/Duration;", "", "getDays$annotations", "(D)V", "getDays", "(D)J", "(I)V", "(I)J", "(J)V", "(J)J", "hours", "getHours$annotations", "getHours", "microseconds", "getMicroseconds$annotations", "getMicroseconds", "milliseconds", "getMilliseconds$annotations", "getMilliseconds", "minutes", "getMinutes$annotations", "getMinutes", "nanoseconds", "getNanoseconds$annotations", "getNanoseconds", "seconds", "getSeconds$annotations", "getSeconds", "durationOf", "normalValue", "unitDiscriminator", "(JI)J", "durationOfMillis", "normalMillis", "durationOfMillisNormalized", "millis", "durationOfNanos", "normalNanos", "durationOfNanosNormalized", "nanos", "millisToNanos", "nanosToMillis", "parseDuration", "value", "", "strictIso", "", "(Ljava/lang/String;Z)J", "parseOverLongIsoComponent", "skipWhile", "startIndex", "predicate", "Lkotlin/Function1;", "", "substringWhile", "times", TypedValues.TransitionType.S_DURATION, "times-kIfJnKk", "(DJ)J", "times-mvk6XK0", "(IJ)J", "toDuration", "unit", "Lkotlin/time/DurationUnit;", "(DLkotlin/time/DurationUnit;)J", "(ILkotlin/time/DurationUnit;)J", "(JLkotlin/time/DurationUnit;)J", "kotlin-stdlib"}, m172k = 2, m171mv = {1, 8, 0}, m169xi = 48)
/* loaded from: classes.dex */
public final class DurationKt {
    public static final long MAX_MILLIS = 4611686018427387903L;
    public static final long MAX_NANOS = 4611686018426999999L;
    private static final long MAX_NANOS_IN_MILLIS = 4611686018426L;
    public static final int NANOS_IN_MILLIS = 1000000;

    @Deprecated(message = "Use 'Double.days' extension property from Duration.Companion instead.", replaceWith = @ReplaceWith(expression = "this.days", imports = {"kotlin.time.Duration.Companion.days"}))
    @DeprecatedSinceKotlin(errorSince = "1.8", warningSince = "1.5")
    public static /* synthetic */ void getDays$annotations(double d) {
    }

    @Deprecated(message = "Use 'Int.days' extension property from Duration.Companion instead.", replaceWith = @ReplaceWith(expression = "this.days", imports = {"kotlin.time.Duration.Companion.days"}))
    @DeprecatedSinceKotlin(errorSince = "1.8", warningSince = "1.5")
    public static /* synthetic */ void getDays$annotations(int i) {
    }

    @Deprecated(message = "Use 'Long.days' extension property from Duration.Companion instead.", replaceWith = @ReplaceWith(expression = "this.days", imports = {"kotlin.time.Duration.Companion.days"}))
    @DeprecatedSinceKotlin(errorSince = "1.8", warningSince = "1.5")
    public static /* synthetic */ void getDays$annotations(long j) {
    }

    @Deprecated(message = "Use 'Double.hours' extension property from Duration.Companion instead.", replaceWith = @ReplaceWith(expression = "this.hours", imports = {"kotlin.time.Duration.Companion.hours"}))
    @DeprecatedSinceKotlin(errorSince = "1.8", warningSince = "1.5")
    public static /* synthetic */ void getHours$annotations(double d) {
    }

    @Deprecated(message = "Use 'Int.hours' extension property from Duration.Companion instead.", replaceWith = @ReplaceWith(expression = "this.hours", imports = {"kotlin.time.Duration.Companion.hours"}))
    @DeprecatedSinceKotlin(errorSince = "1.8", warningSince = "1.5")
    public static /* synthetic */ void getHours$annotations(int i) {
    }

    @Deprecated(message = "Use 'Long.hours' extension property from Duration.Companion instead.", replaceWith = @ReplaceWith(expression = "this.hours", imports = {"kotlin.time.Duration.Companion.hours"}))
    @DeprecatedSinceKotlin(errorSince = "1.8", warningSince = "1.5")
    public static /* synthetic */ void getHours$annotations(long j) {
    }

    @Deprecated(message = "Use 'Double.microseconds' extension property from Duration.Companion instead.", replaceWith = @ReplaceWith(expression = "this.microseconds", imports = {"kotlin.time.Duration.Companion.microseconds"}))
    @DeprecatedSinceKotlin(errorSince = "1.8", warningSince = "1.5")
    public static /* synthetic */ void getMicroseconds$annotations(double d) {
    }

    @Deprecated(message = "Use 'Int.microseconds' extension property from Duration.Companion instead.", replaceWith = @ReplaceWith(expression = "this.microseconds", imports = {"kotlin.time.Duration.Companion.microseconds"}))
    @DeprecatedSinceKotlin(errorSince = "1.8", warningSince = "1.5")
    public static /* synthetic */ void getMicroseconds$annotations(int i) {
    }

    @Deprecated(message = "Use 'Long.microseconds' extension property from Duration.Companion instead.", replaceWith = @ReplaceWith(expression = "this.microseconds", imports = {"kotlin.time.Duration.Companion.microseconds"}))
    @DeprecatedSinceKotlin(errorSince = "1.8", warningSince = "1.5")
    public static /* synthetic */ void getMicroseconds$annotations(long j) {
    }

    @Deprecated(message = "Use 'Double.milliseconds' extension property from Duration.Companion instead.", replaceWith = @ReplaceWith(expression = "this.milliseconds", imports = {"kotlin.time.Duration.Companion.milliseconds"}))
    @DeprecatedSinceKotlin(errorSince = "1.8", warningSince = "1.5")
    public static /* synthetic */ void getMilliseconds$annotations(double d) {
    }

    @Deprecated(message = "Use 'Int.milliseconds' extension property from Duration.Companion instead.", replaceWith = @ReplaceWith(expression = "this.milliseconds", imports = {"kotlin.time.Duration.Companion.milliseconds"}))
    @DeprecatedSinceKotlin(errorSince = "1.8", warningSince = "1.5")
    public static /* synthetic */ void getMilliseconds$annotations(int i) {
    }

    @Deprecated(message = "Use 'Long.milliseconds' extension property from Duration.Companion instead.", replaceWith = @ReplaceWith(expression = "this.milliseconds", imports = {"kotlin.time.Duration.Companion.milliseconds"}))
    @DeprecatedSinceKotlin(errorSince = "1.8", warningSince = "1.5")
    public static /* synthetic */ void getMilliseconds$annotations(long j) {
    }

    @Deprecated(message = "Use 'Double.minutes' extension property from Duration.Companion instead.", replaceWith = @ReplaceWith(expression = "this.minutes", imports = {"kotlin.time.Duration.Companion.minutes"}))
    @DeprecatedSinceKotlin(errorSince = "1.8", warningSince = "1.5")
    public static /* synthetic */ void getMinutes$annotations(double d) {
    }

    @Deprecated(message = "Use 'Int.minutes' extension property from Duration.Companion instead.", replaceWith = @ReplaceWith(expression = "this.minutes", imports = {"kotlin.time.Duration.Companion.minutes"}))
    @DeprecatedSinceKotlin(errorSince = "1.8", warningSince = "1.5")
    public static /* synthetic */ void getMinutes$annotations(int i) {
    }

    @Deprecated(message = "Use 'Long.minutes' extension property from Duration.Companion instead.", replaceWith = @ReplaceWith(expression = "this.minutes", imports = {"kotlin.time.Duration.Companion.minutes"}))
    @DeprecatedSinceKotlin(errorSince = "1.8", warningSince = "1.5")
    public static /* synthetic */ void getMinutes$annotations(long j) {
    }

    @Deprecated(message = "Use 'Double.nanoseconds' extension property from Duration.Companion instead.", replaceWith = @ReplaceWith(expression = "this.nanoseconds", imports = {"kotlin.time.Duration.Companion.nanoseconds"}))
    @DeprecatedSinceKotlin(errorSince = "1.8", warningSince = "1.5")
    public static /* synthetic */ void getNanoseconds$annotations(double d) {
    }

    @Deprecated(message = "Use 'Int.nanoseconds' extension property from Duration.Companion instead.", replaceWith = @ReplaceWith(expression = "this.nanoseconds", imports = {"kotlin.time.Duration.Companion.nanoseconds"}))
    @DeprecatedSinceKotlin(errorSince = "1.8", warningSince = "1.5")
    public static /* synthetic */ void getNanoseconds$annotations(int i) {
    }

    @Deprecated(message = "Use 'Long.nanoseconds' extension property from Duration.Companion instead.", replaceWith = @ReplaceWith(expression = "this.nanoseconds", imports = {"kotlin.time.Duration.Companion.nanoseconds"}))
    @DeprecatedSinceKotlin(errorSince = "1.8", warningSince = "1.5")
    public static /* synthetic */ void getNanoseconds$annotations(long j) {
    }

    @Deprecated(message = "Use 'Double.seconds' extension property from Duration.Companion instead.", replaceWith = @ReplaceWith(expression = "this.seconds", imports = {"kotlin.time.Duration.Companion.seconds"}))
    @DeprecatedSinceKotlin(errorSince = "1.8", warningSince = "1.5")
    public static /* synthetic */ void getSeconds$annotations(double d) {
    }

    @Deprecated(message = "Use 'Int.seconds' extension property from Duration.Companion instead.", replaceWith = @ReplaceWith(expression = "this.seconds", imports = {"kotlin.time.Duration.Companion.seconds"}))
    @DeprecatedSinceKotlin(errorSince = "1.8", warningSince = "1.5")
    public static /* synthetic */ void getSeconds$annotations(int i) {
    }

    @Deprecated(message = "Use 'Long.seconds' extension property from Duration.Companion instead.", replaceWith = @ReplaceWith(expression = "this.seconds", imports = {"kotlin.time.Duration.Companion.seconds"}))
    @DeprecatedSinceKotlin(errorSince = "1.8", warningSince = "1.5")
    public static /* synthetic */ void getSeconds$annotations(long j) {
    }

    public static final long millisToNanos(long j) {
        return j * ((long) NANOS_IN_MILLIS);
    }

    public static final long toDuration(int i, DurationUnitJvm unit) {
        Intrinsics.checkNotNullParameter(unit, "unit");
        if (unit.compareTo(DurationUnitJvm.SECONDS) <= 0) {
            return durationOfNanos(DurationUnitKt.convertDurationUnitOverflow(i, unit, DurationUnitJvm.NANOSECONDS));
        }
        return toDuration(i, unit);
    }

    public static final long toDuration(long j, DurationUnitJvm unit) {
        Intrinsics.checkNotNullParameter(unit, "unit");
        long convertDurationUnitOverflow = DurationUnitKt.convertDurationUnitOverflow(MAX_NANOS, DurationUnitJvm.NANOSECONDS, unit);
        if (new LongRange(-convertDurationUnitOverflow, convertDurationUnitOverflow).contains(j)) {
            return durationOfNanos(DurationUnitKt.convertDurationUnitOverflow(j, unit, DurationUnitJvm.NANOSECONDS));
        }
        return durationOfMillis(RangesKt.coerceIn(DurationUnitKt.convertDurationUnit(j, unit, DurationUnitJvm.MILLISECONDS), -4611686018427387903L, (long) MAX_MILLIS));
    }

    public static final long toDuration(double d, DurationUnitJvm unit) {
        Intrinsics.checkNotNullParameter(unit, "unit");
        double convertDurationUnit = DurationUnitKt.convertDurationUnit(d, unit, DurationUnitJvm.NANOSECONDS);
        if (Double.isNaN(convertDurationUnit)) {
            throw new IllegalArgumentException("Duration value cannot be NaN.".toString());
        }
        long roundToLong = MathKt.roundToLong(convertDurationUnit);
        if (new LongRange(-4611686018426999999L, MAX_NANOS).contains(roundToLong)) {
            return durationOfNanos(roundToLong);
        }
        return durationOfMillisNormalized(MathKt.roundToLong(DurationUnitKt.convertDurationUnit(d, unit, DurationUnitJvm.MILLISECONDS)));
    }

    public static final long getNanoseconds(int i) {
        return toDuration(i, DurationUnitJvm.NANOSECONDS);
    }

    public static final long getNanoseconds(long j) {
        return toDuration(j, DurationUnitJvm.NANOSECONDS);
    }

    public static final long getNanoseconds(double d) {
        return toDuration(d, DurationUnitJvm.NANOSECONDS);
    }

    public static final long getMicroseconds(int i) {
        return toDuration(i, DurationUnitJvm.MICROSECONDS);
    }

    public static final long getMicroseconds(long j) {
        return toDuration(j, DurationUnitJvm.MICROSECONDS);
    }

    public static final long getMicroseconds(double d) {
        return toDuration(d, DurationUnitJvm.MICROSECONDS);
    }

    public static final long getMilliseconds(int i) {
        return toDuration(i, DurationUnitJvm.MILLISECONDS);
    }

    public static final long getMilliseconds(long j) {
        return toDuration(j, DurationUnitJvm.MILLISECONDS);
    }

    public static final long getMilliseconds(double d) {
        return toDuration(d, DurationUnitJvm.MILLISECONDS);
    }

    public static final long getSeconds(int i) {
        return toDuration(i, DurationUnitJvm.SECONDS);
    }

    public static final long getSeconds(long j) {
        return toDuration(j, DurationUnitJvm.SECONDS);
    }

    public static final long getSeconds(double d) {
        return toDuration(d, DurationUnitJvm.SECONDS);
    }

    public static final long getMinutes(int i) {
        return toDuration(i, DurationUnitJvm.MINUTES);
    }

    public static final long getMinutes(long j) {
        return toDuration(j, DurationUnitJvm.MINUTES);
    }

    public static final long getMinutes(double d) {
        return toDuration(d, DurationUnitJvm.MINUTES);
    }

    public static final long getHours(int i) {
        return toDuration(i, DurationUnitJvm.HOURS);
    }

    public static final long getHours(long j) {
        return toDuration(j, DurationUnitJvm.HOURS);
    }

    public static final long getHours(double d) {
        return toDuration(d, DurationUnitJvm.HOURS);
    }

    public static final long getDays(int i) {
        return toDuration(i, DurationUnitJvm.DAYS);
    }

    public static final long getDays(long j) {
        return toDuration(j, DurationUnitJvm.DAYS);
    }

    public static final long getDays(double d) {
        return toDuration(d, DurationUnitJvm.DAYS);
    }

    /* renamed from: times-mvk6XK0 */
    private static final long m1789timesmvk6XK0(int i, long j) {
        return Duration.m1701timesUwyO8pc(j, i);
    }

    /* renamed from: times-kIfJnKk */
    private static final long m1788timeskIfJnKk(double d, long j) {
        return Duration.m1700timesUwyO8pc(j, d);
    }

    public static final long parseDuration(String str, boolean z) {
        boolean z2;
        DurationUnitJvm durationUnitJvm;
        int i;
        int i2;
        boolean z3;
        boolean z4;
        String str2 = str;
        int length = str.length();
        if (length == 0) {
            throw new IllegalArgumentException("The string is empty");
        }
        long m1765getZEROUwyO8pc = Duration.Companion.m1765getZEROUwyO8pc();
        char charAt = str2.charAt(0);
        int i3 = (charAt == '+' || charAt == '-') ? 1 : 0;
        boolean z5 = i3 > 0;
        boolean z6 = z5 && StringsKt.startsWith$default((CharSequence) str2, '-', false, 2, (Object) null);
        if (length <= i3) {
            throw new IllegalArgumentException("No components");
        }
        char c = '9';
        char c2 = '0';
        if (str2.charAt(i3) == 'P') {
            int i4 = i3 + 1;
            if (i4 == length) {
                throw new IllegalArgumentException();
            }
            boolean z7 = false;
            DurationUnitJvm durationUnitJvm2 = null;
            while (i4 < length) {
                if (str2.charAt(i4) != 'T') {
                    int i5 = i4;
                    while (true) {
                        if (i5 >= str.length()) {
                            i2 = length;
                            z3 = z6;
                            break;
                        }
                        char charAt2 = str2.charAt(i5);
                        z3 = z6;
                        if (!new PrimitiveRanges(c2, c).contains(charAt2)) {
                            i2 = length;
                            if (!StringsKt.contains$default((CharSequence) "+-.", charAt2, false, 2, (Object) null)) {
                                break;
                            }
                        } else {
                            i2 = length;
                        }
                        i5++;
                        length = i2;
                        z6 = z3;
                        c2 = '0';
                        c = '9';
                    }
                    Intrinsics.checkNotNull(str2, "null cannot be cast to non-null type java.lang.String");
                    String substring = str2.substring(i4, i5);
                    Intrinsics.checkNotNullExpressionValue(substring, "this as java.lang.String…ing(startIndex, endIndex)");
                    String str3 = substring;
                    if (str3.length() == 0) {
                        throw new IllegalArgumentException();
                    }
                    int length2 = i4 + substring.length();
                    String str4 = str2;
                    if (length2 < 0 || length2 > StringsKt.getLastIndex(str4)) {
                        throw new IllegalArgumentException("Missing unit for value " + substring);
                    }
                    char charAt3 = str4.charAt(length2);
                    i4 = length2 + 1;
                    DurationUnitJvm durationUnitByIsoChar = DurationUnitKt.durationUnitByIsoChar(charAt3, z7);
                    if (durationUnitJvm2 != null && durationUnitJvm2.compareTo(durationUnitByIsoChar) <= 0) {
                        throw new IllegalArgumentException("Unexpected order of duration components");
                    }
                    int indexOf$default = StringsKt.indexOf$default((CharSequence) str3, '.', 0, false, 6, (Object) null);
                    if (durationUnitByIsoChar == DurationUnitJvm.SECONDS && indexOf$default > 0) {
                        Intrinsics.checkNotNull(substring, "null cannot be cast to non-null type java.lang.String");
                        String substring2 = substring.substring(0, indexOf$default);
                        Intrinsics.checkNotNullExpressionValue(substring2, "this as java.lang.String…ing(startIndex, endIndex)");
                        z4 = z7;
                        long m1699plusLRDsOJo = Duration.m1699plusLRDsOJo(m1765getZEROUwyO8pc, toDuration(parseOverLongIsoComponent(substring2), durationUnitByIsoChar));
                        Intrinsics.checkNotNull(substring, "null cannot be cast to non-null type java.lang.String");
                        String substring3 = substring.substring(indexOf$default);
                        Intrinsics.checkNotNullExpressionValue(substring3, "this as java.lang.String).substring(startIndex)");
                        m1765getZEROUwyO8pc = Duration.m1699plusLRDsOJo(m1699plusLRDsOJo, toDuration(Double.parseDouble(substring3), durationUnitByIsoChar));
                    } else {
                        z4 = z7;
                        m1765getZEROUwyO8pc = Duration.m1699plusLRDsOJo(m1765getZEROUwyO8pc, toDuration(parseOverLongIsoComponent(substring), durationUnitByIsoChar));
                    }
                    z7 = z4;
                    durationUnitJvm2 = durationUnitByIsoChar;
                    length = i2;
                    z6 = z3;
                    c2 = '0';
                    c = '9';
                } else if (z7 || (i4 = i4 + 1) == length) {
                    throw new IllegalArgumentException();
                } else {
                    z7 = true;
                }
            }
            z2 = z6;
        } else {
            z2 = z6;
            if (z) {
                throw new IllegalArgumentException();
            }
            String str5 = "Unexpected order of duration components";
            if (StringsKt.regionMatches(str, i3, "Infinity", 0, Math.max(length - i3, "Infinity".length()), true)) {
                m1765getZEROUwyO8pc = Duration.Companion.m1763getINFINITEUwyO8pc();
            } else {
                boolean z8 = !z5;
                if (z5 && str2.charAt(i3) == '(' && StringsKt.last(str2) == ')') {
                    i3++;
                    int i6 = length - 1;
                    if (i3 == i6) {
                        throw new IllegalArgumentException("No components");
                    }
                    i = i6;
                    durationUnitJvm = null;
                    z8 = true;
                } else {
                    durationUnitJvm = null;
                    i = length;
                }
                boolean z9 = false;
                while (i3 < i) {
                    if (z9 && z8) {
                        while (i3 < str.length() && str2.charAt(i3) == ' ') {
                            i3++;
                        }
                    }
                    int i7 = i3;
                    while (i7 < str.length()) {
                        char charAt4 = str2.charAt(i7);
                        if (!new PrimitiveRanges('0', '9').contains(charAt4) && charAt4 != '.') {
                            break;
                        }
                        i7++;
                    }
                    Intrinsics.checkNotNull(str2, "null cannot be cast to non-null type java.lang.String");
                    String substring4 = str2.substring(i3, i7);
                    Intrinsics.checkNotNullExpressionValue(substring4, "this as java.lang.String…ing(startIndex, endIndex)");
                    String str6 = substring4;
                    if (str6.length() == 0) {
                        throw new IllegalArgumentException();
                    }
                    int length3 = i3 + substring4.length();
                    int i8 = length3;
                    while (i8 < str.length()) {
                        if (!new PrimitiveRanges('a', 'z').contains(str2.charAt(i8))) {
                            break;
                        }
                        i8++;
                    }
                    Intrinsics.checkNotNull(str2, "null cannot be cast to non-null type java.lang.String");
                    String substring5 = str2.substring(length3, i8);
                    Intrinsics.checkNotNullExpressionValue(substring5, "this as java.lang.String…ing(startIndex, endIndex)");
                    i3 = length3 + substring5.length();
                    DurationUnitJvm durationUnitByShortName = DurationUnitKt.durationUnitByShortName(substring5);
                    if (durationUnitJvm != null && durationUnitJvm.compareTo(durationUnitByShortName) <= 0) {
                        throw new IllegalArgumentException(str5);
                    }
                    String str7 = str5;
                    int indexOf$default2 = StringsKt.indexOf$default((CharSequence) str6, '.', 0, false, 6, (Object) null);
                    if (indexOf$default2 > 0) {
                        Intrinsics.checkNotNull(substring4, "null cannot be cast to non-null type java.lang.String");
                        String substring6 = substring4.substring(0, indexOf$default2);
                        Intrinsics.checkNotNullExpressionValue(substring6, "this as java.lang.String…ing(startIndex, endIndex)");
                        long m1699plusLRDsOJo2 = Duration.m1699plusLRDsOJo(m1765getZEROUwyO8pc, toDuration(Long.parseLong(substring6), durationUnitByShortName));
                        Intrinsics.checkNotNull(substring4, "null cannot be cast to non-null type java.lang.String");
                        String substring7 = substring4.substring(indexOf$default2);
                        Intrinsics.checkNotNullExpressionValue(substring7, "this as java.lang.String).substring(startIndex)");
                        m1765getZEROUwyO8pc = Duration.m1699plusLRDsOJo(m1699plusLRDsOJo2, toDuration(Double.parseDouble(substring7), durationUnitByShortName));
                        if (i3 < i) {
                            throw new IllegalArgumentException("Fractional component must be last");
                        }
                    } else {
                        m1765getZEROUwyO8pc = Duration.m1699plusLRDsOJo(m1765getZEROUwyO8pc, toDuration(Long.parseLong(substring4), durationUnitByShortName));
                    }
                    str2 = str;
                    str5 = str7;
                    durationUnitJvm = durationUnitByShortName;
                    z9 = true;
                }
            }
        }
        return z2 ? Duration.m1715unaryMinusUwyO8pc(m1765getZEROUwyO8pc) : m1765getZEROUwyO8pc;
    }

    /* JADX WARN: Removed duplicated region for block: B:62:0x007a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    private static final long parseOverLongIsoComponent(java.lang.String r9) {
        /*
            int r0 = r9.length()
            r1 = 1
            r2 = 0
            r3 = 2
            r4 = 0
            if (r0 <= 0) goto L1a
            java.lang.String r5 = "+-"
            java.lang.CharSequence r5 = (java.lang.CharSequence) r5
            char r6 = r9.charAt(r4)
            boolean r5 = kotlin.text.StringsKt.contains$default(r5, r6, r4, r3, r2)
            if (r5 == 0) goto L1a
            r5 = r1
            goto L1b
        L1a:
            r5 = r4
        L1b:
            int r0 = r0 - r5
            r6 = 16
            if (r0 <= r6) goto L72
            kotlin.ranges.IntRange r0 = new kotlin.ranges.IntRange
            r6 = r9
            java.lang.CharSequence r6 = (java.lang.CharSequence) r6
            int r6 = kotlin.text.StringsKt.getLastIndex(r6)
            r0.<init>(r5, r6)
            java.lang.Iterable r0 = (java.lang.Iterable) r0
            boolean r5 = r0 instanceof java.util.Collection
            if (r5 == 0) goto L3c
            r5 = r0
            java.util.Collection r5 = (java.util.Collection) r5
            boolean r5 = r5.isEmpty()
            if (r5 == 0) goto L3c
            goto L61
        L3c:
            java.util.Iterator r0 = r0.iterator()
        L40:
            boolean r5 = r0.hasNext()
            if (r5 == 0) goto L61
            r5 = r0
            kotlin.collections.IntIterator r5 = (kotlin.collections.IntIterator) r5
            int r5 = r5.nextInt()
            kotlin.ranges.CharRange r6 = new kotlin.ranges.CharRange
            r7 = 48
            r8 = 57
            r6.<init>(r7, r8)
            char r5 = r9.charAt(r5)
            boolean r5 = r6.contains(r5)
            if (r5 != 0) goto L40
            goto L72
        L61:
            char r9 = r9.charAt(r4)
            r0 = 45
            if (r9 != r0) goto L6c
            r0 = -9223372036854775808
            goto L71
        L6c:
            r0 = 9223372036854775807(0x7fffffffffffffff, double:NaN)
        L71:
            return r0
        L72:
            java.lang.String r0 = "+"
            boolean r0 = kotlin.text.StringsKt.startsWith$default(r9, r0, r4, r3, r2)
            if (r0 == 0) goto L7e
            java.lang.String r9 = kotlin.text.StringsKt.drop(r9, r1)
        L7e:
            long r0 = java.lang.Long.parseLong(r9)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlin.time.DurationKt.parseOverLongIsoComponent(java.lang.String):long");
    }

    private static final int skipWhile(String str, int i, Function1<? super Character, Boolean> function1) {
        while (i < str.length() && function1.invoke(Character.valueOf(str.charAt(i))).booleanValue()) {
            i++;
        }
        return i;
    }

    public static final long nanosToMillis(long j) {
        return j / ((long) NANOS_IN_MILLIS);
    }

    public static final long durationOfNanos(long j) {
        return Duration.m1663constructorimpl(j << 1);
    }

    public static final long durationOfMillis(long j) {
        return Duration.m1663constructorimpl((j << 1) + 1);
    }

    public static final long durationOf(long j, int i) {
        return Duration.m1663constructorimpl((j << 1) + i);
    }

    public static final long durationOfNanosNormalized(long j) {
        if (new LongRange(-4611686018426999999L, MAX_NANOS).contains(j)) {
            return durationOfNanos(j);
        }
        return durationOfMillis(nanosToMillis(j));
    }

    public static final long durationOfMillisNormalized(long j) {
        if (new LongRange(-4611686018426L, MAX_NANOS_IN_MILLIS).contains(j)) {
            return durationOfNanos(millisToNanos(j));
        }
        return durationOfMillis(RangesKt.coerceIn(j, -4611686018427387903L, (long) MAX_MILLIS));
    }

    private static final String substringWhile(String str, int i, Function1<? super Character, Boolean> function1) {
        int i2 = i;
        while (i2 < str.length() && function1.invoke(Character.valueOf(str.charAt(i2))).booleanValue()) {
            i2++;
        }
        Intrinsics.checkNotNull(str, "null cannot be cast to non-null type java.lang.String");
        String substring = str.substring(i, i2);
        Intrinsics.checkNotNullExpressionValue(substring, "this as java.lang.String…ing(startIndex, endIndex)");
        return substring;
    }
}