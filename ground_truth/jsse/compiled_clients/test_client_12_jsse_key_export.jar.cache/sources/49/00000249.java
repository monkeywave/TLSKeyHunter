package org.bouncycastle.asn1;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/DateUtil.class */
class DateUtil {
    private static Long ZERO = longValueOf(0);
    private static final Map localeCache = new HashMap();
    static Locale EN_Locale = forEN();

    DateUtil() {
    }

    private static Locale forEN() {
        if ("en".equalsIgnoreCase(Locale.getDefault().getLanguage())) {
            return Locale.getDefault();
        }
        Locale[] availableLocales = Locale.getAvailableLocales();
        for (int i = 0; i != availableLocales.length; i++) {
            if ("en".equalsIgnoreCase(availableLocales[i].getLanguage())) {
                return availableLocales[i];
            }
        }
        return Locale.getDefault();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Date epochAdjust(Date date) throws ParseException {
        Locale locale = Locale.getDefault();
        if (locale == null) {
            return date;
        }
        synchronized (localeCache) {
            Long l = (Long) localeCache.get(locale);
            if (l == null) {
                long time = new SimpleDateFormat("yyyyMMddHHmmssz").parse("19700101000000GMT+00:00").getTime();
                l = time == 0 ? ZERO : longValueOf(time);
                localeCache.put(locale, l);
            }
            if (l != ZERO) {
                return new Date(date.getTime() - l.longValue());
            }
            return date;
        }
    }

    private static Long longValueOf(long j) {
        return Long.valueOf(j);
    }
}