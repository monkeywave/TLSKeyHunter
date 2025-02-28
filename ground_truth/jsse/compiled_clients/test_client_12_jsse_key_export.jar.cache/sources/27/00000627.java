package org.bouncycastle.i18n;

import java.io.UnsupportedEncodingException;
import java.util.Locale;
import java.util.TimeZone;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/i18n/TextBundle.class */
public class TextBundle extends LocalizedMessage {
    public static final String TEXT_ENTRY = "text";

    public TextBundle(String str, String str2) throws NullPointerException {
        super(str, str2);
    }

    public TextBundle(String str, String str2, String str3) throws NullPointerException, UnsupportedEncodingException {
        super(str, str2, str3);
    }

    public TextBundle(String str, String str2, Object[] objArr) throws NullPointerException {
        super(str, str2, objArr);
    }

    public TextBundle(String str, String str2, String str3, Object[] objArr) throws NullPointerException, UnsupportedEncodingException {
        super(str, str2, str3, objArr);
    }

    public String getText(Locale locale, TimeZone timeZone) throws MissingEntryException {
        return getEntry(TEXT_ENTRY, locale, timeZone);
    }

    public String getText(Locale locale) throws MissingEntryException {
        return getEntry(TEXT_ENTRY, locale, TimeZone.getDefault());
    }
}