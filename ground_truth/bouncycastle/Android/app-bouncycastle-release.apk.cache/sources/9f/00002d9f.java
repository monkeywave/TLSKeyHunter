package org.bouncycastle.tls;

/* loaded from: classes2.dex */
public class TlsFatalAlert extends TlsException {
    protected short alertDescription;

    public TlsFatalAlert(short s) {
        this(s, (String) null);
    }

    public TlsFatalAlert(short s, String str) {
        this(s, str, null);
    }

    public TlsFatalAlert(short s, String str, Throwable th) {
        super(getMessage(s, str), th);
        this.alertDescription = s;
    }

    public TlsFatalAlert(short s, Throwable th) {
        this(s, null, th);
    }

    private static String getMessage(short s, String str) {
        String text = AlertDescription.getText(s);
        return str != null ? text + "; " + str : text;
    }

    public short getAlertDescription() {
        return this.alertDescription;
    }
}