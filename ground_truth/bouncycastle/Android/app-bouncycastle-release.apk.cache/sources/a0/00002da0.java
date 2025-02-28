package org.bouncycastle.tls;

/* loaded from: classes2.dex */
public class TlsFatalAlertReceived extends TlsException {
    protected short alertDescription;

    public TlsFatalAlertReceived(short s) {
        super(AlertDescription.getText(s));
        this.alertDescription = s;
    }

    public short getAlertDescription() {
        return this.alertDescription;
    }
}