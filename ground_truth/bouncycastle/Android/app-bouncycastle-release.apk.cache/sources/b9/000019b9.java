package org.bouncycastle.asn1;

import java.util.Date;

/* loaded from: classes.dex */
public class DERUTCTime extends ASN1UTCTime {
    public DERUTCTime(String str) {
        super(str);
    }

    public DERUTCTime(Date date) {
        super(date);
    }

    DERUTCTime(byte[] bArr) {
        super(bArr);
    }
}