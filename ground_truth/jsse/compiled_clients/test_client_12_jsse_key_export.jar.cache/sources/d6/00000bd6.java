package org.bouncycastle.jce.provider;

import java.util.Date;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/provider/CertStatus.class */
class CertStatus {
    public static final int UNREVOKED = 11;
    public static final int UNDETERMINED = 12;
    int certStatus = 11;
    Date revocationDate = null;

    public Date getRevocationDate() {
        return this.revocationDate;
    }

    public void setRevocationDate(Date date) {
        this.revocationDate = date;
    }

    public int getCertStatus() {
        return this.certStatus;
    }

    public void setCertStatus(int i) {
        this.certStatus = i;
    }
}