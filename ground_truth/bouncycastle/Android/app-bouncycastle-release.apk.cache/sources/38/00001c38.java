package org.bouncycastle.crypto;

/* loaded from: classes.dex */
public interface CryptoServiceProperties {
    int bitsOfSecurity();

    Object getParams();

    CryptoServicePurpose getPurpose();

    String getServiceName();
}