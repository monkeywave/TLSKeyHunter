package org.bouncycastle.jcajce.p012io;

import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Mac;

/* renamed from: org.bouncycastle.jcajce.io.OutputStreamFactory */
/* loaded from: classes2.dex */
public class OutputStreamFactory {
    public static OutputStream createStream(MessageDigest messageDigest) {
        return new DigestUpdatingOutputStream(messageDigest);
    }

    public static OutputStream createStream(Signature signature) {
        return new SignatureUpdatingOutputStream(signature);
    }

    public static OutputStream createStream(Mac mac) {
        return new MacUpdatingOutputStream(mac);
    }
}