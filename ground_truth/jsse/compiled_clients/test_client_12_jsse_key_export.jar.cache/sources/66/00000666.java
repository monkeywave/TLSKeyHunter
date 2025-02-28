package org.bouncycastle.jcajce.p006io;

import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Mac;

/* renamed from: org.bouncycastle.jcajce.io.OutputStreamFactory */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/io/OutputStreamFactory.class */
public class OutputStreamFactory {
    public static OutputStream createStream(Signature signature) {
        return new SignatureUpdatingOutputStream(signature);
    }

    public static OutputStream createStream(MessageDigest messageDigest) {
        return new DigestUpdatingOutputStream(messageDigest);
    }

    public static OutputStream createStream(Mac mac) {
        return new MacUpdatingOutputStream(mac);
    }
}