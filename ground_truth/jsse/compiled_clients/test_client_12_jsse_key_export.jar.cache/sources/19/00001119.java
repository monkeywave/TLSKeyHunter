package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/RandomCookie.class */
final class RandomCookie {
    final byte[] randomBytes;
    private static final byte[] hrrRandomBytes = {-49, 33, -83, 116, -27, -102, 97, 17, -66, 29, -116, 2, 30, 101, -72, -111, -62, -94, 17, 22, 122, -69, -116, 94, 7, -98, 9, -30, -56, -88, 51, -100};
    private static final byte[] t12Protection = {68, 79, 87, 78, 71, 82, 68, 1};
    private static final byte[] t11Protection = {68, 79, 87, 78, 71, 82, 68, 0};
    static final RandomCookie hrrRandom = new RandomCookie(hrrRandomBytes);

    /* JADX INFO: Access modifiers changed from: package-private */
    public RandomCookie(SecureRandom generator) {
        this.randomBytes = new byte[32];
        generator.nextBytes(this.randomBytes);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public RandomCookie(HandshakeContext context) {
        this.randomBytes = new byte[32];
        SecureRandom generator = context.sslContext.getSecureRandom();
        generator.nextBytes(this.randomBytes);
        byte[] protection = null;
        if (context.maximumActiveProtocol.useTLS13PlusSpec()) {
            if (!context.negotiatedProtocol.useTLS13PlusSpec()) {
                protection = context.negotiatedProtocol.useTLS12PlusSpec() ? t12Protection : t11Protection;
            }
        } else if (context.maximumActiveProtocol.useTLS12PlusSpec() && !context.negotiatedProtocol.useTLS12PlusSpec()) {
            protection = t11Protection;
        }
        if (protection != null) {
            System.arraycopy(protection, 0, this.randomBytes, this.randomBytes.length - protection.length, protection.length);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public RandomCookie(ByteBuffer m) throws IOException {
        this.randomBytes = new byte[32];
        m.get(this.randomBytes);
    }

    private RandomCookie(byte[] randomBytes) {
        this.randomBytes = new byte[32];
        System.arraycopy(randomBytes, 0, this.randomBytes, 0, 32);
    }

    public String toString() {
        return "random_bytes = {" + Utilities.toHexString(this.randomBytes) + "}";
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isHelloRetryRequest() {
        return Arrays.equals(hrrRandomBytes, this.randomBytes);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isVersionDowngrade(HandshakeContext context) {
        if (context.maximumActiveProtocol.useTLS13PlusSpec()) {
            if (context.negotiatedProtocol.useTLS13PlusSpec()) {
                return false;
            }
            return isT12Downgrade() || isT11Downgrade();
        } else if (context.maximumActiveProtocol.useTLS12PlusSpec() && !context.negotiatedProtocol.useTLS12PlusSpec()) {
            return isT11Downgrade();
        } else {
            return false;
        }
    }

    private boolean isT12Downgrade() {
        return Utilities.equals(this.randomBytes, 24, 32, t12Protection, 0, 8);
    }

    private boolean isT11Downgrade() {
        return Utilities.equals(this.randomBytes, 24, 32, t11Protection, 0, 8);
    }
}