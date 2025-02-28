package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.openjsse.sun.security.ssl.ClientHello;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HelloCookieManager.class */
public abstract class HelloCookieManager {
    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract byte[] createCookie(ServerHandshakeContext serverHandshakeContext, ClientHello.ClientHelloMessage clientHelloMessage) throws IOException;

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract boolean isCookieValid(ServerHandshakeContext serverHandshakeContext, ClientHello.ClientHelloMessage clientHelloMessage, byte[] bArr) throws IOException;

    HelloCookieManager() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HelloCookieManager$Builder.class */
    public static class Builder {
        final SecureRandom secureRandom;
        private volatile D10HelloCookieManager d10HelloCookieManager;
        private volatile D13HelloCookieManager d13HelloCookieManager;
        private volatile T13HelloCookieManager t13HelloCookieManager;

        /* JADX INFO: Access modifiers changed from: package-private */
        public Builder(SecureRandom secureRandom) {
            this.secureRandom = secureRandom;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public HelloCookieManager valueOf(ProtocolVersion protocolVersion) {
            if (protocolVersion.isDTLS) {
                if (protocolVersion.useTLS13PlusSpec()) {
                    if (this.d13HelloCookieManager != null) {
                        return this.d13HelloCookieManager;
                    }
                    synchronized (this) {
                        if (this.d13HelloCookieManager == null) {
                            this.d13HelloCookieManager = new D13HelloCookieManager(this.secureRandom);
                        }
                    }
                    return this.d13HelloCookieManager;
                } else if (this.d10HelloCookieManager != null) {
                    return this.d10HelloCookieManager;
                } else {
                    synchronized (this) {
                        if (this.d10HelloCookieManager == null) {
                            this.d10HelloCookieManager = new D10HelloCookieManager(this.secureRandom);
                        }
                    }
                    return this.d10HelloCookieManager;
                }
            } else if (protocolVersion.useTLS13PlusSpec()) {
                if (this.t13HelloCookieManager != null) {
                    return this.t13HelloCookieManager;
                }
                synchronized (this) {
                    if (this.t13HelloCookieManager == null) {
                        this.t13HelloCookieManager = new T13HelloCookieManager(this.secureRandom);
                    }
                }
                return this.t13HelloCookieManager;
            } else {
                return null;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HelloCookieManager$D10HelloCookieManager.class */
    public static final class D10HelloCookieManager extends HelloCookieManager {
        final SecureRandom secureRandom;
        private int cookieVersion;
        private byte[] cookieSecret = new byte[32];
        private byte[] legacySecret = new byte[32];

        D10HelloCookieManager(SecureRandom secureRandom) {
            this.secureRandom = secureRandom;
            this.cookieVersion = secureRandom.nextInt();
            secureRandom.nextBytes(this.cookieSecret);
            System.arraycopy(this.cookieSecret, 0, this.legacySecret, 0, 32);
        }

        @Override // org.openjsse.sun.security.ssl.HelloCookieManager
        byte[] createCookie(ServerHandshakeContext context, ClientHello.ClientHelloMessage clientHello) throws IOException {
            int version;
            byte[] secret;
            synchronized (this) {
                version = this.cookieVersion;
                secret = this.cookieSecret;
                if ((this.cookieVersion & 16777215) == 0) {
                    System.arraycopy(this.cookieSecret, 0, this.legacySecret, 0, 32);
                    this.secureRandom.nextBytes(this.cookieSecret);
                }
                this.cookieVersion++;
            }
            MessageDigest md = JsseJce.getMessageDigest("SHA-256");
            byte[] helloBytes = clientHello.getHelloCookieBytes();
            md.update(helloBytes);
            byte[] cookie = md.digest(secret);
            cookie[0] = (byte) ((version >> 24) & GF2Field.MASK);
            return cookie;
        }

        @Override // org.openjsse.sun.security.ssl.HelloCookieManager
        boolean isCookieValid(ServerHandshakeContext context, ClientHello.ClientHelloMessage clientHello, byte[] cookie) throws IOException {
            byte[] secret;
            if (cookie == null || cookie.length != 32) {
                return false;
            }
            synchronized (this) {
                if (((this.cookieVersion >> 24) & GF2Field.MASK) == cookie[0]) {
                    secret = this.cookieSecret;
                } else {
                    secret = this.legacySecret;
                }
            }
            MessageDigest md = JsseJce.getMessageDigest("SHA-256");
            byte[] helloBytes = clientHello.getHelloCookieBytes();
            md.update(helloBytes);
            byte[] target = md.digest(secret);
            target[0] = cookie[0];
            return Arrays.equals(target, cookie);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HelloCookieManager$D13HelloCookieManager.class */
    public static final class D13HelloCookieManager extends HelloCookieManager {
        D13HelloCookieManager(SecureRandom secureRandom) {
        }

        @Override // org.openjsse.sun.security.ssl.HelloCookieManager
        byte[] createCookie(ServerHandshakeContext context, ClientHello.ClientHelloMessage clientHello) throws IOException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override // org.openjsse.sun.security.ssl.HelloCookieManager
        boolean isCookieValid(ServerHandshakeContext context, ClientHello.ClientHelloMessage clientHello, byte[] cookie) throws IOException {
            throw new UnsupportedOperationException("Not supported yet.");
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HelloCookieManager$T13HelloCookieManager.class */
    public static final class T13HelloCookieManager extends HelloCookieManager {
        final SecureRandom secureRandom;
        private int cookieVersion;
        private final byte[] cookieSecret = new byte[64];
        private final byte[] legacySecret = new byte[64];

        T13HelloCookieManager(SecureRandom secureRandom) {
            this.secureRandom = secureRandom;
            this.cookieVersion = secureRandom.nextInt();
            secureRandom.nextBytes(this.cookieSecret);
            System.arraycopy(this.cookieSecret, 0, this.legacySecret, 0, 64);
        }

        @Override // org.openjsse.sun.security.ssl.HelloCookieManager
        byte[] createCookie(ServerHandshakeContext context, ClientHello.ClientHelloMessage clientHello) throws IOException {
            int version;
            byte[] secret;
            synchronized (this) {
                version = this.cookieVersion;
                secret = this.cookieSecret;
                if ((this.cookieVersion & 16777215) == 0) {
                    System.arraycopy(this.cookieSecret, 0, this.legacySecret, 0, 64);
                    this.secureRandom.nextBytes(this.cookieSecret);
                }
                this.cookieVersion++;
            }
            MessageDigest md = JsseJce.getMessageDigest(context.negotiatedCipherSuite.hashAlg.name);
            byte[] headerBytes = clientHello.getHeaderBytes();
            md.update(headerBytes);
            byte[] headerCookie = md.digest(secret);
            context.handshakeHash.update();
            byte[] clientHelloHash = context.handshakeHash.digest();
            byte[] prefix = {(byte) ((context.negotiatedCipherSuite.f964id >> 8) & GF2Field.MASK), (byte) (context.negotiatedCipherSuite.f964id & GF2Field.MASK), (byte) ((version >> 24) & GF2Field.MASK)};
            byte[] cookie = Arrays.copyOf(prefix, prefix.length + headerCookie.length + clientHelloHash.length);
            System.arraycopy(headerCookie, 0, cookie, prefix.length, headerCookie.length);
            System.arraycopy(clientHelloHash, 0, cookie, prefix.length + headerCookie.length, clientHelloHash.length);
            return cookie;
        }

        @Override // org.openjsse.sun.security.ssl.HelloCookieManager
        boolean isCookieValid(ServerHandshakeContext context, ClientHello.ClientHelloMessage clientHello, byte[] cookie) throws IOException {
            byte[] secret;
            if (cookie == null || cookie.length <= 32) {
                return false;
            }
            int csId = ((cookie[0] & 255) << 8) | (cookie[1] & 255);
            CipherSuite cs = CipherSuite.valueOf(csId);
            if (cs == null || cs.hashAlg == null || cs.hashAlg.hashLength == 0) {
                return false;
            }
            int hashLen = cs.hashAlg.hashLength;
            if (cookie.length != 3 + (hashLen * 2)) {
                return false;
            }
            byte[] prevHeadCookie = Arrays.copyOfRange(cookie, 3, 3 + hashLen);
            byte[] prevClientHelloHash = Arrays.copyOfRange(cookie, 3 + hashLen, cookie.length);
            synchronized (this) {
                if (((byte) ((this.cookieVersion >> 24) & GF2Field.MASK)) == cookie[2]) {
                    secret = this.cookieSecret;
                } else {
                    secret = this.legacySecret;
                }
            }
            MessageDigest md = JsseJce.getMessageDigest(cs.hashAlg.name);
            byte[] headerBytes = clientHello.getHeaderBytes();
            md.update(headerBytes);
            byte[] headerCookie = md.digest(secret);
            if (!Arrays.equals(headerCookie, prevHeadCookie)) {
                return false;
            }
            byte[] hrrMessage = ServerHello.hrrReproducer.produce(context, clientHello);
            context.handshakeHash.push(hrrMessage);
            byte[] hashedClientHello = new byte[4 + hashLen];
            hashedClientHello[0] = SSLHandshake.MESSAGE_HASH.f987id;
            hashedClientHello[1] = 0;
            hashedClientHello[2] = 0;
            hashedClientHello[3] = (byte) (hashLen & GF2Field.MASK);
            System.arraycopy(prevClientHelloHash, 0, hashedClientHello, 4, hashLen);
            context.handshakeHash.push(hashedClientHello);
            return true;
        }
    }
}