package org.openjsse.sun.security.ssl;

import java.io.EOFException;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketException;
import java.nio.ByteBuffer;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.net.ssl.SSLHandshakeException;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SSLTransport.class */
public interface SSLTransport {
    String getPeerHost();

    int getPeerPort();

    boolean useDelegatedTask();

    default void shutdown() throws IOException {
    }

    static Plaintext decode(TransportContext context, ByteBuffer[] srcs, int srcsOffset, int srcsLength, ByteBuffer[] dsts, int dstsOffset, int dstsLength) throws IOException {
        try {
            Plaintext[] plaintexts = context.inputRecord.decode(srcs, srcsOffset, srcsLength);
            if (plaintexts == null || plaintexts.length == 0) {
                return Plaintext.PLAINTEXT_NULL;
            }
            Plaintext finalPlaintext = Plaintext.PLAINTEXT_NULL;
            for (Plaintext plainText : plaintexts) {
                if (plainText == Plaintext.PLAINTEXT_NULL) {
                    if (context.handshakeContext != null && context.handshakeContext.sslConfig.enableRetransmissions && context.sslContext.isDTLS()) {
                        if (SSLLogger.isOn && SSLLogger.isOn("ssl,verbose")) {
                            SSLLogger.finest("retransmited handshake flight", new Object[0]);
                        }
                        context.outputRecord.launchRetransmission();
                    }
                } else if (plainText != null && plainText.contentType != ContentType.APPLICATION_DATA.f965id) {
                    context.dispatch(plainText);
                }
                if (plainText == null) {
                    plainText = Plaintext.PLAINTEXT_NULL;
                } else if (plainText.contentType != ContentType.APPLICATION_DATA.f965id) {
                    continue;
                } else if (!context.isNegotiated) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,verbose")) {
                        SSLLogger.warning("unexpected application data before handshake completion", new Object[0]);
                    }
                    throw context.fatal(Alert.UNEXPECTED_MESSAGE, "Receiving application data before handshake complete");
                } else if (dsts != null && dstsLength > 0) {
                    ByteBuffer fragment = plainText.fragment;
                    int remains = fragment.remaining();
                    int limit = dstsOffset + dstsLength;
                    for (int i = dstsOffset; i < limit && remains > 0; i++) {
                        int amount = Math.min(dsts[i].remaining(), remains);
                        fragment.limit(fragment.position() + amount);
                        dsts[i].put(fragment);
                        remains -= amount;
                        if (!dsts[i].hasRemaining()) {
                            dstsOffset++;
                        }
                    }
                    if (remains > 0) {
                        throw context.fatal(Alert.INTERNAL_ERROR, "no sufficient room in the destination buffers");
                    }
                }
                finalPlaintext = plainText;
            }
            return finalPlaintext;
        } catch (EOFException eofe) {
            throw eofe;
        } catch (InterruptedIOException | SocketException se) {
            throw se;
        } catch (IOException ioe) {
            throw context.fatal(Alert.UNEXPECTED_MESSAGE, ioe);
        } catch (UnsupportedOperationException unsoe) {
            if (!context.sslContext.isDTLS()) {
                context.outputRecord.encodeV2NoCipher();
                if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.finest("may be talking to SSLv2", new Object[0]);
                }
            }
            throw context.fatal(Alert.UNEXPECTED_MESSAGE, unsoe);
        } catch (AEADBadTagException bte) {
            throw context.fatal(Alert.BAD_RECORD_MAC, bte);
        } catch (BadPaddingException bpe) {
            Alert alert = context.handshakeContext != null ? Alert.HANDSHAKE_FAILURE : Alert.BAD_RECORD_MAC;
            throw context.fatal(alert, bpe);
        } catch (SSLHandshakeException she) {
            throw context.fatal(Alert.HANDSHAKE_FAILURE, she);
        }
    }
}