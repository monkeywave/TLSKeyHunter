package org.bouncycastle.tls;

import androidx.core.view.ViewCompat;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import org.bouncycastle.tls.SessionParameters;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

/* loaded from: classes2.dex */
public abstract class TlsProtocol implements TlsCloseable {
    protected static final short ADS_MODE_0_N = 1;
    protected static final short ADS_MODE_0_N_FIRSTONLY = 2;
    protected static final short ADS_MODE_1_Nsub1 = 0;
    protected static final short CS_CLIENT_CERTIFICATE = 15;
    protected static final short CS_CLIENT_CERTIFICATE_VERIFY = 17;
    protected static final short CS_CLIENT_END_OF_EARLY_DATA = 13;
    protected static final short CS_CLIENT_FINISHED = 18;
    protected static final short CS_CLIENT_HELLO = 1;
    protected static final short CS_CLIENT_HELLO_RETRY = 3;
    protected static final short CS_CLIENT_KEY_EXCHANGE = 16;
    protected static final short CS_CLIENT_SUPPLEMENTAL_DATA = 14;
    protected static final short CS_END = 21;
    protected static final short CS_SERVER_CERTIFICATE = 7;
    protected static final short CS_SERVER_CERTIFICATE_REQUEST = 11;
    protected static final short CS_SERVER_CERTIFICATE_STATUS = 8;
    protected static final short CS_SERVER_CERTIFICATE_VERIFY = 9;
    protected static final short CS_SERVER_ENCRYPTED_EXTENSIONS = 5;
    protected static final short CS_SERVER_FINISHED = 20;
    protected static final short CS_SERVER_HELLO = 4;
    protected static final short CS_SERVER_HELLO_DONE = 12;
    protected static final short CS_SERVER_HELLO_RETRY_REQUEST = 2;
    protected static final short CS_SERVER_KEY_EXCHANGE = 10;
    protected static final short CS_SERVER_SESSION_TICKET = 19;
    protected static final short CS_SERVER_SUPPLEMENTAL_DATA = 6;
    protected static final short CS_START = 0;
    protected static final Integer EXT_RenegotiationInfo = Integers.valueOf(65281);
    protected static final Integer EXT_SessionTicket = Integers.valueOf(35);
    private ByteQueue alertQueue;
    private volatile boolean appDataReady;
    private volatile boolean appDataSplitEnabled;
    private volatile int appDataSplitMode;
    private ByteQueue applicationDataQueue;
    protected boolean blocking;
    protected Hashtable clientExtensions;
    private volatile boolean closed;
    protected short connection_state;
    protected boolean expectSessionTicket;
    private volatile boolean failedWithError;
    TlsHandshakeHash handshakeHash;
    private ByteQueue handshakeQueue;
    protected ByteQueueInputStream inputBuffers;
    private volatile boolean keyUpdateEnabled;
    private volatile boolean keyUpdatePendingSend;
    private int maxHandshakeMessageSize;
    protected ByteQueueOutputStream outputBuffer;
    protected boolean receivedChangeCipherSpec;
    final RecordStream recordStream;
    final Object recordWriteLock;
    private volatile boolean resumableHandshake;
    protected byte[] retryCookie;
    protected int retryGroup;
    protected boolean selectedPSK13;
    protected Hashtable serverExtensions;
    protected TlsSecret sessionMasterSecret;
    protected SessionParameters sessionParameters;
    private TlsInputStream tlsInputStream;
    private TlsOutputStream tlsOutputStream;
    protected TlsSession tlsSession;

    /* JADX INFO: Access modifiers changed from: protected */
    public TlsProtocol() {
        this.applicationDataQueue = new ByteQueue(0);
        this.alertQueue = new ByteQueue(2);
        this.handshakeQueue = new ByteQueue(0);
        this.recordWriteLock = new Object();
        this.maxHandshakeMessageSize = -1;
        this.tlsInputStream = null;
        this.tlsOutputStream = null;
        this.closed = false;
        this.failedWithError = false;
        this.appDataReady = false;
        this.appDataSplitEnabled = true;
        this.keyUpdateEnabled = false;
        this.keyUpdatePendingSend = false;
        this.resumableHandshake = false;
        this.appDataSplitMode = 0;
        this.tlsSession = null;
        this.sessionParameters = null;
        this.sessionMasterSecret = null;
        this.retryCookie = null;
        this.retryGroup = -1;
        this.clientExtensions = null;
        this.serverExtensions = null;
        this.connection_state = (short) 0;
        this.selectedPSK13 = false;
        this.receivedChangeCipherSpec = false;
        this.expectSessionTicket = false;
        this.blocking = false;
        this.inputBuffers = new ByteQueueInputStream();
        this.outputBuffer = new ByteQueueOutputStream();
        this.recordStream = new RecordStream(this, this.inputBuffers, this.outputBuffer);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public TlsProtocol(InputStream inputStream, OutputStream outputStream) {
        this.applicationDataQueue = new ByteQueue(0);
        this.alertQueue = new ByteQueue(2);
        this.handshakeQueue = new ByteQueue(0);
        this.recordWriteLock = new Object();
        this.maxHandshakeMessageSize = -1;
        this.tlsInputStream = null;
        this.tlsOutputStream = null;
        this.closed = false;
        this.failedWithError = false;
        this.appDataReady = false;
        this.appDataSplitEnabled = true;
        this.keyUpdateEnabled = false;
        this.keyUpdatePendingSend = false;
        this.resumableHandshake = false;
        this.appDataSplitMode = 0;
        this.tlsSession = null;
        this.sessionParameters = null;
        this.sessionMasterSecret = null;
        this.retryCookie = null;
        this.retryGroup = -1;
        this.clientExtensions = null;
        this.serverExtensions = null;
        this.connection_state = (short) 0;
        this.selectedPSK13 = false;
        this.receivedChangeCipherSpec = false;
        this.expectSessionTicket = false;
        this.blocking = true;
        this.recordStream = new RecordStream(this, inputStream, outputStream);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static void assertEmpty(ByteArrayInputStream byteArrayInputStream) throws IOException {
        if (byteArrayInputStream.available() > 0) {
            throw new TlsFatalAlert((short) 50);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static byte[] createRandomBlock(boolean z, TlsContext tlsContext) {
        byte[] generateNonce = tlsContext.getNonceGenerator().generateNonce(32);
        if (z) {
            TlsUtils.writeGMTUnixTime(generateNonce, 0);
        }
        return generateNonce;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static byte[] createRenegotiationInfo(byte[] bArr) throws IOException {
        return TlsUtils.encodeOpaque8(bArr);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static void establishMasterSecret(TlsContext tlsContext, TlsKeyExchange tlsKeyExchange) throws IOException {
        TlsSecret generatePreMasterSecret = tlsKeyExchange.generatePreMasterSecret();
        if (generatePreMasterSecret == null) {
            throw new TlsFatalAlert((short) 80);
        }
        try {
            tlsContext.getSecurityParametersHandshake().masterSecret = TlsUtils.calculateMasterSecret(tlsContext, generatePreMasterSecret);
        } finally {
            generatePreMasterSecret.destroy();
        }
    }

    private void processAlertQueue() throws IOException {
        while (this.alertQueue.available() >= 2) {
            byte[] removeData = this.alertQueue.removeData(2, 0);
            handleAlertMessage(removeData[0], removeData[1]);
        }
    }

    private void processApplicationDataQueue() {
    }

    private void processChangeCipherSpec(byte[] bArr, int i, int i2) throws IOException {
        ProtocolVersion serverVersion = getContext().getServerVersion();
        if (serverVersion == null || TlsUtils.isTLSv13(serverVersion)) {
            throw new TlsFatalAlert((short) 10);
        }
        for (int i3 = 0; i3 < i2; i3++) {
            if (TlsUtils.readUint8(bArr, i + i3) != 1) {
                throw new TlsFatalAlert((short) 50);
            }
            if (this.receivedChangeCipherSpec || this.alertQueue.available() > 0 || this.handshakeQueue.available() > 0) {
                throw new TlsFatalAlert((short) 10);
            }
            this.recordStream.notifyChangeCipherSpecReceived();
            this.receivedChangeCipherSpec = true;
            handleChangeCipherSpecMessage();
        }
    }

    private void processHandshakeQueue(ByteQueue byteQueue) throws IOException {
        ProtocolVersion serverVersion;
        ProtocolVersion serverVersion2;
        while (byteQueue.available() >= 4) {
            int readInt32 = byteQueue.readInt32();
            short s = (short) (readInt32 >>> 24);
            if (!HandshakeType.isRecognized(s)) {
                throw new TlsFatalAlert((short) 10, "Handshake message of unrecognized type: " + ((int) s));
            }
            int i = readInt32 & ViewCompat.MEASURED_SIZE_MASK;
            if (i > this.maxHandshakeMessageSize) {
                throw new TlsFatalAlert((short) 80, "Handshake message length exceeds the maximum: " + HandshakeType.getText(s) + ", " + i + " > " + this.maxHandshakeMessageSize);
            }
            int i2 = i + 4;
            if (byteQueue.available() < i2) {
                return;
            }
            if (s != 0 && ((serverVersion2 = getContext().getServerVersion()) == null || !TlsUtils.isTLSv13(serverVersion2))) {
                checkReceivedChangeCipherSpec(20 == s);
            }
            HandshakeMessageInput readHandshakeMessage = byteQueue.readHandshakeMessage(i2);
            if (s != 0 && s != 1 && s != 2 && (s == 4 ? !((serverVersion = getContext().getServerVersion()) == null || TlsUtils.isTLSv13(serverVersion)) : !(s == 15 || s == 20 || s == 24))) {
                readHandshakeMessage.updateHash(this.handshakeHash);
            }
            readHandshakeMessage.skip(4L);
            handleHandshakeMessage(s, readHandshakeMessage);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static Hashtable readExtensions(ByteArrayInputStream byteArrayInputStream) throws IOException {
        if (byteArrayInputStream.available() < 1) {
            return null;
        }
        byte[] readOpaque16 = TlsUtils.readOpaque16(byteArrayInputStream);
        assertEmpty(byteArrayInputStream);
        return readExtensionsData(readOpaque16);
    }

    protected static Hashtable readExtensionsData(byte[] bArr) throws IOException {
        Hashtable hashtable = new Hashtable();
        if (bArr.length > 0) {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
            do {
                int readUint16 = TlsUtils.readUint16(byteArrayInputStream);
                if (hashtable.put(Integers.valueOf(readUint16), TlsUtils.readOpaque16(byteArrayInputStream)) != null) {
                    throw new TlsFatalAlert((short) 47, "Repeated extension: " + ExtensionType.getText(readUint16));
                }
            } while (byteArrayInputStream.available() > 0);
            return hashtable;
        }
        return hashtable;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static Hashtable readExtensionsData13(int i, byte[] bArr) throws IOException {
        Hashtable hashtable = new Hashtable();
        if (bArr.length > 0) {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
            do {
                int readUint16 = TlsUtils.readUint16(byteArrayInputStream);
                if (!TlsUtils.isPermittedExtensionType13(i, readUint16)) {
                    throw new TlsFatalAlert((short) 47, "Invalid extension: " + ExtensionType.getText(readUint16));
                }
                if (hashtable.put(Integers.valueOf(readUint16), TlsUtils.readOpaque16(byteArrayInputStream)) != null) {
                    throw new TlsFatalAlert((short) 47, "Repeated extension: " + ExtensionType.getText(readUint16));
                }
            } while (byteArrayInputStream.available() > 0);
            return hashtable;
        }
        return hashtable;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static Hashtable readExtensionsDataClientHello(byte[] bArr) throws IOException {
        int readUint16;
        Hashtable hashtable = new Hashtable();
        if (bArr.length > 0) {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
            boolean z = false;
            do {
                readUint16 = TlsUtils.readUint16(byteArrayInputStream);
                if (hashtable.put(Integers.valueOf(readUint16), TlsUtils.readOpaque16(byteArrayInputStream)) != null) {
                    throw new TlsFatalAlert((short) 47, "Repeated extension: " + ExtensionType.getText(readUint16));
                }
                z |= 41 == readUint16;
            } while (byteArrayInputStream.available() > 0);
            if (z && 41 != readUint16) {
                throw new TlsFatalAlert((short) 47, "'pre_shared_key' MUST be last in ClientHello");
            }
        }
        return hashtable;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static Vector readSupplementalDataMessage(ByteArrayInputStream byteArrayInputStream) throws IOException {
        byte[] readOpaque24 = TlsUtils.readOpaque24(byteArrayInputStream, 1);
        assertEmpty(byteArrayInputStream);
        ByteArrayInputStream byteArrayInputStream2 = new ByteArrayInputStream(readOpaque24);
        Vector vector = new Vector();
        while (byteArrayInputStream2.available() > 0) {
            vector.addElement(new SupplementalDataEntry(TlsUtils.readUint16(byteArrayInputStream2), TlsUtils.readOpaque16(byteArrayInputStream2)));
        }
        return vector;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static void writeExtensions(OutputStream outputStream, Hashtable hashtable) throws IOException {
        writeExtensions(outputStream, hashtable, 0);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static void writeExtensions(OutputStream outputStream, Hashtable hashtable, int i) throws IOException {
        if (hashtable == null || hashtable.isEmpty()) {
            return;
        }
        byte[] writeExtensionsData = writeExtensionsData(hashtable, i);
        int length = writeExtensionsData.length + i;
        TlsUtils.checkUint16(length);
        TlsUtils.writeUint16(length, outputStream);
        outputStream.write(writeExtensionsData);
    }

    protected static void writeExtensionsData(Hashtable hashtable, int i, ByteArrayOutputStream byteArrayOutputStream) throws IOException {
        writeSelectedExtensions(byteArrayOutputStream, hashtable, true);
        writeSelectedExtensions(byteArrayOutputStream, hashtable, false);
        writePreSharedKeyExtension(byteArrayOutputStream, hashtable, i);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static byte[] writeExtensionsData(Hashtable hashtable) throws IOException {
        return writeExtensionsData(hashtable, 0);
    }

    protected static byte[] writeExtensionsData(Hashtable hashtable, int i) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        writeExtensionsData(hashtable, i, byteArrayOutputStream);
        return byteArrayOutputStream.toByteArray();
    }

    protected static void writePreSharedKeyExtension(OutputStream outputStream, Hashtable hashtable, int i) throws IOException {
        byte[] bArr = (byte[]) hashtable.get(TlsExtensionsUtils.EXT_pre_shared_key);
        if (bArr != null) {
            TlsUtils.checkUint16(41);
            TlsUtils.writeUint16(41, outputStream);
            int length = bArr.length + i;
            TlsUtils.checkUint16(length);
            TlsUtils.writeUint16(length, outputStream);
            outputStream.write(bArr);
        }
    }

    protected static void writeSelectedExtensions(OutputStream outputStream, Hashtable hashtable, boolean z) throws IOException {
        Enumeration keys = hashtable.keys();
        while (keys.hasMoreElements()) {
            Integer num = (Integer) keys.nextElement();
            int intValue = num.intValue();
            if (41 != intValue) {
                byte[] bArr = (byte[]) hashtable.get(num);
                if (z == (bArr.length == 0)) {
                    TlsUtils.checkUint16(intValue);
                    TlsUtils.writeUint16(intValue, outputStream);
                    TlsUtils.writeOpaque16(bArr, outputStream);
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static void writeSupplementalData(OutputStream outputStream, Vector vector) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        for (int i = 0; i < vector.size(); i++) {
            SupplementalDataEntry supplementalDataEntry = (SupplementalDataEntry) vector.elementAt(i);
            int dataType = supplementalDataEntry.getDataType();
            TlsUtils.checkUint16(dataType);
            TlsUtils.writeUint16(dataType, byteArrayOutputStream);
            TlsUtils.writeOpaque16(supplementalDataEntry.getData(), byteArrayOutputStream);
        }
        TlsUtils.writeOpaque24(byteArrayOutputStream.toByteArray(), outputStream);
    }

    public int applicationDataAvailable() {
        return this.applicationDataQueue.available();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void applyMaxFragmentLengthExtension(short s) throws IOException {
        if (s >= 0) {
            if (!MaxFragmentLength.isValid(s)) {
                throw new TlsFatalAlert((short) 80);
            }
            this.recordStream.setPlaintextLimit(1 << (s + 8));
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void beginHandshake(boolean z) throws IOException {
        AbstractTlsContext contextAdmin = getContextAdmin();
        TlsPeer peer = getPeer();
        this.maxHandshakeMessageSize = Math.max(1024, peer.getMaxHandshakeMessageSize());
        this.handshakeHash = new DeferredHash(contextAdmin);
        this.connection_state = (short) 0;
        this.selectedPSK13 = false;
        contextAdmin.handshakeBeginning(peer);
        SecurityParameters securityParametersHandshake = contextAdmin.getSecurityParametersHandshake();
        if (z != securityParametersHandshake.isRenegotiating()) {
            throw new TlsFatalAlert((short) 80);
        }
        securityParametersHandshake.extendedPadding = peer.shouldUseExtendedPadding();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void blockForHandshake() throws IOException {
        while (this.connection_state != 21) {
            if (isClosed()) {
                throw new TlsFatalAlert((short) 80);
            }
            safeReadRecord();
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void cancelSession() {
        TlsSecret tlsSecret = this.sessionMasterSecret;
        if (tlsSecret != null) {
            tlsSecret.destroy();
            this.sessionMasterSecret = null;
        }
        SessionParameters sessionParameters = this.sessionParameters;
        if (sessionParameters != null) {
            sessionParameters.clear();
            this.sessionParameters = null;
        }
        this.tlsSession = null;
    }

    protected void checkReceivedChangeCipherSpec(boolean z) throws IOException {
        if (z != this.receivedChangeCipherSpec) {
            throw new TlsFatalAlert((short) 10);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void cleanupHandshake() {
        SecurityParameters securityParameters;
        TlsContext context = getContext();
        if (context != null && (securityParameters = context.getSecurityParameters()) != null) {
            securityParameters.clear();
        }
        this.tlsSession = null;
        this.sessionParameters = null;
        this.sessionMasterSecret = null;
        this.retryCookie = null;
        this.retryGroup = -1;
        this.clientExtensions = null;
        this.serverExtensions = null;
        this.selectedPSK13 = false;
        this.receivedChangeCipherSpec = false;
        this.expectSessionTicket = false;
    }

    @Override // org.bouncycastle.tls.TlsCloseable
    public void close() throws IOException {
        handleClose(true);
    }

    protected void closeConnection() throws IOException {
        this.recordStream.close();
    }

    public void closeInput() throws IOException {
        if (this.blocking) {
            throw new IllegalStateException("Cannot use closeInput() in blocking mode!");
        }
        if (this.closed) {
            return;
        }
        if (this.inputBuffers.available() > 0) {
            throw new EOFException();
        }
        if (!this.appDataReady) {
            throw new TlsFatalAlert((short) 40);
        }
        if (getPeer().requiresCloseNotify()) {
            handleFailure();
            throw new TlsNoCloseNotifyException();
        } else {
            handleClose(false);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void completeHandshake() throws IOException {
        try {
            AbstractTlsContext contextAdmin = getContextAdmin();
            SecurityParameters securityParametersHandshake = contextAdmin.getSecurityParametersHandshake();
            if (!contextAdmin.isHandshaking() || securityParametersHandshake.getLocalVerifyData() == null || securityParametersHandshake.getPeerVerifyData() == null) {
                throw new TlsFatalAlert((short) 80);
            }
            this.recordStream.finaliseHandshake();
            this.connection_state = (short) 21;
            this.handshakeHash = new DeferredHash(contextAdmin);
            this.alertQueue.shrink();
            this.handshakeQueue.shrink();
            ProtocolVersion negotiatedVersion = securityParametersHandshake.getNegotiatedVersion();
            this.appDataSplitEnabled = !TlsUtils.isTLSv11(negotiatedVersion);
            this.appDataReady = true;
            this.keyUpdateEnabled = TlsUtils.isTLSv13(negotiatedVersion);
            if (this.blocking) {
                this.tlsInputStream = new TlsInputStream(this);
                this.tlsOutputStream = new TlsOutputStream(this);
            }
            SessionParameters sessionParameters = this.sessionParameters;
            if (sessionParameters == null) {
                this.sessionMasterSecret = securityParametersHandshake.getMasterSecret();
                this.sessionParameters = new SessionParameters.Builder().setCipherSuite(securityParametersHandshake.getCipherSuite()).setExtendedMasterSecret(securityParametersHandshake.isExtendedMasterSecret()).setLocalCertificate(securityParametersHandshake.getLocalCertificate()).setMasterSecret(contextAdmin.getCrypto().adoptSecret(this.sessionMasterSecret)).setNegotiatedVersion(securityParametersHandshake.getNegotiatedVersion()).setPeerCertificate(securityParametersHandshake.getPeerCertificate()).setPSKIdentity(securityParametersHandshake.getPSKIdentity()).setSRPIdentity(securityParametersHandshake.getSRPIdentity()).setServerExtensions(this.serverExtensions).build();
                this.tlsSession = TlsUtils.importSession(securityParametersHandshake.getSessionID(), this.sessionParameters);
            } else {
                securityParametersHandshake.localCertificate = sessionParameters.getLocalCertificate();
                securityParametersHandshake.peerCertificate = this.sessionParameters.getPeerCertificate();
                securityParametersHandshake.pskIdentity = this.sessionParameters.getPSKIdentity();
                securityParametersHandshake.srpIdentity = this.sessionParameters.getSRPIdentity();
            }
            contextAdmin.handshakeComplete(getPeer(), this.tlsSession);
        } finally {
            cleanupHandshake();
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public boolean establishSession(TlsSession tlsSession) {
        SessionParameters exportSessionParameters;
        ProtocolVersion negotiatedVersion;
        TlsSecret sessionMasterSecret;
        this.tlsSession = null;
        this.sessionParameters = null;
        this.sessionMasterSecret = null;
        if (tlsSession == null || !tlsSession.isResumable() || (exportSessionParameters = tlsSession.exportSessionParameters()) == null || (negotiatedVersion = exportSessionParameters.getNegotiatedVersion()) == null || !negotiatedVersion.isTLS()) {
            return false;
        }
        if ((TlsUtils.isExtendedMasterSecretOptional(negotiatedVersion) || exportSessionParameters.isExtendedMasterSecret() != negotiatedVersion.isSSL()) && (sessionMasterSecret = TlsUtils.getSessionMasterSecret(getContext().getCrypto(), exportSessionParameters.getMasterSecret())) != null) {
            this.tlsSession = tlsSession;
            this.sessionParameters = exportSessionParameters;
            this.sessionMasterSecret = sessionMasterSecret;
            return true;
        }
        return false;
    }

    public void flush() throws IOException {
    }

    public int getAppDataSplitMode() {
        return this.appDataSplitMode;
    }

    public int getApplicationDataLimit() {
        return this.recordStream.getPlaintextLimit();
    }

    public int getAvailableInputBytes() {
        if (this.blocking) {
            throw new IllegalStateException("Cannot use getAvailableInputBytes() in blocking mode! Use getInputStream().available() instead.");
        }
        return applicationDataAvailable();
    }

    public int getAvailableOutputBytes() {
        if (this.blocking) {
            throw new IllegalStateException("Cannot use getAvailableOutputBytes() in blocking mode! Use getOutputStream() instead.");
        }
        return this.outputBuffer.getBuffer().available();
    }

    protected abstract TlsContext getContext();

    abstract AbstractTlsContext getContextAdmin();

    public InputStream getInputStream() {
        if (this.blocking) {
            return this.tlsInputStream;
        }
        throw new IllegalStateException("Cannot use InputStream in non-blocking mode! Use offerInput() instead.");
    }

    public OutputStream getOutputStream() {
        if (this.blocking) {
            return this.tlsOutputStream;
        }
        throw new IllegalStateException("Cannot use OutputStream in non-blocking mode! Use offerOutput() instead.");
    }

    protected abstract TlsPeer getPeer();

    protected int getRenegotiationPolicy() {
        return 0;
    }

    protected void handleAlertMessage(short s, short s2) throws IOException {
        getPeer().notifyAlertReceived(s, s2);
        if (s == 1) {
            handleAlertWarningMessage(s2);
        } else {
            handleFailure();
            throw new TlsFatalAlertReceived(s2);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void handleAlertWarningMessage(short s) throws IOException {
        if (s == 0) {
            if (!this.appDataReady) {
                throw new TlsFatalAlert((short) 40);
            }
            handleClose(false);
        } else if (s == 41) {
            throw new TlsFatalAlert((short) 10);
        } else {
            if (s == 100) {
                throw new TlsFatalAlert((short) 40);
            }
        }
    }

    protected void handleChangeCipherSpecMessage() throws IOException {
    }

    protected void handleClose(boolean z) throws IOException {
        if (this.closed) {
            return;
        }
        this.closed = true;
        if (!this.appDataReady) {
            cleanupHandshake();
            if (z) {
                raiseAlertWarning((short) 90, "User canceled handshake");
            }
        }
        raiseAlertWarning((short) 0, "Connection closed");
        closeConnection();
        getPeer().notifyConnectionClosed();
    }

    protected void handleException(short s, String str, Throwable th) throws IOException {
        if (((this.appDataReady || isResumableHandshake()) && (th instanceof InterruptedIOException)) || this.closed) {
            return;
        }
        raiseAlertFatal(s, str, th);
        handleFailure();
    }

    protected void handleFailure() throws IOException {
        this.closed = true;
        this.failedWithError = true;
        invalidateSession();
        if (!this.appDataReady) {
            cleanupHandshake();
        }
        closeConnection();
        getPeer().notifyConnectionClosed();
    }

    protected abstract void handleHandshakeMessage(short s, HandshakeMessageInput handshakeMessageInput) throws IOException;

    /* JADX INFO: Access modifiers changed from: protected */
    /* JADX WARN: Removed duplicated region for block: B:21:0x003d  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0048 A[RETURN] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public boolean handleRenegotiation() throws java.io.IOException {
        /*
            r4 = this;
            org.bouncycastle.tls.TlsContext r0 = r4.getContext()
            org.bouncycastle.tls.SecurityParameters r0 = r0.getSecurityParametersConnection()
            r1 = 0
            if (r0 == 0) goto L39
            boolean r2 = r0.isSecureRenegotiation()
            if (r2 == 0) goto L39
            boolean r2 = r0.isResumedSession()
            if (r2 == 0) goto L1d
            boolean r2 = r0.isExtendedMasterSecret()
            if (r2 == 0) goto L39
        L1d:
            int r2 = r0.getEntity()
            if (r2 != 0) goto L28
            org.bouncycastle.tls.Certificate r0 = r0.getLocalCertificate()
            goto L2c
        L28:
            org.bouncycastle.tls.Certificate r0 = r0.getPeerCertificate()
        L2c:
            if (r0 == 0) goto L39
            boolean r0 = r0.isEmpty()
            if (r0 != 0) goto L39
            int r0 = r4.getRenegotiationPolicy()
            goto L3a
        L39:
            r0 = r1
        L3a:
            r2 = 1
            if (r0 == r2) goto L48
            r3 = 2
            if (r0 == r3) goto L44
            r4.refuseRenegotiation()
            return r1
        L44:
            r4.beginHandshake(r2)
            return r2
        L48:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.tls.TlsProtocol.handleRenegotiation():boolean");
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void invalidateSession() {
        TlsSession tlsSession = this.tlsSession;
        if (tlsSession != null) {
            tlsSession.invalidate();
        }
        cancelSession();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isApplicationDataReady() {
        return this.appDataReady;
    }

    public boolean isClosed() {
        return this.closed;
    }

    public boolean isConnected() {
        AbstractTlsContext contextAdmin;
        return (this.closed || (contextAdmin = getContextAdmin()) == null || !contextAdmin.isConnected()) ? false : true;
    }

    public boolean isHandshaking() {
        AbstractTlsContext contextAdmin;
        return (this.closed || (contextAdmin = getContextAdmin()) == null || !contextAdmin.isHandshaking()) ? false : true;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public boolean isLegacyConnectionState() {
        switch (this.connection_state) {
            case 0:
            case 1:
            case 4:
            case 6:
            case 7:
            case 8:
            case 10:
            case 11:
            case 12:
            case 14:
            case 15:
            case 16:
            case 17:
            case 18:
            case 19:
            case 20:
            case 21:
                return true;
            case 2:
            case 3:
            case 5:
            case 9:
            case 13:
            default:
                return false;
        }
    }

    public boolean isResumableHandshake() {
        return this.resumableHandshake;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public boolean isTLSv13ConnectionState() {
        switch (this.connection_state) {
            case 0:
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 7:
            case 9:
            case 11:
            case 13:
            case 15:
            case 17:
            case 18:
            case 20:
            case 21:
                return true;
            case 6:
            case 8:
            case 10:
            case 12:
            case 14:
            case 16:
            case 19:
            default:
                return false;
        }
    }

    public void offerInput(byte[] bArr) throws IOException {
        offerInput(bArr, 0, bArr.length);
    }

    public void offerInput(byte[] bArr, int i, int i2) throws IOException {
        if (this.blocking) {
            throw new IllegalStateException("Cannot use offerInput() in blocking mode! Use getInputStream() instead.");
        }
        if (this.closed) {
            throw new IOException("Connection is closed, cannot accept any more input");
        }
        if (this.inputBuffers.available() == 0 && safeReadFullRecord(bArr, i, i2)) {
            if (this.closed && !this.appDataReady) {
                throw new TlsFatalAlert((short) 80);
            }
            return;
        }
        this.inputBuffers.addBytes(bArr, i, i2);
        while (this.inputBuffers.available() >= 5) {
            byte[] bArr2 = new byte[5];
            if (5 != this.inputBuffers.peek(bArr2)) {
                throw new TlsFatalAlert((short) 80);
            }
            if (this.inputBuffers.available() < safePreviewRecordHeader(bArr2).getRecordSize()) {
                return;
            }
            safeReadRecord();
            if (this.closed) {
                if (!this.appDataReady) {
                    throw new TlsFatalAlert((short) 80);
                }
                return;
            }
        }
    }

    public RecordPreview previewInputRecord(byte[] bArr) throws IOException {
        if (this.blocking) {
            throw new IllegalStateException("Cannot use previewInputRecord() in blocking mode!");
        }
        if (this.inputBuffers.available() == 0) {
            if (this.closed) {
                throw new IOException("Connection is closed, cannot accept any more input");
            }
            return safePreviewRecordHeader(bArr);
        }
        throw new IllegalStateException("Can only use previewInputRecord() for record-aligned input.");
    }

    public int previewOutputRecord() {
        int readUint16;
        if (this.blocking) {
            throw new IllegalStateException("Cannot use previewOutputRecord() in blocking mode!");
        }
        ByteQueue buffer = this.outputBuffer.getBuffer();
        int available = buffer.available();
        if (available < 1) {
            return 0;
        }
        if (available < 5 || available < (readUint16 = buffer.readUint16(3) + 5)) {
            throw new IllegalStateException("Can only use previewOutputRecord() for record-aligned output.");
        }
        return readUint16;
    }

    public RecordPreview previewOutputRecord(int i) throws IOException {
        if (this.appDataReady) {
            if (this.blocking) {
                throw new IllegalStateException("Cannot use previewOutputRecord() in blocking mode!");
            }
            if (this.outputBuffer.getBuffer().available() == 0) {
                if (this.closed) {
                    throw new IOException("Connection is closed, cannot produce any more output");
                }
                if (i < 1) {
                    return new RecordPreview(0, 0);
                }
                if (this.appDataSplitEnabled) {
                    int i2 = this.appDataSplitMode;
                    if (i2 == 1 || i2 == 2) {
                        return RecordPreview.combineAppData(this.recordStream.previewOutputRecord(0), this.recordStream.previewOutputRecord(i));
                    }
                    RecordPreview previewOutputRecord = this.recordStream.previewOutputRecord(1);
                    return i > 1 ? RecordPreview.combineAppData(previewOutputRecord, this.recordStream.previewOutputRecord(i - 1)) : previewOutputRecord;
                }
                RecordPreview previewOutputRecord2 = this.recordStream.previewOutputRecord(i);
                if (this.keyUpdateEnabled) {
                    if (this.keyUpdatePendingSend || this.recordStream.needsKeyUpdate()) {
                        return RecordPreview.extendRecordSize(previewOutputRecord2, this.recordStream.previewOutputRecordSize(HandshakeMessageOutput.getLength(1)));
                    }
                    return previewOutputRecord2;
                }
                return previewOutputRecord2;
            }
            throw new IllegalStateException("Can only use previewOutputRecord() for record-aligned output.");
        }
        throw new IllegalStateException("Cannot use previewOutputRecord() until initial handshake completed.");
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void process13FinishedMessage(ByteArrayInputStream byteArrayInputStream) throws IOException {
        TlsContext context = getContext();
        SecurityParameters securityParametersHandshake = context.getSecurityParametersHandshake();
        boolean isServer = context.isServer();
        byte[] readFully = TlsUtils.readFully(securityParametersHandshake.getVerifyDataLength(), byteArrayInputStream);
        assertEmpty(byteArrayInputStream);
        byte[] calculateVerifyData = TlsUtils.calculateVerifyData(context, this.handshakeHash, !isServer);
        if (!Arrays.constantTimeAreEqual(calculateVerifyData, readFully)) {
            throw new TlsFatalAlert((short) 51);
        }
        securityParametersHandshake.peerVerifyData = calculateVerifyData;
        securityParametersHandshake.tlsUnique = null;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void processFinishedMessage(ByteArrayInputStream byteArrayInputStream) throws IOException {
        TlsContext context = getContext();
        SecurityParameters securityParametersHandshake = context.getSecurityParametersHandshake();
        boolean isServer = context.isServer();
        byte[] readFully = TlsUtils.readFully(securityParametersHandshake.getVerifyDataLength(), byteArrayInputStream);
        assertEmpty(byteArrayInputStream);
        byte[] calculateVerifyData = TlsUtils.calculateVerifyData(context, this.handshakeHash, !isServer);
        if (!Arrays.constantTimeAreEqual(calculateVerifyData, readFully)) {
            throw new TlsFatalAlert((short) 51);
        }
        securityParametersHandshake.peerVerifyData = calculateVerifyData;
        if ((!securityParametersHandshake.isResumedSession() || securityParametersHandshake.isExtendedMasterSecret()) && securityParametersHandshake.getLocalVerifyData() == null) {
            securityParametersHandshake.tlsUnique = calculateVerifyData;
        }
    }

    protected short processMaxFragmentLengthExtension(Hashtable hashtable, Hashtable hashtable2, short s) throws IOException {
        return TlsUtils.processMaxFragmentLengthExtension(hashtable, hashtable2, s);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void processRecord(short s, byte[] bArr, int i, int i2) throws IOException {
        switch (s) {
            case 20:
                processChangeCipherSpec(bArr, i, i2);
                return;
            case 21:
                this.alertQueue.addData(bArr, i, i2);
                processAlertQueue();
                return;
            case 22:
                if (this.handshakeQueue.available() > 0) {
                    this.handshakeQueue.addData(bArr, i, i2);
                    processHandshakeQueue(this.handshakeQueue);
                    return;
                }
                ByteQueue byteQueue = new ByteQueue(bArr, i, i2);
                processHandshakeQueue(byteQueue);
                int available = byteQueue.available();
                if (available > 0) {
                    this.handshakeQueue.addData(bArr, (i + i2) - available, available);
                    return;
                }
                return;
            case 23:
                if (!this.appDataReady) {
                    throw new TlsFatalAlert((short) 10);
                }
                this.applicationDataQueue.addData(bArr, i, i2);
                processApplicationDataQueue();
                return;
            default:
                throw new TlsFatalAlert((short) 10);
        }
    }

    protected void raiseAlertFatal(short s, String str, Throwable th) throws IOException {
        getPeer().notifyAlertRaised((short) 2, s, str, th);
        try {
            this.recordStream.writeRecord((short) 21, new byte[]{2, (byte) s}, 0, 2);
        } catch (Exception unused) {
        }
    }

    protected void raiseAlertWarning(short s, String str) throws IOException {
        getPeer().notifyAlertRaised((short) 1, s, str, null);
        safeWriteRecord((short) 21, new byte[]{1, (byte) s}, 0, 2);
    }

    public int readApplicationData(byte[] bArr, int i, int i2) throws IOException {
        bArr.getClass();
        int length = bArr.length - i;
        if ((length | i | i2 | (length - i2)) >= 0) {
            if (this.appDataReady) {
                if (i2 < 1) {
                    return 0;
                }
                while (this.applicationDataQueue.available() < 1) {
                    if (this.closed) {
                        if (this.failedWithError) {
                            throw new IOException("Cannot read application data on failed TLS connection");
                        }
                        return -1;
                    }
                    safeReadRecord();
                }
                int min = Math.min(i2, this.applicationDataQueue.available());
                this.applicationDataQueue.removeData(bArr, i, min, 0);
                return min;
            }
            throw new IllegalStateException("Cannot read application data until initial handshake completed.");
        }
        throw new IndexOutOfBoundsException();
    }

    public int readInput(ByteBuffer byteBuffer, int i) {
        if (this.blocking) {
            throw new IllegalStateException("Cannot use readInput() in blocking mode! Use getInputStream() instead.");
        }
        int min = Math.min(i, this.applicationDataQueue.available());
        if (min < 1) {
            return 0;
        }
        this.applicationDataQueue.removeData(byteBuffer, min, 0);
        return min;
    }

    public int readInput(byte[] bArr, int i, int i2) {
        if (this.blocking) {
            throw new IllegalStateException("Cannot use readInput() in blocking mode! Use getInputStream() instead.");
        }
        int min = Math.min(i2, this.applicationDataQueue.available());
        if (min < 1) {
            return 0;
        }
        this.applicationDataQueue.removeData(bArr, i, min, 0);
        return min;
    }

    public int readOutput(ByteBuffer byteBuffer, int i) {
        if (this.blocking) {
            throw new IllegalStateException("Cannot use readOutput() in blocking mode! Use getOutputStream() instead.");
        }
        int min = Math.min(getAvailableOutputBytes(), i);
        this.outputBuffer.getBuffer().removeData(byteBuffer, min, 0);
        return min;
    }

    public int readOutput(byte[] bArr, int i, int i2) {
        if (this.blocking) {
            throw new IllegalStateException("Cannot use readOutput() in blocking mode! Use getOutputStream() instead.");
        }
        int min = Math.min(getAvailableOutputBytes(), i2);
        this.outputBuffer.getBuffer().removeData(bArr, i, min, 0);
        return min;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void receive13KeyUpdate(ByteArrayInputStream byteArrayInputStream) throws IOException {
        if (!this.appDataReady || !this.keyUpdateEnabled) {
            throw new TlsFatalAlert((short) 10);
        }
        short readUint8 = TlsUtils.readUint8(byteArrayInputStream);
        assertEmpty(byteArrayInputStream);
        if (!KeyUpdateRequest.isValid(readUint8)) {
            throw new TlsFatalAlert((short) 47);
        }
        boolean z = 1 == readUint8;
        TlsUtils.update13TrafficSecretPeer(getContext());
        this.recordStream.notifyKeyUpdateReceived();
        this.keyUpdatePendingSend = z | this.keyUpdatePendingSend;
    }

    protected void refuseRenegotiation() throws IOException {
        if (TlsUtils.isSSL(getContext())) {
            throw new TlsFatalAlert((short) 40);
        }
        raiseAlertWarning((short) 100, "Renegotiation not supported");
    }

    public void resumeHandshake() throws IOException {
        if (!this.blocking) {
            throw new IllegalStateException("Cannot use resumeHandshake() in non-blocking mode!");
        }
        if (!isHandshaking()) {
            throw new IllegalStateException("No handshake in progress");
        }
        blockForHandshake();
    }

    protected RecordPreview safePreviewRecordHeader(byte[] bArr) throws IOException {
        try {
            return this.recordStream.previewRecordHeader(bArr);
        } catch (RuntimeException e) {
            handleException((short) 80, "Failed to read record", e);
            throw new TlsFatalAlert((short) 80, e);
        } catch (TlsFatalAlert e2) {
            handleException(e2.getAlertDescription(), "Failed to read record", e2);
            throw e2;
        } catch (IOException e3) {
            handleException((short) 80, "Failed to read record", e3);
            throw e3;
        }
    }

    protected boolean safeReadFullRecord(byte[] bArr, int i, int i2) throws IOException {
        try {
            return this.recordStream.readFullRecord(bArr, i, i2);
        } catch (RuntimeException e) {
            handleException((short) 80, "Failed to process record", e);
            throw new TlsFatalAlert((short) 80, e);
        } catch (TlsFatalAlert e2) {
            handleException(e2.getAlertDescription(), "Failed to process record", e2);
            throw e2;
        } catch (IOException e3) {
            handleException((short) 80, "Failed to process record", e3);
            throw e3;
        }
    }

    protected void safeReadRecord() throws IOException {
        try {
            if (this.recordStream.readRecord()) {
                return;
            }
            if (!this.appDataReady) {
                throw new TlsFatalAlert((short) 40);
            }
            if (getPeer().requiresCloseNotify()) {
                handleFailure();
                throw new TlsNoCloseNotifyException();
            } else {
                handleClose(false);
            }
        } catch (RuntimeException e) {
            handleException((short) 80, "Failed to read record", e);
            throw new TlsFatalAlert((short) 80, e);
        } catch (TlsFatalAlert e2) {
            handleException(e2.getAlertDescription(), "Failed to read record", e2);
            throw e2;
        } catch (TlsFatalAlertReceived e3) {
            throw e3;
        } catch (IOException e4) {
            handleException((short) 80, "Failed to read record", e4);
            throw e4;
        }
    }

    protected void safeWriteRecord(short s, byte[] bArr, int i, int i2) throws IOException {
        try {
            this.recordStream.writeRecord(s, bArr, i, i2);
        } catch (RuntimeException e) {
            handleException((short) 80, "Failed to write record", e);
            throw new TlsFatalAlert((short) 80, e);
        } catch (TlsFatalAlert e2) {
            handleException(e2.getAlertDescription(), "Failed to write record", e2);
            throw e2;
        } catch (IOException e3) {
            handleException((short) 80, "Failed to write record", e3);
            throw e3;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void send13CertificateMessage(Certificate certificate) throws IOException {
        if (certificate == null) {
            throw new TlsFatalAlert((short) 80);
        }
        TlsContext context = getContext();
        SecurityParameters securityParametersHandshake = context.getSecurityParametersHandshake();
        if (securityParametersHandshake.getLocalCertificate() != null) {
            throw new TlsFatalAlert((short) 80);
        }
        HandshakeMessageOutput handshakeMessageOutput = new HandshakeMessageOutput((short) 11);
        certificate.encode(context, handshakeMessageOutput, null);
        handshakeMessageOutput.send(this);
        securityParametersHandshake.localCertificate = certificate;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void send13CertificateVerifyMessage(DigitallySigned digitallySigned) throws IOException {
        HandshakeMessageOutput handshakeMessageOutput = new HandshakeMessageOutput((short) 15);
        digitallySigned.encode(handshakeMessageOutput);
        handshakeMessageOutput.send(this);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void send13FinishedMessage() throws IOException {
        TlsContext context = getContext();
        SecurityParameters securityParametersHandshake = context.getSecurityParametersHandshake();
        byte[] calculateVerifyData = TlsUtils.calculateVerifyData(context, this.handshakeHash, context.isServer());
        securityParametersHandshake.localVerifyData = calculateVerifyData;
        securityParametersHandshake.tlsUnique = null;
        HandshakeMessageOutput.send(this, (short) 20, calculateVerifyData);
    }

    protected void send13KeyUpdate(boolean z) throws IOException {
        if (!this.appDataReady || !this.keyUpdateEnabled) {
            throw new TlsFatalAlert((short) 80);
        }
        HandshakeMessageOutput.send(this, (short) 24, TlsUtils.encodeUint8(z ? (short) 1 : (short) 0));
        TlsUtils.update13TrafficSecretLocal(getContext());
        this.recordStream.notifyKeyUpdateSent();
        this.keyUpdatePendingSend = (z ? 1 : 0) & (this.keyUpdatePendingSend ? 1 : 0);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void sendCertificateMessage(Certificate certificate, OutputStream outputStream) throws IOException {
        TlsContext context = getContext();
        SecurityParameters securityParametersHandshake = context.getSecurityParametersHandshake();
        if (securityParametersHandshake.getLocalCertificate() != null) {
            throw new TlsFatalAlert((short) 80);
        }
        if (certificate == null) {
            certificate = Certificate.EMPTY_CHAIN;
        }
        if (certificate.isEmpty() && !context.isServer() && securityParametersHandshake.getNegotiatedVersion().isSSL()) {
            raiseAlertWarning((short) 41, "SSLv3 client didn't provide credentials");
        } else {
            HandshakeMessageOutput handshakeMessageOutput = new HandshakeMessageOutput((short) 11);
            certificate.encode(context, handshakeMessageOutput, outputStream);
            handshakeMessageOutput.send(this);
        }
        securityParametersHandshake.localCertificate = certificate;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void sendChangeCipherSpec() throws IOException {
        sendChangeCipherSpecMessage();
        this.recordStream.enablePendingCipherWrite();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void sendChangeCipherSpecMessage() throws IOException {
        safeWriteRecord((short) 20, new byte[]{1}, 0, 1);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void sendFinishedMessage() throws IOException {
        TlsContext context = getContext();
        SecurityParameters securityParametersHandshake = context.getSecurityParametersHandshake();
        byte[] calculateVerifyData = TlsUtils.calculateVerifyData(context, this.handshakeHash, context.isServer());
        securityParametersHandshake.localVerifyData = calculateVerifyData;
        if ((!securityParametersHandshake.isResumedSession() || securityParametersHandshake.isExtendedMasterSecret()) && securityParametersHandshake.getPeerVerifyData() == null) {
            securityParametersHandshake.tlsUnique = calculateVerifyData;
        }
        HandshakeMessageOutput.send(this, (short) 20, calculateVerifyData);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void sendSupplementalDataMessage(Vector vector) throws IOException {
        HandshakeMessageOutput handshakeMessageOutput = new HandshakeMessageOutput((short) 23);
        writeSupplementalData(handshakeMessageOutput, vector);
        handshakeMessageOutput.send(this);
    }

    public void setAppDataSplitMode(int i) {
        if (i < 0 || i > 2) {
            throw new IllegalArgumentException("Illegal appDataSplitMode mode: " + i);
        }
        this.appDataSplitMode = i;
    }

    public void setResumableHandshake(boolean z) {
        this.resumableHandshake = z;
    }

    public void writeApplicationData(byte[] bArr, int i, int i2) throws IOException {
        bArr.getClass();
        int length = bArr.length - i;
        if ((length | i | i2 | (length - i2)) < 0) {
            throw new IndexOutOfBoundsException();
        }
        if (!this.appDataReady) {
            throw new IllegalStateException("Cannot write application data until initial handshake completed.");
        }
        synchronized (this.recordWriteLock) {
            while (i2 > 0) {
                if (this.closed) {
                    throw new IOException("Cannot write application data on closed/failed TLS connection");
                }
                if (this.appDataSplitEnabled) {
                    int i3 = this.appDataSplitMode;
                    if (i3 != 1) {
                        if (i3 == 2) {
                            this.appDataSplitEnabled = false;
                        } else if (i2 > 1) {
                            safeWriteRecord((short) 23, bArr, i, 1);
                            i++;
                            i2--;
                        }
                    }
                    safeWriteRecord((short) 23, TlsUtils.EMPTY_BYTES, 0, 0);
                } else if (this.keyUpdateEnabled) {
                    if (this.keyUpdatePendingSend) {
                        send13KeyUpdate(false);
                    } else if (this.recordStream.needsKeyUpdate()) {
                        send13KeyUpdate(true);
                    }
                }
                int min = Math.min(i2, this.recordStream.getPlaintextLimit());
                safeWriteRecord((short) 23, bArr, i, min);
                i += min;
                i2 -= min;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void writeHandshakeMessage(byte[] bArr, int i, int i2) throws IOException {
        ProtocolVersion serverVersion;
        if (i2 < 4) {
            throw new TlsFatalAlert((short) 80);
        }
        short readUint8 = TlsUtils.readUint8(bArr, i);
        if (readUint8 != 0 && readUint8 != 1 && (readUint8 == 4 ? !((serverVersion = getContext().getServerVersion()) == null || TlsUtils.isTLSv13(serverVersion)) : readUint8 != 24)) {
            this.handshakeHash.update(bArr, i, i2);
        }
        int i3 = 0;
        do {
            int min = Math.min(i2 - i3, this.recordStream.getPlaintextLimit());
            safeWriteRecord((short) 22, bArr, i + i3, min);
            i3 += min;
        } while (i3 < i2);
    }
}