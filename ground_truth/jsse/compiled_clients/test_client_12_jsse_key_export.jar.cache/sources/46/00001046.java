package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import javax.crypto.BadPaddingException;
import javax.net.ssl.SSLException;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.openjsse.sun.security.ssl.SSLCipher;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/DTLSInputRecord.class */
public final class DTLSInputRecord extends InputRecord implements DTLSRecord {
    private DTLSReassembler reassembler;
    private int readEpoch;

    /* JADX INFO: Access modifiers changed from: package-private */
    public DTLSInputRecord(HandshakeHash handshakeHash) {
        super(handshakeHash, SSLCipher.SSLReadCipher.nullDTlsReadCipher());
        this.reassembler = null;
        this.readEpoch = 0;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.InputRecord
    public void changeReadCiphers(SSLCipher.SSLReadCipher readCipher) {
        this.readCipher = readCipher;
        this.readEpoch++;
    }

    @Override // org.openjsse.sun.security.ssl.InputRecord, java.io.Closeable, java.lang.AutoCloseable
    public synchronized void close() throws IOException {
        if (!this.isClosed) {
            super.close();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.InputRecord
    public boolean isEmpty() {
        return this.reassembler == null || this.reassembler.isEmpty();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.InputRecord
    public int estimateFragmentSize(int packetSize) {
        if (packetSize > 0) {
            return this.readCipher.estimateFragmentSize(packetSize, 13);
        }
        return 16384;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.InputRecord
    public void expectingFinishFlight() {
        if (this.reassembler != null) {
            this.reassembler.expectingFinishFlight();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.InputRecord
    public void finishHandshake() {
        this.reassembler = null;
    }

    @Override // org.openjsse.sun.security.ssl.InputRecord
    Plaintext acquirePlaintext() {
        if (this.reassembler != null) {
            return this.reassembler.acquirePlaintext();
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.InputRecord
    public Plaintext[] decode(ByteBuffer[] srcs, int srcsOffset, int srcsLength) throws IOException, BadPaddingException {
        if (srcs == null || srcs.length == 0 || srcsLength == 0) {
            Plaintext pt = acquirePlaintext();
            return pt == null ? new Plaintext[0] : new Plaintext[]{pt};
        } else if (srcsLength == 1) {
            return decode(srcs[srcsOffset]);
        } else {
            ByteBuffer packet = extract(srcs, srcsOffset, srcsLength, 13);
            return decode(packet);
        }
    }

    Plaintext[] decode(ByteBuffer packet) {
        if (this.isClosed) {
            return null;
        }
        if (SSLLogger.isOn && SSLLogger.isOn("packet")) {
            SSLLogger.fine("Raw read", packet);
        }
        int srcPos = packet.position();
        int srcLim = packet.limit();
        byte contentType = packet.get();
        byte majorVersion = packet.get();
        byte minorVersion = packet.get();
        byte[] recordEnS = new byte[8];
        packet.get(recordEnS);
        int recordEpoch = ((recordEnS[0] & 255) << 8) | (recordEnS[1] & 255);
        long recordSeq = ((recordEnS[2] & 255) << 40) | ((recordEnS[3] & 255) << 32) | ((recordEnS[4] & 255) << 24) | ((recordEnS[5] & 255) << 16) | ((recordEnS[6] & 255) << 8) | (recordEnS[7] & 255);
        int contentLen = ((packet.get() & 255) << 8) | (packet.get() & 255);
        if (SSLLogger.isOn && SSLLogger.isOn("record")) {
            SSLLogger.fine("READ: " + ProtocolVersion.nameOf(majorVersion, minorVersion) + " " + ContentType.nameOf(contentType) + ", length = " + contentLen, new Object[0]);
        }
        int recLim = Math.addExact(srcPos, 13 + contentLen);
        if (this.readEpoch > recordEpoch) {
            packet.position(recLim);
            if (SSLLogger.isOn && SSLLogger.isOn("record")) {
                SSLLogger.fine("READ: discard this old record", recordEnS);
                return null;
            }
            return null;
        } else if (this.readEpoch < recordEpoch) {
            if ((contentType != ContentType.HANDSHAKE.f965id && contentType != ContentType.CHANGE_CIPHER_SPEC.f965id) || ((this.reassembler == null && contentType != ContentType.HANDSHAKE.f965id) || this.readEpoch < recordEpoch - 1)) {
                packet.position(recLim);
                if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                    SSLLogger.fine("Premature record (epoch), discard it.", new Object[0]);
                    return null;
                }
                return null;
            }
            byte[] fragment = new byte[contentLen];
            packet.get(fragment);
            RecordFragment buffered = new RecordFragment(fragment, contentType, majorVersion, minorVersion, recordEnS, recordEpoch, recordSeq, true);
            if (this.reassembler == null) {
                this.reassembler = new DTLSReassembler(recordEpoch);
            }
            this.reassembler.queueUpFragment(buffered);
            packet.position(recLim);
            Plaintext pt = this.reassembler.acquirePlaintext();
            if (pt == null) {
                return null;
            }
            return new Plaintext[]{pt};
        } else {
            packet.limit(recLim);
            packet.position(srcPos + 13);
            try {
                try {
                    Plaintext plaintext = this.readCipher.decrypt(contentType, packet, recordEnS);
                    ByteBuffer plaintextFragment = plaintext.fragment;
                    byte contentType2 = plaintext.contentType;
                    packet.limit(srcLim);
                    packet.position(recLim);
                    if (contentType2 != ContentType.CHANGE_CIPHER_SPEC.f965id && contentType2 != ContentType.HANDSHAKE.f965id) {
                        if (this.reassembler != null && this.reassembler.handshakeEpoch < recordEpoch) {
                            if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                                SSLLogger.fine("Cleanup the handshake reassembler", new Object[0]);
                            }
                            this.reassembler = null;
                        }
                        return new Plaintext[]{new Plaintext(contentType2, majorVersion, minorVersion, recordEpoch, Authenticator.toLong(recordEnS), plaintextFragment)};
                    }
                    if (contentType2 == ContentType.CHANGE_CIPHER_SPEC.f965id) {
                        if (this.reassembler == null) {
                            this.reassembler = new DTLSReassembler(recordEpoch);
                        }
                        this.reassembler.queueUpChangeCipherSpec(new RecordFragment(plaintextFragment, contentType2, majorVersion, minorVersion, recordEnS, recordEpoch, recordSeq, false));
                    } else {
                        while (plaintextFragment.remaining() > 0) {
                            HandshakeFragment hsFrag = parseHandshakeMessage(contentType2, majorVersion, minorVersion, recordEnS, recordEpoch, recordSeq, plaintextFragment);
                            if (hsFrag == null) {
                                if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                                    SSLLogger.fine("Invalid handshake message, discard it.", new Object[0]);
                                    return null;
                                }
                                return null;
                            }
                            if (this.reassembler == null) {
                                this.reassembler = new DTLSReassembler(recordEpoch);
                            }
                            this.reassembler.queueUpHandshake(hsFrag);
                        }
                    }
                    if (this.reassembler != null) {
                        Plaintext pt2 = this.reassembler.acquirePlaintext();
                        if (pt2 == null) {
                            return null;
                        }
                        return new Plaintext[]{pt2};
                    } else if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                        SSLLogger.fine("The reassembler is not initialized yet.", new Object[0]);
                        return null;
                    } else {
                        return null;
                    }
                } catch (GeneralSecurityException gse) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                        SSLLogger.fine("Discard invalid record: " + gse, new Object[0]);
                    }
                    packet.limit(srcLim);
                    packet.position(recLim);
                    return null;
                }
            } catch (Throwable th) {
                packet.limit(srcLim);
                packet.position(recLim);
                throw th;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // org.openjsse.sun.security.ssl.InputRecord
    public int bytesInCompletePacket(ByteBuffer[] srcs, int srcsOffset, int srcsLength) throws IOException {
        return bytesInCompletePacket(srcs[srcsOffset]);
    }

    private int bytesInCompletePacket(ByteBuffer packet) throws SSLException {
        if (packet.remaining() < 13) {
            return -1;
        }
        int pos = packet.position();
        byte contentType = packet.get(pos);
        if (ContentType.valueOf(contentType) == null) {
            throw new SSLException("Unrecognized SSL message, plaintext connection?");
        }
        byte majorVersion = packet.get(pos + 1);
        byte minorVersion = packet.get(pos + 2);
        if (!ProtocolVersion.isNegotiable(majorVersion, minorVersion, true, false)) {
            throw new SSLException("Unrecognized record version " + ProtocolVersion.nameOf(majorVersion, minorVersion) + " , plaintext connection?");
        }
        int fragLen = ((packet.get(pos + 11) & 255) << 8) + (packet.get(pos + 12) & 255) + 13;
        if (fragLen > 18432) {
            throw new SSLException("Record overflow, fragment length (" + fragLen + ") MUST not exceed " + Record.maxFragmentSize);
        }
        return fragLen;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static HandshakeFragment parseHandshakeMessage(byte contentType, byte majorVersion, byte minorVersion, byte[] recordEnS, int recordEpoch, long recordSeq, ByteBuffer plaintextFragment) {
        int remaining = plaintextFragment.remaining();
        if (remaining < 12) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.fine("Discard invalid record: too small record to hold a handshake fragment", new Object[0]);
                return null;
            }
            return null;
        }
        byte handshakeType = plaintextFragment.get();
        int messageLength = ((plaintextFragment.get() & 255) << 16) | ((plaintextFragment.get() & 255) << 8) | (plaintextFragment.get() & 255);
        int messageSeq = ((plaintextFragment.get() & 255) << 8) | (plaintextFragment.get() & 255);
        int fragmentOffset = ((plaintextFragment.get() & 255) << 16) | ((plaintextFragment.get() & 255) << 8) | (plaintextFragment.get() & 255);
        int fragmentLength = ((plaintextFragment.get() & 255) << 16) | ((plaintextFragment.get() & 255) << 8) | (plaintextFragment.get() & 255);
        if (remaining - 12 < fragmentLength) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                SSLLogger.fine("Discard invalid record: not a complete handshake fragment in the record", new Object[0]);
                return null;
            }
            return null;
        }
        byte[] fragment = new byte[fragmentLength];
        plaintextFragment.get(fragment);
        return new HandshakeFragment(fragment, contentType, majorVersion, minorVersion, recordEnS, recordEpoch, recordSeq, handshakeType, messageLength, messageSeq, fragmentOffset, fragmentLength);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/DTLSInputRecord$RecordFragment.class */
    public static class RecordFragment implements Comparable<RecordFragment> {
        boolean isCiphertext;
        byte contentType;
        byte majorVersion;
        byte minorVersion;
        int recordEpoch;
        long recordSeq;
        byte[] recordEnS;
        byte[] fragment;

        RecordFragment(ByteBuffer fragBuf, byte contentType, byte majorVersion, byte minorVersion, byte[] recordEnS, int recordEpoch, long recordSeq, boolean isCiphertext) {
            this((byte[]) null, contentType, majorVersion, minorVersion, recordEnS, recordEpoch, recordSeq, isCiphertext);
            this.fragment = new byte[fragBuf.remaining()];
            fragBuf.get(this.fragment);
        }

        RecordFragment(byte[] fragment, byte contentType, byte majorVersion, byte minorVersion, byte[] recordEnS, int recordEpoch, long recordSeq, boolean isCiphertext) {
            this.isCiphertext = isCiphertext;
            this.contentType = contentType;
            this.majorVersion = majorVersion;
            this.minorVersion = minorVersion;
            this.recordEpoch = recordEpoch;
            this.recordSeq = recordSeq;
            this.recordEnS = recordEnS;
            this.fragment = fragment;
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // java.lang.Comparable
        public int compareTo(RecordFragment o) {
            if (this.contentType == ContentType.CHANGE_CIPHER_SPEC.f965id) {
                if (o.contentType == ContentType.CHANGE_CIPHER_SPEC.f965id) {
                    return Integer.compare(this.recordEpoch, o.recordEpoch);
                }
                if (this.recordEpoch == o.recordEpoch && o.contentType == ContentType.HANDSHAKE.f965id) {
                    return 1;
                }
            } else if (o.contentType == ContentType.CHANGE_CIPHER_SPEC.f965id) {
                if (this.recordEpoch == o.recordEpoch && this.contentType == ContentType.HANDSHAKE.f965id) {
                    return -1;
                }
                return compareToSequence(o.recordEpoch, o.recordSeq);
            }
            return compareToSequence(o.recordEpoch, o.recordSeq);
        }

        int compareToSequence(int epoch, long seq) {
            if (this.recordEpoch > epoch) {
                return 1;
            }
            if (this.recordEpoch == epoch) {
                return Long.compare(this.recordSeq, seq);
            }
            return -1;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/DTLSInputRecord$HandshakeFragment.class */
    public static final class HandshakeFragment extends RecordFragment {
        byte handshakeType;
        int messageSeq;
        int messageLength;
        int fragmentOffset;
        int fragmentLength;

        HandshakeFragment(byte[] fragment, byte contentType, byte majorVersion, byte minorVersion, byte[] recordEnS, int recordEpoch, long recordSeq, byte handshakeType, int messageLength, int messageSeq, int fragmentOffset, int fragmentLength) {
            super(fragment, contentType, majorVersion, minorVersion, recordEnS, recordEpoch, recordSeq, false);
            this.handshakeType = handshakeType;
            this.messageSeq = messageSeq;
            this.messageLength = messageLength;
            this.fragmentOffset = fragmentOffset;
            this.fragmentLength = fragmentLength;
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // org.openjsse.sun.security.ssl.DTLSInputRecord.RecordFragment, java.lang.Comparable
        public int compareTo(RecordFragment o) {
            if (o instanceof HandshakeFragment) {
                HandshakeFragment other = (HandshakeFragment) o;
                if (this.messageSeq != other.messageSeq) {
                    return this.messageSeq - other.messageSeq;
                }
                if (this.fragmentOffset != other.fragmentOffset) {
                    return this.fragmentOffset - other.fragmentOffset;
                }
                if (this.fragmentLength == other.fragmentLength) {
                    return 0;
                }
                return compareToSequence(o.recordEpoch, o.recordSeq);
            }
            return super.compareTo(o);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/DTLSInputRecord$HoleDescriptor.class */
    public static final class HoleDescriptor {
        int offset;
        int limit;

        HoleDescriptor(int offset, int limit) {
            this.offset = offset;
            this.limit = limit;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/DTLSInputRecord$HandshakeFlight.class */
    public static final class HandshakeFlight implements Cloneable {
        static final byte HF_UNKNOWN = SSLHandshake.NOT_APPLICABLE.f987id;
        byte handshakeType = HF_UNKNOWN;
        int flightEpoch = 0;
        int minMessageSeq = 0;
        int maxMessageSeq = 0;
        int maxRecordEpoch = 0;
        long maxRecordSeq = -1;
        HashMap<Byte, List<HoleDescriptor>> holesMap = new HashMap<>(5);

        HandshakeFlight() {
        }

        boolean isRetransmitOf(HandshakeFlight hs) {
            return hs != null && this.handshakeType == hs.handshakeType && this.minMessageSeq == hs.minMessageSeq;
        }

        public Object clone() {
            HandshakeFlight hf = new HandshakeFlight();
            hf.handshakeType = this.handshakeType;
            hf.flightEpoch = this.flightEpoch;
            hf.minMessageSeq = this.minMessageSeq;
            hf.maxMessageSeq = this.maxMessageSeq;
            hf.maxRecordEpoch = this.maxRecordEpoch;
            hf.maxRecordSeq = this.maxRecordSeq;
            hf.holesMap = new HashMap<>(this.holesMap);
            return hf;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/DTLSInputRecord$DTLSReassembler.class */
    public final class DTLSReassembler {
        final int handshakeEpoch;
        int nextRecordEpoch;
        TreeSet<RecordFragment> bufferedFragments = new TreeSet<>();
        HandshakeFlight handshakeFlight = new HandshakeFlight();
        HandshakeFlight precedingFlight = null;
        long nextRecordSeq = 0;
        boolean expectCCSFlight = false;
        boolean flightIsReady = false;
        boolean needToCheckFlight = false;

        DTLSReassembler(int handshakeEpoch) {
            this.handshakeEpoch = handshakeEpoch;
            this.nextRecordEpoch = handshakeEpoch;
            this.handshakeFlight.flightEpoch = handshakeEpoch;
        }

        void expectingFinishFlight() {
            this.expectCCSFlight = true;
        }

        void queueUpHandshake(HandshakeFragment hsf) {
            if (!isDesirable(hsf)) {
                return;
            }
            cleanUpRetransmit(hsf);
            boolean isMinimalFlightMessage = false;
            if (this.handshakeFlight.minMessageSeq == hsf.messageSeq) {
                isMinimalFlightMessage = true;
            } else if (this.precedingFlight != null && this.precedingFlight.minMessageSeq == hsf.messageSeq) {
                isMinimalFlightMessage = true;
            }
            if (isMinimalFlightMessage && hsf.fragmentOffset == 0 && hsf.handshakeType != SSLHandshake.FINISHED.f987id) {
                this.handshakeFlight.handshakeType = hsf.handshakeType;
                this.handshakeFlight.flightEpoch = hsf.recordEpoch;
                this.handshakeFlight.minMessageSeq = hsf.messageSeq;
            }
            if (hsf.handshakeType == SSLHandshake.FINISHED.f987id) {
                this.handshakeFlight.maxMessageSeq = hsf.messageSeq;
                this.handshakeFlight.maxRecordEpoch = hsf.recordEpoch;
                this.handshakeFlight.maxRecordSeq = hsf.recordSeq;
            } else {
                if (this.handshakeFlight.maxMessageSeq < hsf.messageSeq) {
                    this.handshakeFlight.maxMessageSeq = hsf.messageSeq;
                }
                int n = hsf.recordEpoch - this.handshakeFlight.maxRecordEpoch;
                if (n > 0) {
                    this.handshakeFlight.maxRecordEpoch = hsf.recordEpoch;
                    this.handshakeFlight.maxRecordSeq = hsf.recordSeq;
                } else if (n == 0 && this.handshakeFlight.maxRecordSeq < hsf.recordSeq) {
                    this.handshakeFlight.maxRecordSeq = hsf.recordSeq;
                }
            }
            boolean fragmented = false;
            if (hsf.fragmentOffset != 0 || hsf.fragmentLength != hsf.messageLength) {
                fragmented = true;
            }
            List<HoleDescriptor> holes = this.handshakeFlight.holesMap.get(Byte.valueOf(hsf.handshakeType));
            if (holes == null) {
                if (!fragmented) {
                    holes = Collections.emptyList();
                } else {
                    holes = new LinkedList<>();
                    holes.add(new HoleDescriptor(0, hsf.messageLength));
                }
                this.handshakeFlight.holesMap.put(Byte.valueOf(hsf.handshakeType), holes);
            } else if (holes.isEmpty()) {
                if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                    SSLLogger.fine("Have got the full message, discard it.", new Object[0]);
                    return;
                }
                return;
            }
            if (fragmented) {
                int fragmentLimit = hsf.fragmentOffset + hsf.fragmentLength;
                int i = 0;
                while (true) {
                    if (i >= holes.size()) {
                        break;
                    }
                    HoleDescriptor hole = holes.get(i);
                    if (hole.limit <= hsf.fragmentOffset || hole.offset >= fragmentLimit) {
                        i++;
                    } else if ((hole.offset > hsf.fragmentOffset && hole.offset < fragmentLimit) || (hole.limit > hsf.fragmentOffset && hole.limit < fragmentLimit)) {
                        if (SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                            SSLLogger.fine("Discard invalid record: handshake fragment ranges are overlapping", new Object[0]);
                            return;
                        }
                        return;
                    } else {
                        holes.remove(i);
                        if (hsf.fragmentOffset > hole.offset) {
                            holes.add(new HoleDescriptor(hole.offset, hsf.fragmentOffset));
                        }
                        if (fragmentLimit < hole.limit) {
                            holes.add(new HoleDescriptor(fragmentLimit, hole.limit));
                        }
                    }
                }
            }
            if (hsf.handshakeType == SSLHandshake.FINISHED.f987id) {
                this.bufferedFragments.add(hsf);
            } else {
                bufferFragment(hsf);
            }
        }

        void queueUpChangeCipherSpec(RecordFragment rf) {
            if (!isDesirable(rf)) {
                return;
            }
            cleanUpRetransmit(rf);
            if (this.expectCCSFlight) {
                this.handshakeFlight.handshakeType = HandshakeFlight.HF_UNKNOWN;
                this.handshakeFlight.flightEpoch = rf.recordEpoch;
            }
            if (this.handshakeFlight.maxRecordSeq < rf.recordSeq) {
                this.handshakeFlight.maxRecordSeq = rf.recordSeq;
            }
            bufferFragment(rf);
        }

        void queueUpFragment(RecordFragment rf) {
            if (!isDesirable(rf)) {
                return;
            }
            cleanUpRetransmit(rf);
            bufferFragment(rf);
        }

        private void bufferFragment(RecordFragment rf) {
            this.bufferedFragments.add(rf);
            if (this.flightIsReady) {
                this.flightIsReady = false;
            }
            if (!this.needToCheckFlight) {
                this.needToCheckFlight = true;
            }
        }

        private void cleanUpRetransmit(RecordFragment rf) {
            boolean isNewFlight = false;
            if (this.precedingFlight != null) {
                if (this.precedingFlight.flightEpoch < rf.recordEpoch) {
                    isNewFlight = true;
                } else if (rf instanceof HandshakeFragment) {
                    HandshakeFragment hsf = (HandshakeFragment) rf;
                    if (this.precedingFlight.maxMessageSeq < hsf.messageSeq) {
                        isNewFlight = true;
                    }
                } else if (rf.contentType != ContentType.CHANGE_CIPHER_SPEC.f965id && this.precedingFlight.maxRecordEpoch < rf.recordEpoch) {
                    isNewFlight = true;
                }
            }
            if (!isNewFlight) {
                return;
            }
            Iterator<RecordFragment> it = this.bufferedFragments.iterator();
            while (it.hasNext()) {
                RecordFragment frag = it.next();
                boolean isOld = false;
                if (frag.recordEpoch < this.precedingFlight.maxRecordEpoch) {
                    isOld = true;
                } else if (frag.recordEpoch == this.precedingFlight.maxRecordEpoch && frag.recordSeq <= this.precedingFlight.maxRecordSeq) {
                    isOld = true;
                }
                if (!isOld && (frag instanceof HandshakeFragment)) {
                    HandshakeFragment hsf2 = (HandshakeFragment) frag;
                    isOld = hsf2.messageSeq <= this.precedingFlight.maxMessageSeq;
                }
                if (!isOld) {
                    break;
                }
                it.remove();
            }
            this.precedingFlight = null;
        }

        private boolean isDesirable(RecordFragment rf) {
            int previousEpoch = this.nextRecordEpoch - 1;
            if (rf.recordEpoch < previousEpoch) {
                if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                    SSLLogger.fine("Too old epoch to use this record, discard it.", new Object[0]);
                    return false;
                }
                return false;
            } else if (rf.recordEpoch != previousEpoch) {
                if (rf.recordEpoch == this.nextRecordEpoch && this.nextRecordSeq > rf.recordSeq) {
                    if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                        SSLLogger.fine("Lagging behind record (sequence), discard it.", new Object[0]);
                        return false;
                    }
                    return false;
                }
                return true;
            } else {
                boolean isDesired = true;
                if (this.precedingFlight == null) {
                    isDesired = false;
                } else if (rf instanceof HandshakeFragment) {
                    HandshakeFragment hsf = (HandshakeFragment) rf;
                    if (this.precedingFlight.minMessageSeq > hsf.messageSeq) {
                        isDesired = false;
                    }
                } else if (rf.contentType == ContentType.CHANGE_CIPHER_SPEC.f965id) {
                    if (this.precedingFlight.flightEpoch != rf.recordEpoch) {
                        isDesired = false;
                    }
                } else if (rf.recordEpoch < this.precedingFlight.maxRecordEpoch || (rf.recordEpoch == this.precedingFlight.maxRecordEpoch && rf.recordSeq <= this.precedingFlight.maxRecordSeq)) {
                    isDesired = false;
                }
                if (!isDesired) {
                    if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                        SSLLogger.fine("Too old retransmission to use, discard it.", new Object[0]);
                        return false;
                    }
                    return false;
                }
                return true;
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public boolean isEmpty() {
            return this.bufferedFragments.isEmpty() || !(this.flightIsReady || this.needToCheckFlight) || (this.needToCheckFlight && !flightIsReady());
        }

        Plaintext acquirePlaintext() {
            Plaintext plaintext;
            if (this.bufferedFragments.isEmpty()) {
                if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                    SSLLogger.fine("No received handshake messages", new Object[0]);
                    return null;
                }
                return null;
            }
            if (!this.flightIsReady && this.needToCheckFlight) {
                this.flightIsReady = flightIsReady();
                if (this.flightIsReady && this.handshakeFlight.isRetransmitOf(this.precedingFlight)) {
                    this.bufferedFragments.clear();
                    resetHandshakeFlight(this.precedingFlight);
                    if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                        SSLLogger.fine("Received a retransmission flight.", new Object[0]);
                    }
                    return Plaintext.PLAINTEXT_NULL;
                }
                this.needToCheckFlight = false;
            }
            if (!this.flightIsReady) {
                if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                    SSLLogger.fine("The handshake flight is not ready to use: " + ((int) this.handshakeFlight.handshakeType), new Object[0]);
                    return null;
                }
                return null;
            }
            RecordFragment rFrag = this.bufferedFragments.first();
            if (!rFrag.isCiphertext) {
                plaintext = acquireHandshakeMessage();
                if (this.bufferedFragments.isEmpty()) {
                    this.handshakeFlight.holesMap.clear();
                    this.precedingFlight = (HandshakeFlight) this.handshakeFlight.clone();
                    resetHandshakeFlight(this.precedingFlight);
                    if (this.expectCCSFlight && this.precedingFlight.handshakeType == HandshakeFlight.HF_UNKNOWN) {
                        this.expectCCSFlight = false;
                    }
                }
            } else {
                plaintext = acquireCachedMessage();
            }
            return plaintext;
        }

        private void resetHandshakeFlight(HandshakeFlight prev) {
            this.handshakeFlight.handshakeType = HandshakeFlight.HF_UNKNOWN;
            this.handshakeFlight.flightEpoch = prev.maxRecordEpoch;
            if (prev.flightEpoch != prev.maxRecordEpoch) {
                this.handshakeFlight.minMessageSeq = 0;
            } else {
                this.handshakeFlight.minMessageSeq = prev.maxMessageSeq + 1;
            }
            this.handshakeFlight.maxMessageSeq = 0;
            this.handshakeFlight.maxRecordEpoch = this.handshakeFlight.flightEpoch;
            this.handshakeFlight.maxRecordSeq = prev.maxRecordSeq + 1;
            this.handshakeFlight.holesMap.clear();
            this.flightIsReady = false;
            this.needToCheckFlight = false;
        }

        private Plaintext acquireCachedMessage() {
            RecordFragment rFrag = this.bufferedFragments.first();
            if (DTLSInputRecord.this.readEpoch != rFrag.recordEpoch) {
                if (DTLSInputRecord.this.readEpoch > rFrag.recordEpoch) {
                    if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                        SSLLogger.fine("Discard old buffered ciphertext fragments.", new Object[0]);
                    }
                    this.bufferedFragments.remove(rFrag);
                }
                if (this.flightIsReady) {
                    this.flightIsReady = false;
                }
                if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                    SSLLogger.fine("Not yet ready to decrypt the cached fragments.", new Object[0]);
                    return null;
                }
                return null;
            }
            this.bufferedFragments.remove(rFrag);
            ByteBuffer fragment = ByteBuffer.wrap(rFrag.fragment);
            try {
                Plaintext plaintext = DTLSInputRecord.this.readCipher.decrypt(rFrag.contentType, fragment, rFrag.recordEnS);
                ByteBuffer plaintextFragment = plaintext.fragment;
                rFrag.contentType = plaintext.contentType;
                if (rFrag.contentType == ContentType.HANDSHAKE.f965id) {
                    while (plaintextFragment.remaining() > 0) {
                        HandshakeFragment hsFrag = DTLSInputRecord.parseHandshakeMessage(rFrag.contentType, rFrag.majorVersion, rFrag.minorVersion, rFrag.recordEnS, rFrag.recordEpoch, rFrag.recordSeq, plaintextFragment);
                        if (hsFrag == null) {
                            if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                                SSLLogger.fine("Invalid handshake fragment, discard it", plaintextFragment);
                                return null;
                            }
                            return null;
                        }
                        queueUpHandshake(hsFrag);
                        if (hsFrag.handshakeType != SSLHandshake.FINISHED.f987id) {
                            this.flightIsReady = false;
                            this.needToCheckFlight = true;
                        }
                    }
                    return acquirePlaintext();
                }
                return new Plaintext(rFrag.contentType, rFrag.majorVersion, rFrag.minorVersion, rFrag.recordEpoch, Authenticator.toLong(rFrag.recordEnS), plaintextFragment);
            } catch (GeneralSecurityException gse) {
                if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                    SSLLogger.fine("Discard invalid record: ", gse);
                    return null;
                }
                return null;
            }
        }

        /* JADX WARN: Multi-variable type inference failed */
        private Plaintext acquireHandshakeMessage() {
            RecordFragment rFrag = this.bufferedFragments.first();
            if (rFrag.contentType == ContentType.CHANGE_CIPHER_SPEC.f965id) {
                this.nextRecordEpoch = rFrag.recordEpoch + 1;
                this.nextRecordSeq = 0L;
                this.bufferedFragments.remove(rFrag);
                return new Plaintext(rFrag.contentType, rFrag.majorVersion, rFrag.minorVersion, rFrag.recordEpoch, Authenticator.toLong(rFrag.recordEnS), ByteBuffer.wrap(rFrag.fragment));
            }
            HandshakeFragment hsFrag = (HandshakeFragment) rFrag;
            if (hsFrag.messageLength == hsFrag.fragmentLength && hsFrag.fragmentOffset == 0) {
                this.bufferedFragments.remove(rFrag);
                this.nextRecordSeq = hsFrag.recordSeq + 1;
                byte[] recordFrag = new byte[hsFrag.messageLength + 4];
                Plaintext plaintext = new Plaintext(hsFrag.contentType, hsFrag.majorVersion, hsFrag.minorVersion, hsFrag.recordEpoch, Authenticator.toLong(hsFrag.recordEnS), ByteBuffer.wrap(recordFrag));
                recordFrag[0] = hsFrag.handshakeType;
                recordFrag[1] = (byte) ((hsFrag.messageLength >>> 16) & GF2Field.MASK);
                recordFrag[2] = (byte) ((hsFrag.messageLength >>> 8) & GF2Field.MASK);
                recordFrag[3] = (byte) (hsFrag.messageLength & GF2Field.MASK);
                System.arraycopy(hsFrag.fragment, 0, recordFrag, 4, hsFrag.fragmentLength);
                handshakeHashing(hsFrag, plaintext);
                return plaintext;
            }
            byte[] recordFrag2 = new byte[hsFrag.messageLength + 4];
            Plaintext plaintext2 = new Plaintext(hsFrag.contentType, hsFrag.majorVersion, hsFrag.minorVersion, hsFrag.recordEpoch, Authenticator.toLong(hsFrag.recordEnS), ByteBuffer.wrap(recordFrag2));
            recordFrag2[0] = hsFrag.handshakeType;
            recordFrag2[1] = (byte) ((hsFrag.messageLength >>> 16) & GF2Field.MASK);
            recordFrag2[2] = (byte) ((hsFrag.messageLength >>> 8) & GF2Field.MASK);
            recordFrag2[3] = (byte) (hsFrag.messageLength & GF2Field.MASK);
            int msgSeq = hsFrag.messageSeq;
            long maxRecodeSN = hsFrag.recordSeq;
            HandshakeFragment hmFrag = hsFrag;
            do {
                System.arraycopy(hmFrag.fragment, 0, recordFrag2, hmFrag.fragmentOffset + 4, hmFrag.fragmentLength);
                this.bufferedFragments.remove(rFrag);
                if (maxRecodeSN < hmFrag.recordSeq) {
                    maxRecodeSN = hmFrag.recordSeq;
                }
                if (!this.bufferedFragments.isEmpty()) {
                    rFrag = this.bufferedFragments.first();
                    if (rFrag.contentType != ContentType.HANDSHAKE.f965id) {
                        break;
                    }
                    hmFrag = (HandshakeFragment) rFrag;
                }
                if (this.bufferedFragments.isEmpty()) {
                    break;
                }
            } while (msgSeq == hmFrag.messageSeq);
            handshakeHashing(hsFrag, plaintext2);
            this.nextRecordSeq = maxRecodeSN + 1;
            return plaintext2;
        }

        boolean flightIsReady() {
            byte flightType = this.handshakeFlight.handshakeType;
            if (flightType == HandshakeFlight.HF_UNKNOWN) {
                if (this.expectCCSFlight) {
                    boolean isReady = hasFinishedMessage(this.bufferedFragments);
                    if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                        SSLLogger.fine("Has the final flight been received? " + isReady, new Object[0]);
                    }
                    return isReady;
                } else if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                    SSLLogger.fine("No flight is received yet.", new Object[0]);
                    return false;
                } else {
                    return false;
                }
            } else if (flightType == SSLHandshake.CLIENT_HELLO.f987id || flightType == SSLHandshake.HELLO_REQUEST.f987id || flightType == SSLHandshake.HELLO_VERIFY_REQUEST.f987id) {
                boolean isReady2 = hasCompleted(flightType);
                if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                    SSLLogger.fine("Is the handshake message completed? " + isReady2, new Object[0]);
                }
                return isReady2;
            } else if (flightType == SSLHandshake.SERVER_HELLO.f987id) {
                if (!hasCompleted(flightType)) {
                    if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                        SSLLogger.fine("The ServerHello message is not completed yet.", new Object[0]);
                        return false;
                    }
                    return false;
                } else if (hasFinishedMessage(this.bufferedFragments)) {
                    if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                        SSLLogger.fine("It's an abbreviated handshake.", new Object[0]);
                        return true;
                    }
                    return true;
                } else {
                    List<HoleDescriptor> holes = this.handshakeFlight.holesMap.get(Byte.valueOf(SSLHandshake.SERVER_HELLO_DONE.f987id));
                    if (holes == null || !holes.isEmpty()) {
                        if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                            SSLLogger.fine("Not yet got the ServerHelloDone message", new Object[0]);
                            return false;
                        }
                        return false;
                    }
                    boolean isReady3 = hasCompleted(this.bufferedFragments, this.handshakeFlight.minMessageSeq, this.handshakeFlight.maxMessageSeq);
                    if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                        SSLLogger.fine("Is the ServerHello flight (message " + this.handshakeFlight.minMessageSeq + "-" + this.handshakeFlight.maxMessageSeq + ") completed? " + isReady3, new Object[0]);
                    }
                    return isReady3;
                }
            } else if (flightType == SSLHandshake.CERTIFICATE.f987id || flightType == SSLHandshake.CLIENT_KEY_EXCHANGE.f987id) {
                if (!hasCompleted(flightType)) {
                    if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                        SSLLogger.fine("The ClientKeyExchange or client Certificate message is not completed yet.", new Object[0]);
                        return false;
                    }
                    return false;
                } else if (flightType == SSLHandshake.CERTIFICATE.f987id && needClientVerify(this.bufferedFragments) && !hasCompleted(SSLHandshake.CERTIFICATE_VERIFY.f987id)) {
                    if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                        SSLLogger.fine("Not yet have the CertificateVerify message", new Object[0]);
                        return false;
                    }
                    return false;
                } else if (!hasFinishedMessage(this.bufferedFragments)) {
                    if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                        SSLLogger.fine("Not yet have the ChangeCipherSpec and Finished messages", new Object[0]);
                        return false;
                    }
                    return false;
                } else {
                    boolean isReady4 = hasCompleted(this.bufferedFragments, this.handshakeFlight.minMessageSeq, this.handshakeFlight.maxMessageSeq);
                    if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                        SSLLogger.fine("Is the ClientKeyExchange flight (message " + this.handshakeFlight.minMessageSeq + "-" + this.handshakeFlight.maxMessageSeq + ") completed? " + isReady4, new Object[0]);
                    }
                    return isReady4;
                }
            } else if (SSLLogger.isOn && SSLLogger.isOn("verbose")) {
                SSLLogger.fine("Need to receive more handshake messages", new Object[0]);
                return false;
            } else {
                return false;
            }
        }

        private boolean hasFinishedMessage(Set<RecordFragment> fragments) {
            boolean hasCCS = false;
            boolean hasFin = false;
            for (RecordFragment fragment : fragments) {
                if (fragment.contentType == ContentType.CHANGE_CIPHER_SPEC.f965id) {
                    if (hasFin) {
                        return true;
                    }
                    hasCCS = true;
                } else if (fragment.contentType == ContentType.HANDSHAKE.f965id && fragment.isCiphertext) {
                    if (hasCCS) {
                        return true;
                    }
                    hasFin = true;
                }
            }
            return hasFin && hasCCS;
        }

        private boolean needClientVerify(Set<RecordFragment> fragments) {
            for (RecordFragment rFrag : fragments) {
                if (rFrag.contentType == ContentType.HANDSHAKE.f965id && !rFrag.isCiphertext) {
                    HandshakeFragment hsFrag = (HandshakeFragment) rFrag;
                    if (hsFrag.handshakeType == SSLHandshake.CERTIFICATE.f987id) {
                        return rFrag.fragment != null && rFrag.fragment.length > 28;
                    }
                } else {
                    return false;
                }
            }
            return false;
        }

        private boolean hasCompleted(byte handshakeType) {
            List<HoleDescriptor> holes = this.handshakeFlight.holesMap.get(Byte.valueOf(handshakeType));
            if (holes == null) {
                return false;
            }
            return holes.isEmpty();
        }

        private boolean hasCompleted(Set<RecordFragment> fragments, int presentMsgSeq, int endMsgSeq) {
            for (RecordFragment rFrag : fragments) {
                if (rFrag.contentType != ContentType.HANDSHAKE.f965id || rFrag.isCiphertext) {
                    break;
                }
                HandshakeFragment hsFrag = (HandshakeFragment) rFrag;
                if (hsFrag.messageSeq != presentMsgSeq) {
                    if (hsFrag.messageSeq != presentMsgSeq + 1) {
                        break;
                    } else if (!hasCompleted(hsFrag.handshakeType)) {
                        return false;
                    } else {
                        presentMsgSeq = hsFrag.messageSeq;
                    }
                }
            }
            return presentMsgSeq >= endMsgSeq;
        }

        private void handshakeHashing(HandshakeFragment hsFrag, Plaintext plaintext) {
            byte hsType = hsFrag.handshakeType;
            if (!DTLSInputRecord.this.handshakeHash.isHashable(hsType)) {
                return;
            }
            plaintext.fragment.position(4);
            byte[] temporary = new byte[plaintext.fragment.remaining() + 12];
            temporary[0] = hsFrag.handshakeType;
            temporary[1] = (byte) ((hsFrag.messageLength >> 16) & GF2Field.MASK);
            temporary[2] = (byte) ((hsFrag.messageLength >> 8) & GF2Field.MASK);
            temporary[3] = (byte) (hsFrag.messageLength & GF2Field.MASK);
            temporary[4] = (byte) ((hsFrag.messageSeq >> 8) & GF2Field.MASK);
            temporary[5] = (byte) (hsFrag.messageSeq & GF2Field.MASK);
            temporary[6] = 0;
            temporary[7] = 0;
            temporary[8] = 0;
            temporary[9] = temporary[1];
            temporary[10] = temporary[2];
            temporary[11] = temporary[3];
            plaintext.fragment.get(temporary, 12, plaintext.fragment.remaining());
            DTLSInputRecord.this.handshakeHash.receive(temporary);
            plaintext.fragment.position(0);
        }
    }
}