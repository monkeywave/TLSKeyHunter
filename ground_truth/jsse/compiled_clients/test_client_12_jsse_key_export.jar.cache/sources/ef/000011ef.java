package org.openjsse.sun.security.ssl;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.cert.Extension;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.openjsse.sun.security.ssl.CertStatusExtension;
import org.openjsse.sun.security.ssl.SSLExtension;
import org.openjsse.sun.security.ssl.X509Authentication;
import org.openjsse.sun.security.util.Cache;
import sun.security.action.GetBooleanAction;
import sun.security.action.GetIntegerAction;
import sun.security.action.GetPropertyAction;
import sun.security.provider.certpath.CertId;
import sun.security.provider.certpath.OCSP;
import sun.security.provider.certpath.OCSPResponse;
import sun.security.provider.certpath.ResponderId;
import sun.security.x509.PKIXExtensions;
import sun.security.x509.SerialNumber;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/StatusResponseManager.class */
public final class StatusResponseManager {
    private static final int DEFAULT_CORE_THREADS = 8;
    private static final int DEFAULT_CACHE_SIZE = 256;
    private static final int DEFAULT_CACHE_LIFETIME = 3600;
    private final ScheduledThreadPoolExecutor threadMgr;
    private final Cache<CertId, ResponseCacheEntry> responseCache;
    private final URI defaultResponder;
    private final boolean respOverride;
    private final int cacheCapacity;
    private final int cacheLifetime;
    private final boolean ignoreExtensions;

    /* JADX INFO: Access modifiers changed from: package-private */
    public StatusResponseManager() {
        URI tmpURI;
        URI uri;
        int cap = ((Integer) AccessController.doPrivileged((PrivilegedAction<Object>) new GetIntegerAction("jdk.tls.stapling.cacheSize", 256))).intValue();
        this.cacheCapacity = cap > 0 ? cap : 0;
        int life = ((Integer) AccessController.doPrivileged((PrivilegedAction<Object>) new GetIntegerAction("jdk.tls.stapling.cacheLifetime", (int) DEFAULT_CACHE_LIFETIME))).intValue();
        this.cacheLifetime = life > 0 ? life : 0;
        String uriStr = GetPropertyAction.privilegedGetProperty("jdk.tls.stapling.responderURI");
        if (uriStr != null) {
            try {
            } catch (URISyntaxException e) {
                tmpURI = null;
            }
            if (!uriStr.isEmpty()) {
                uri = new URI(uriStr);
                tmpURI = uri;
                this.defaultResponder = tmpURI;
                this.respOverride = ((Boolean) AccessController.doPrivileged((PrivilegedAction<Object>) new GetBooleanAction("jdk.tls.stapling.responderOverride"))).booleanValue();
                this.ignoreExtensions = ((Boolean) AccessController.doPrivileged((PrivilegedAction<Object>) new GetBooleanAction("jdk.tls.stapling.ignoreExtensions"))).booleanValue();
                this.threadMgr = new ScheduledThreadPoolExecutor(8, new ThreadFactory() { // from class: org.openjsse.sun.security.ssl.StatusResponseManager.1
                    @Override // java.util.concurrent.ThreadFactory
                    public Thread newThread(Runnable r) {
                        Thread t = Executors.defaultThreadFactory().newThread(r);
                        t.setDaemon(true);
                        return t;
                    }
                }, new ThreadPoolExecutor.DiscardPolicy());
                this.threadMgr.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
                this.threadMgr.setContinueExistingPeriodicTasksAfterShutdownPolicy(false);
                this.threadMgr.setKeepAliveTime(5000L, TimeUnit.MILLISECONDS);
                this.threadMgr.allowCoreThreadTimeOut(true);
                this.responseCache = Cache.newSoftMemoryCache(this.cacheCapacity, this.cacheLifetime);
            }
        }
        uri = null;
        tmpURI = uri;
        this.defaultResponder = tmpURI;
        this.respOverride = ((Boolean) AccessController.doPrivileged((PrivilegedAction<Object>) new GetBooleanAction("jdk.tls.stapling.responderOverride"))).booleanValue();
        this.ignoreExtensions = ((Boolean) AccessController.doPrivileged((PrivilegedAction<Object>) new GetBooleanAction("jdk.tls.stapling.ignoreExtensions"))).booleanValue();
        this.threadMgr = new ScheduledThreadPoolExecutor(8, new ThreadFactory() { // from class: org.openjsse.sun.security.ssl.StatusResponseManager.1
            @Override // java.util.concurrent.ThreadFactory
            public Thread newThread(Runnable r) {
                Thread t = Executors.defaultThreadFactory().newThread(r);
                t.setDaemon(true);
                return t;
            }
        }, new ThreadPoolExecutor.DiscardPolicy());
        this.threadMgr.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
        this.threadMgr.setContinueExistingPeriodicTasksAfterShutdownPolicy(false);
        this.threadMgr.setKeepAliveTime(5000L, TimeUnit.MILLISECONDS);
        this.threadMgr.allowCoreThreadTimeOut(true);
        this.responseCache = Cache.newSoftMemoryCache(this.cacheCapacity, this.cacheLifetime);
    }

    int getCacheLifetime() {
        return this.cacheLifetime;
    }

    int getCacheCapacity() {
        return this.cacheCapacity;
    }

    URI getDefaultResponder() {
        return this.defaultResponder;
    }

    boolean getURIOverride() {
        return this.respOverride;
    }

    boolean getIgnoreExtensions() {
        return this.ignoreExtensions;
    }

    void clear() {
        if (SSLLogger.isOn && SSLLogger.isOn("respmgr")) {
            SSLLogger.fine("Clearing response cache", new Object[0]);
        }
        this.responseCache.clear();
    }

    int size() {
        return this.responseCache.size();
    }

    URI getURI(X509Certificate cert) {
        Objects.requireNonNull(cert);
        if (cert.getExtensionValue(PKIXExtensions.OCSPNoCheck_Id.toString()) != null) {
            if (SSLLogger.isOn && SSLLogger.isOn("respmgr")) {
                SSLLogger.fine("OCSP NoCheck extension found.  OCSP will be skipped", new Object[0]);
                return null;
            }
            return null;
        } else if (this.defaultResponder != null && this.respOverride) {
            if (SSLLogger.isOn && SSLLogger.isOn("respmgr")) {
                SSLLogger.fine("Responder override: URI is " + this.defaultResponder, new Object[0]);
            }
            return this.defaultResponder;
        } else {
            URI certURI = OCSP.getResponderURI(cert);
            return certURI != null ? certURI : this.defaultResponder;
        }
    }

    void shutdown() {
        if (SSLLogger.isOn && SSLLogger.isOn("respmgr")) {
            SSLLogger.fine("Shutting down " + this.threadMgr.getActiveCount() + " active threads", new Object[0]);
        }
        this.threadMgr.shutdown();
    }

    Map<X509Certificate, byte[]> get(CertStatusExtension.CertStatusRequestType type, CertStatusExtension.CertStatusRequest request, X509Certificate[] chain, long delay, TimeUnit unit) {
        Map<X509Certificate, byte[]> responseMap = new HashMap<>();
        List<OCSPFetchCall> requestList = new ArrayList<>();
        if (SSLLogger.isOn && SSLLogger.isOn("respmgr")) {
            SSLLogger.fine("Beginning check: Type = " + type + ", Chain length = " + chain.length, new Object[0]);
        }
        if (chain.length < 2) {
            return Collections.emptyMap();
        }
        if (type == CertStatusExtension.CertStatusRequestType.OCSP) {
            try {
                CertStatusExtension.OCSPStatusRequest ocspReq = (CertStatusExtension.OCSPStatusRequest) request;
                CertId cid = new CertId(chain[1], new SerialNumber(chain[0].getSerialNumber()));
                ResponseCacheEntry cacheEntry = getFromCache(cid, ocspReq);
                if (cacheEntry != null) {
                    responseMap.put(chain[0], cacheEntry.ocspBytes);
                } else {
                    StatusInfo sInfo = new StatusInfo(chain[0], cid);
                    requestList.add(new OCSPFetchCall(sInfo, ocspReq));
                }
            } catch (IOException exc) {
                if (SSLLogger.isOn && SSLLogger.isOn("respmgr")) {
                    SSLLogger.fine("Exception during CertId creation: ", exc);
                }
            }
        } else if (type == CertStatusExtension.CertStatusRequestType.OCSP_MULTI) {
            CertStatusExtension.OCSPStatusRequest ocspReq2 = (CertStatusExtension.OCSPStatusRequest) request;
            for (int ctr = 0; ctr < chain.length - 1; ctr++) {
                try {
                    CertId cid2 = new CertId(chain[ctr + 1], new SerialNumber(chain[ctr].getSerialNumber()));
                    ResponseCacheEntry cacheEntry2 = getFromCache(cid2, ocspReq2);
                    if (cacheEntry2 != null) {
                        responseMap.put(chain[ctr], cacheEntry2.ocspBytes);
                    } else {
                        StatusInfo sInfo2 = new StatusInfo(chain[ctr], cid2);
                        requestList.add(new OCSPFetchCall(sInfo2, ocspReq2));
                    }
                } catch (IOException exc2) {
                    if (SSLLogger.isOn && SSLLogger.isOn("respmgr")) {
                        SSLLogger.fine("Exception during CertId creation: ", exc2);
                    }
                }
            }
        } else if (SSLLogger.isOn && SSLLogger.isOn("respmgr")) {
            SSLLogger.fine("Unsupported status request type: " + type, new Object[0]);
        }
        if (!requestList.isEmpty()) {
            try {
                List<Future<StatusInfo>> resultList = this.threadMgr.invokeAll(requestList, delay, unit);
                for (Future<StatusInfo> task : resultList) {
                    if (task.isDone()) {
                        if (!task.isCancelled()) {
                            StatusInfo info = task.get();
                            if (info != null && info.responseData != null) {
                                responseMap.put(info.cert, info.responseData.ocspBytes);
                            } else if (SSLLogger.isOn && SSLLogger.isOn("respmgr")) {
                                SSLLogger.fine("Completed task had no response data", new Object[0]);
                            }
                        } else if (SSLLogger.isOn && SSLLogger.isOn("respmgr")) {
                            SSLLogger.fine("Found cancelled task", new Object[0]);
                        }
                    }
                }
            } catch (InterruptedException | ExecutionException exc3) {
                if (SSLLogger.isOn && SSLLogger.isOn("respmgr")) {
                    SSLLogger.fine("Exception when getting data: ", exc3);
                }
            }
        }
        return Collections.unmodifiableMap(responseMap);
    }

    private ResponseCacheEntry getFromCache(CertId cid, CertStatusExtension.OCSPStatusRequest ocspRequest) {
        for (Extension ext : ocspRequest.extensions) {
            if (ext.getId().equals(PKIXExtensions.OCSPNonce_Id.toString())) {
                if (SSLLogger.isOn && SSLLogger.isOn("respmgr")) {
                    SSLLogger.fine("Nonce extension found, skipping cache check", new Object[0]);
                    return null;
                }
                return null;
            }
        }
        ResponseCacheEntry respEntry = this.responseCache.get(cid);
        if (respEntry != null && respEntry.nextUpdate != null && respEntry.nextUpdate.before(new Date())) {
            if (SSLLogger.isOn && SSLLogger.isOn("respmgr")) {
                SSLLogger.fine("nextUpdate threshold exceeded, purging from cache", new Object[0]);
            }
            respEntry = null;
        }
        if (SSLLogger.isOn && SSLLogger.isOn("respmgr")) {
            SSLLogger.fine("Check cache for SN" + cid.getSerialNumber() + ": " + (respEntry != null ? "HIT" : "MISS"), new Object[0]);
        }
        return respEntry;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder("StatusResponseManager: ");
        sb.append("Core threads: ").append(this.threadMgr.getCorePoolSize());
        sb.append(", Cache timeout: ");
        if (this.cacheLifetime > 0) {
            sb.append(this.cacheLifetime).append(" seconds");
        } else {
            sb.append(" indefinite");
        }
        sb.append(", Cache MaxSize: ");
        if (this.cacheCapacity > 0) {
            sb.append(this.cacheCapacity).append(" items");
        } else {
            sb.append(" unbounded");
        }
        sb.append(", Default URI: ");
        if (this.defaultResponder != null) {
            sb.append(this.defaultResponder);
        } else {
            sb.append("NONE");
        }
        return sb.toString();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/StatusResponseManager$StatusInfo.class */
    public class StatusInfo {
        final X509Certificate cert;
        final CertId cid;
        final URI responder;
        ResponseCacheEntry responseData;

        StatusInfo(StatusResponseManager this$0, X509Certificate subjectCert, X509Certificate issuerCert) throws IOException {
            this(subjectCert, new CertId(issuerCert, new SerialNumber(subjectCert.getSerialNumber())));
        }

        StatusInfo(X509Certificate subjectCert, CertId certId) {
            this.cert = subjectCert;
            this.cid = certId;
            this.responder = StatusResponseManager.this.getURI(this.cert);
            this.responseData = null;
        }

        StatusInfo(StatusInfo orig) {
            this.cert = orig.cert;
            this.cid = orig.cid;
            this.responder = orig.responder;
            this.responseData = null;
        }

        public String toString() {
            StringBuilder sb = new StringBuilder("StatusInfo:");
            sb.append("\n\tCert: ").append(this.cert.getSubjectX500Principal());
            sb.append("\n\tSerial: ").append(this.cert.getSerialNumber());
            sb.append("\n\tResponder: ").append(this.responder);
            sb.append("\n\tResponse data: ").append(this.responseData != null ? this.responseData.ocspBytes.length + " bytes" : "<NULL>");
            return sb.toString();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/StatusResponseManager$ResponseCacheEntry.class */
    public class ResponseCacheEntry {
        final OCSPResponse.ResponseStatus status;
        final byte[] ocspBytes;
        final Date nextUpdate;
        final OCSPResponse.SingleResponse singleResp;
        final ResponderId respId;

        ResponseCacheEntry(byte[] responseBytes, CertId cid) throws IOException {
            Objects.requireNonNull(responseBytes, "Non-null responseBytes required");
            Objects.requireNonNull(cid, "Non-null Cert ID required");
            this.ocspBytes = (byte[]) responseBytes.clone();
            OCSPResponse oResp = new OCSPResponse(this.ocspBytes);
            this.status = oResp.getResponseStatus();
            this.respId = oResp.getResponderId();
            this.singleResp = oResp.getSingleResponse(cid);
            if (this.status == OCSPResponse.ResponseStatus.SUCCESSFUL) {
                if (this.singleResp != null) {
                    this.nextUpdate = this.singleResp.getNextUpdate();
                    return;
                }
                throw new IOException("Unable to find SingleResponse for SN " + cid.getSerialNumber());
            }
            this.nextUpdate = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/StatusResponseManager$OCSPFetchCall.class */
    public class OCSPFetchCall implements Callable<StatusInfo> {
        StatusInfo statInfo;
        CertStatusExtension.OCSPStatusRequest ocspRequest;
        List<Extension> extensions;
        List<ResponderId> responderIds;

        public OCSPFetchCall(StatusInfo info, CertStatusExtension.OCSPStatusRequest request) {
            this.statInfo = (StatusInfo) Objects.requireNonNull(info, "Null StatusInfo not allowed");
            this.ocspRequest = (CertStatusExtension.OCSPStatusRequest) Objects.requireNonNull(request, "Null OCSPStatusRequest not allowed");
            this.extensions = this.ocspRequest.extensions;
            this.responderIds = this.ocspRequest.responderIds;
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // java.util.concurrent.Callable
        public StatusInfo call() {
            if (SSLLogger.isOn && SSLLogger.isOn("respmgr")) {
                SSLLogger.fine("Starting fetch for SN " + this.statInfo.cid.getSerialNumber(), new Object[0]);
            }
            try {
            } catch (IOException ioe) {
                if (SSLLogger.isOn && SSLLogger.isOn("respmgr")) {
                    SSLLogger.fine("Caught exception: ", ioe);
                }
            }
            if (this.statInfo.responder == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("respmgr")) {
                    SSLLogger.fine("Null URI detected, OCSP fetch aborted", new Object[0]);
                }
                return this.statInfo;
            }
            if (SSLLogger.isOn && SSLLogger.isOn("respmgr")) {
                SSLLogger.fine("Attempting fetch from " + this.statInfo.responder, new Object[0]);
            }
            List<Extension> extsToSend = (StatusResponseManager.this.ignoreExtensions || !this.responderIds.isEmpty()) ? Collections.emptyList() : this.extensions;
            byte[] respBytes = OCSP.getOCSPBytes(Collections.singletonList(this.statInfo.cid), this.statInfo.responder, extsToSend);
            if (respBytes != null) {
                ResponseCacheEntry cacheEntry = new ResponseCacheEntry(respBytes, this.statInfo.cid);
                if (SSLLogger.isOn && SSLLogger.isOn("respmgr")) {
                    SSLLogger.fine("OCSP Status: " + cacheEntry.status + " (" + respBytes.length + " bytes)", new Object[0]);
                }
                if (cacheEntry.status == OCSPResponse.ResponseStatus.SUCCESSFUL) {
                    this.statInfo.responseData = cacheEntry;
                    addToCache(this.statInfo.cid, cacheEntry);
                }
            } else if (SSLLogger.isOn && SSLLogger.isOn("respmgr")) {
                SSLLogger.fine("No data returned from OCSP Responder", new Object[0]);
            }
            return this.statInfo;
        }

        private void addToCache(CertId certId, ResponseCacheEntry entry) {
            if (entry.nextUpdate != null || StatusResponseManager.this.cacheLifetime != 0) {
                StatusResponseManager.this.responseCache.put(certId, entry);
                if (SSLLogger.isOn && SSLLogger.isOn("respmgr")) {
                    SSLLogger.fine("Added response for SN " + certId.getSerialNumber() + " to cache", new Object[0]);
                }
            } else if (SSLLogger.isOn && SSLLogger.isOn("respmgr")) {
                SSLLogger.fine("Not caching this OCSP response", new Object[0]);
            }
        }

        private long getNextTaskDelay(Date nextUpdate) {
            long delaySec;
            int lifetime = StatusResponseManager.this.getCacheLifetime();
            if (nextUpdate != null) {
                long nuDiffSec = (nextUpdate.getTime() - System.currentTimeMillis()) / 1000;
                delaySec = lifetime > 0 ? Long.min(nuDiffSec, lifetime) : nuDiffSec;
            } else {
                delaySec = lifetime > 0 ? lifetime : -1L;
            }
            return delaySec;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static final StaplingParameters processStapling(ServerHandshakeContext shc) {
        byte[] respDER;
        StaplingParameters params = null;
        SSLExtension ext = null;
        CertStatusExtension.CertStatusRequestType type = null;
        CertStatusExtension.CertStatusRequest req = null;
        if (!shc.sslContext.isStaplingEnabled(false) || shc.isResumption) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Staping disabled or is a resumed session", new Object[0]);
                return null;
            }
            return null;
        }
        Map<SSLExtension, SSLExtension.SSLExtensionSpec> exts = shc.handshakeExtensions;
        CertStatusExtension.CertStatusRequestSpec statReq = (CertStatusExtension.CertStatusRequestSpec) exts.get(SSLExtension.CH_STATUS_REQUEST);
        CertStatusExtension.CertStatusRequestV2Spec statReqV2 = (CertStatusExtension.CertStatusRequestV2Spec) exts.get(SSLExtension.CH_STATUS_REQUEST_V2);
        if (statReqV2 != null && !shc.negotiatedProtocol.useTLS13PlusSpec()) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                SSLLogger.fine("SH Processing status_request_v2 extension", new Object[0]);
            }
            ext = SSLExtension.CH_STATUS_REQUEST_V2;
            int ocspIdx = -1;
            int ocspMultiIdx = -1;
            CertStatusExtension.CertStatusRequest[] reqItems = statReqV2.certStatusRequests;
            for (int pos = 0; pos < reqItems.length && (ocspIdx == -1 || ocspMultiIdx == -1); pos++) {
                CertStatusExtension.CertStatusRequest item = reqItems[pos];
                CertStatusExtension.CertStatusRequestType curType = CertStatusExtension.CertStatusRequestType.valueOf(item.statusType);
                if (ocspIdx < 0 && curType == CertStatusExtension.CertStatusRequestType.OCSP) {
                    if (((CertStatusExtension.OCSPStatusRequest) item).responderIds.isEmpty()) {
                        ocspIdx = pos;
                    }
                } else if (ocspMultiIdx < 0 && curType == CertStatusExtension.CertStatusRequestType.OCSP_MULTI && ((CertStatusExtension.OCSPStatusRequest) item).responderIds.isEmpty()) {
                    ocspMultiIdx = pos;
                }
            }
            if (ocspMultiIdx >= 0) {
                req = reqItems[ocspMultiIdx];
                type = CertStatusExtension.CertStatusRequestType.valueOf(req.statusType);
            } else if (ocspIdx >= 0) {
                req = reqItems[ocspIdx];
                type = CertStatusExtension.CertStatusRequestType.valueOf(req.statusType);
            } else if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.finest("Warning: No suitable request found in the status_request_v2 extension.", new Object[0]);
            }
        }
        if (statReq != null && (ext == null || type == null || req == null)) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                SSLLogger.fine("SH Processing status_request extension", new Object[0]);
            }
            ext = SSLExtension.CH_STATUS_REQUEST;
            type = CertStatusExtension.CertStatusRequestType.valueOf(statReq.statusRequest.statusType);
            if (type == CertStatusExtension.CertStatusRequestType.OCSP) {
                CertStatusExtension.OCSPStatusRequest ocspReq = (CertStatusExtension.OCSPStatusRequest) statReq.statusRequest;
                if (ocspReq.responderIds.isEmpty()) {
                    req = ocspReq;
                } else if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.finest("Warning: No suitable request found in the status_request extension.", new Object[0]);
                }
            }
        }
        if (type == null || req == null || ext == null) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("No suitable status_request or status_request_v2, stapling is disabled", new Object[0]);
                return null;
            }
            return null;
        }
        X509Authentication.X509Possession x509Possession = null;
        Iterator<SSLPossession> it = shc.handshakePossessions.iterator();
        while (true) {
            if (!it.hasNext()) {
                break;
            }
            SSLPossession possession = it.next();
            if (possession instanceof X509Authentication.X509Possession) {
                x509Possession = (X509Authentication.X509Possession) possession;
                break;
            }
        }
        if (x509Possession == null) {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.finest("Warning: no X.509 certificates found.  Stapling is disabled.", new Object[0]);
                return null;
            }
            return null;
        }
        X509Certificate[] certs = x509Possession.popCerts;
        StatusResponseManager statRespMgr = shc.sslContext.getStatusResponseManager();
        if (statRespMgr != null) {
            CertStatusExtension.CertStatusRequestType fetchType = shc.negotiatedProtocol.useTLS13PlusSpec() ? CertStatusExtension.CertStatusRequestType.OCSP_MULTI : type;
            Map<X509Certificate, byte[]> responses = statRespMgr.get(fetchType, req, certs, shc.statusRespTimeout, TimeUnit.MILLISECONDS);
            if (!responses.isEmpty()) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.finest("Response manager returned " + responses.size() + " entries.", new Object[0]);
                }
                if (type == CertStatusExtension.CertStatusRequestType.OCSP && ((respDER = responses.get(certs[0])) == null || respDER.length <= 0)) {
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.finest("Warning: Null or zero-length response found for leaf certificate. Stapling is disabled.", new Object[0]);
                        return null;
                    }
                    return null;
                }
                params = new StaplingParameters(ext, type, req, responses);
            } else if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.finest("Warning: no OCSP responses obtained.  Stapling is disabled.", new Object[0]);
            }
        } else {
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.finest("Warning: lazy initialization of the StatusResponseManager failed.  Stapling is disabled.", new Object[0]);
            }
            params = null;
        }
        return params;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/StatusResponseManager$StaplingParameters.class */
    public static final class StaplingParameters {
        final SSLExtension statusRespExt;
        final CertStatusExtension.CertStatusRequestType statReqType;
        final CertStatusExtension.CertStatusRequest statReqData;
        final Map<X509Certificate, byte[]> responseMap;

        StaplingParameters(SSLExtension ext, CertStatusExtension.CertStatusRequestType type, CertStatusExtension.CertStatusRequest req, Map<X509Certificate, byte[]> responses) {
            this.statusRespExt = ext;
            this.statReqType = type;
            this.statReqData = req;
            this.responseMap = responses;
        }
    }
}