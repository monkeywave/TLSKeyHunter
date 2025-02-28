package org.bouncycastle.jcajce.provider.drbg;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.util.Properties;

/* loaded from: classes2.dex */
class EntropyGatherer implements Runnable {
    private static final Logger LOG = Logger.getLogger(EntropyGatherer.class.getName());
    private final IncrementalEntropySource baseRandom;
    private final AtomicReference<byte[]> entropy;
    private final long pause = getPause();
    private final AtomicBoolean seedAvailable;

    /* JADX INFO: Access modifiers changed from: package-private */
    public EntropyGatherer(IncrementalEntropySource incrementalEntropySource, AtomicBoolean atomicBoolean, AtomicReference<byte[]> atomicReference) {
        this.baseRandom = incrementalEntropySource;
        this.seedAvailable = atomicBoolean;
        this.entropy = atomicReference;
    }

    private static long getPause() {
        String propertyValue = Properties.getPropertyValue("org.bouncycastle.drbg.gather_pause_secs");
        if (propertyValue != null) {
            try {
                return Long.parseLong(propertyValue) * 1000;
            } catch (Exception unused) {
            }
        }
        return 5000L;
    }

    @Override // java.lang.Runnable
    public void run() {
        try {
            this.entropy.set(this.baseRandom.getEntropy(this.pause));
            this.seedAvailable.set(true);
        } catch (InterruptedException unused) {
            Logger logger = LOG;
            if (logger.isLoggable(Level.FINE)) {
                logger.fine("entropy request interrupted - exiting");
            }
            Thread.currentThread().interrupt();
        }
    }
}