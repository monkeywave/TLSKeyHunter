package org.bouncycastle.jsse.provider;

import java.security.GeneralSecurityException;

/* loaded from: classes2.dex */
interface EngineCreator {
    Object createInstance(Object obj) throws GeneralSecurityException;
}