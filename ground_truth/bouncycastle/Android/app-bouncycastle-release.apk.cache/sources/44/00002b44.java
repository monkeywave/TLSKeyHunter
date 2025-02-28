package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;
import org.bouncycastle.pqc.jcajce.spec.PicnicParameterSpec;

/* loaded from: classes2.dex */
public interface PicnicKey extends Key {
    PicnicParameterSpec getParameterSpec();
}