package javassist;

import java.io.InputStream;
import java.net.URL;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/ClassPath.class */
public interface ClassPath {
    InputStream openClassfile(String str) throws NotFoundException;

    URL find(String str);
}