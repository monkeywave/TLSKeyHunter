package javassist;

import java.io.InputStream;
import java.net.URL;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/ClassClassPath.class */
public class ClassClassPath implements ClassPath {
    private Class<?> thisClass;

    public ClassClassPath(Class<?> c) {
        this.thisClass = c;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ClassClassPath() {
        this(Object.class);
    }

    @Override // javassist.ClassPath
    public InputStream openClassfile(String classname) throws NotFoundException {
        String filename = '/' + classname.replace('.', '/') + ".class";
        return this.thisClass.getResourceAsStream(filename);
    }

    @Override // javassist.ClassPath
    public URL find(String classname) {
        String filename = '/' + classname.replace('.', '/') + ".class";
        return this.thisClass.getResource(filename);
    }

    public String toString() {
        return this.thisClass.getName() + ".class";
    }
}