package javassist;

import java.io.File;
import java.io.FilenameFilter;
import java.io.InputStream;
import java.net.URL;

/* compiled from: ClassPoolTail.java */
/* loaded from: test_client_12_jsse_key_export.jar:javassist/JarDirClassPath.class */
final class JarDirClassPath implements ClassPath {
    JarClassPath[] jars;

    /* JADX INFO: Access modifiers changed from: package-private */
    public JarDirClassPath(String dirName) throws NotFoundException {
        File[] files = new File(dirName).listFiles(new FilenameFilter() { // from class: javassist.JarDirClassPath.1
            @Override // java.io.FilenameFilter
            public boolean accept(File dir, String name) {
                String name2 = name.toLowerCase();
                return name2.endsWith(".jar") || name2.endsWith(".zip");
            }
        });
        if (files != null) {
            this.jars = new JarClassPath[files.length];
            for (int i = 0; i < files.length; i++) {
                this.jars[i] = new JarClassPath(files[i].getPath());
            }
        }
    }

    @Override // javassist.ClassPath
    public InputStream openClassfile(String classname) throws NotFoundException {
        if (this.jars != null) {
            for (int i = 0; i < this.jars.length; i++) {
                InputStream is = this.jars[i].openClassfile(classname);
                if (is != null) {
                    return is;
                }
            }
            return null;
        }
        return null;
    }

    @Override // javassist.ClassPath
    public URL find(String classname) {
        if (this.jars != null) {
            for (int i = 0; i < this.jars.length; i++) {
                URL url = this.jars[i].find(classname);
                if (url != null) {
                    return url;
                }
            }
            return null;
        }
        return null;
    }
}