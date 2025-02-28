package javassist;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/* compiled from: ClassPoolTail.java */
/* loaded from: test_client_12_jsse_key_export.jar:javassist/JarClassPath.class */
final class JarClassPath implements ClassPath {
    Set<String> jarfileEntries;
    String jarfileURL;

    /* JADX INFO: Access modifiers changed from: package-private */
    public JarClassPath(String pathname) throws NotFoundException {
        JarFile jarfile = null;
        try {
            jarfile = new JarFile(pathname);
            this.jarfileEntries = new HashSet();
            Iterator it = Collections.list(jarfile.entries()).iterator();
            while (it.hasNext()) {
                JarEntry je = (JarEntry) it.next();
                if (je.getName().endsWith(".class")) {
                    this.jarfileEntries.add(je.getName());
                }
            }
            this.jarfileURL = new File(pathname).getCanonicalFile().toURI().toURL().toString();
            if (null == jarfile) {
                return;
            }
            try {
                jarfile.close();
            } catch (IOException e) {
            }
        } catch (IOException e2) {
            if (null != jarfile) {
                try {
                    jarfile.close();
                } catch (IOException e3) {
                }
            }
            throw new NotFoundException(pathname);
        } catch (Throwable th) {
            if (null != jarfile) {
                try {
                    jarfile.close();
                } catch (IOException e4) {
                }
            }
            throw th;
        }
    }

    @Override // javassist.ClassPath
    public InputStream openClassfile(String classname) throws NotFoundException {
        URL jarURL = find(classname);
        if (null != jarURL) {
            try {
                if (ClassPool.cacheOpenedJarFile) {
                    return jarURL.openConnection().getInputStream();
                }
                URLConnection con = jarURL.openConnection();
                con.setUseCaches(false);
                return con.getInputStream();
            } catch (IOException e) {
                throw new NotFoundException("broken jar file?: " + classname);
            }
        }
        return null;
    }

    @Override // javassist.ClassPath
    public URL find(String classname) {
        String jarname = classname.replace('.', '/') + ".class";
        if (this.jarfileEntries.contains(jarname)) {
            try {
                return new URL(String.format("jar:%s!/%s", this.jarfileURL, jarname));
            } catch (MalformedURLException e) {
                return null;
            }
        }
        return null;
    }

    public String toString() {
        return this.jarfileURL == null ? "<null>" : this.jarfileURL.toString();
    }
}