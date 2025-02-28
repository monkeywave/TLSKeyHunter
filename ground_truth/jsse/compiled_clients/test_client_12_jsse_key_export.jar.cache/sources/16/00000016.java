package javassist;

/* compiled from: ClassPoolTail.java */
/* loaded from: test_client_12_jsse_key_export.jar:javassist/ClassPathList.class */
final class ClassPathList {
    ClassPathList next;
    ClassPath path;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ClassPathList(ClassPath p, ClassPathList n) {
        this.next = n;
        this.path = p;
    }
}