package javassist.tools.web;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/tools/web/BadHttpRequest.class */
public class BadHttpRequest extends Exception {
    private static final long serialVersionUID = 1;

    /* renamed from: e */
    private Exception f7e;

    public BadHttpRequest() {
        this.f7e = null;
    }

    public BadHttpRequest(Exception _e) {
        this.f7e = _e;
    }

    @Override // java.lang.Throwable
    public String toString() {
        if (this.f7e == null) {
            return super.toString();
        }
        return this.f7e.toString();
    }
}