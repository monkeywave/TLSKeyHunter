package javassist.tools.rmi;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/tools/rmi/ObjectNotFoundException.class */
public class ObjectNotFoundException extends Exception {
    private static final long serialVersionUID = 1;

    public ObjectNotFoundException(String name) {
        super(name + " is not exported");
    }

    public ObjectNotFoundException(String name, Exception e) {
        super(name + " because of " + e.toString());
    }
}