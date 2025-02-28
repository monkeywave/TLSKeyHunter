package javassist.tools.rmi;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/tools/rmi/RemoteException.class */
public class RemoteException extends RuntimeException {
    private static final long serialVersionUID = 1;

    public RemoteException(String msg) {
        super(msg);
    }

    public RemoteException(Exception e) {
        super("by " + e.toString());
    }
}