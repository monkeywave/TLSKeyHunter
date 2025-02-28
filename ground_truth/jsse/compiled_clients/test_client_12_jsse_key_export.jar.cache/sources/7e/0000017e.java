package javassist.tools.rmi;

import java.applet.Applet;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.lang.reflect.Constructor;
import java.net.Socket;
import java.net.URL;

/* loaded from: test_client_12_jsse_key_export.jar:javassist/tools/rmi/ObjectImporter.class */
public class ObjectImporter implements Serializable {
    private static final long serialVersionUID = 1;
    private String servername;
    private String orgServername;
    private int port;
    private int orgPort;
    private static final Class<?>[] proxyConstructorParamTypes = {ObjectImporter.class, Integer.TYPE};
    private final byte[] endofline = {13, 10};
    protected byte[] lookupCommand = "POST /lookup HTTP/1.0".getBytes();
    protected byte[] rmiCommand = "POST /rmi HTTP/1.0".getBytes();

    public ObjectImporter(Applet applet) {
        URL codebase = applet.getCodeBase();
        String host = codebase.getHost();
        this.servername = host;
        this.orgServername = host;
        int port = codebase.getPort();
        this.port = port;
        this.orgPort = port;
    }

    public ObjectImporter(String servername, int port) {
        this.servername = servername;
        this.orgServername = servername;
        this.port = port;
        this.orgPort = port;
    }

    public Object getObject(String name) {
        try {
            return lookupObject(name);
        } catch (ObjectNotFoundException e) {
            return null;
        }
    }

    public void setHttpProxy(String host, int port) {
        String proxyHeader = "POST http://" + this.orgServername + ":" + this.orgPort;
        String cmd = proxyHeader + "/lookup HTTP/1.0";
        this.lookupCommand = cmd.getBytes();
        String cmd2 = proxyHeader + "/rmi HTTP/1.0";
        this.rmiCommand = cmd2.getBytes();
        this.servername = host;
        this.port = port;
    }

    public Object lookupObject(String name) throws ObjectNotFoundException {
        try {
            Socket sock = new Socket(this.servername, this.port);
            OutputStream out = sock.getOutputStream();
            out.write(this.lookupCommand);
            out.write(this.endofline);
            out.write(this.endofline);
            ObjectOutputStream dout = new ObjectOutputStream(out);
            dout.writeUTF(name);
            dout.flush();
            InputStream in = new BufferedInputStream(sock.getInputStream());
            skipHeader(in);
            ObjectInputStream din = new ObjectInputStream(in);
            int n = din.readInt();
            String classname = din.readUTF();
            din.close();
            dout.close();
            sock.close();
            if (n >= 0) {
                return createProxy(n, classname);
            }
            throw new ObjectNotFoundException(name);
        } catch (Exception e) {
            e.printStackTrace();
            throw new ObjectNotFoundException(name, e);
        }
    }

    private Object createProxy(int oid, String classname) throws Exception {
        Class<?> c = Class.forName(classname);
        Constructor<?> cons = c.getConstructor(proxyConstructorParamTypes);
        return cons.newInstance(this, Integer.valueOf(oid));
    }

    public Object call(int objectid, int methodid, Object[] args) throws RemoteException {
        try {
            Socket sock = new Socket(this.servername, this.port);
            OutputStream out = new BufferedOutputStream(sock.getOutputStream());
            out.write(this.rmiCommand);
            out.write(this.endofline);
            out.write(this.endofline);
            ObjectOutputStream dout = new ObjectOutputStream(out);
            dout.writeInt(objectid);
            dout.writeInt(methodid);
            writeParameters(dout, args);
            dout.flush();
            InputStream ins = new BufferedInputStream(sock.getInputStream());
            skipHeader(ins);
            ObjectInputStream din = new ObjectInputStream(ins);
            boolean result = din.readBoolean();
            Object rvalue = null;
            String errmsg = null;
            if (result) {
                rvalue = din.readObject();
            } else {
                errmsg = din.readUTF();
            }
            din.close();
            dout.close();
            sock.close();
            if (rvalue instanceof RemoteRef) {
                RemoteRef ref = (RemoteRef) rvalue;
                rvalue = createProxy(ref.oid, ref.classname);
            }
            if (result) {
                return rvalue;
            }
            throw new RemoteException(errmsg);
        } catch (IOException e) {
            throw new RemoteException(e);
        } catch (ClassNotFoundException e2) {
            throw new RemoteException(e2);
        } catch (Exception e3) {
            throw new RemoteException(e3);
        }
    }

    private void skipHeader(InputStream in) throws IOException {
        int len;
        do {
            len = 0;
            while (true) {
                int c = in.read();
                if (c < 0 || c == 13) {
                    break;
                }
                len++;
            }
            in.read();
        } while (len > 0);
    }

    private void writeParameters(ObjectOutputStream dout, Object[] params) throws IOException {
        int n = params.length;
        dout.writeInt(n);
        for (int i = 0; i < n; i++) {
            if (params[i] instanceof Proxy) {
                Proxy p = (Proxy) params[i];
                dout.writeObject(new RemoteRef(p._getObjectId()));
            } else {
                dout.writeObject(params[i]);
            }
        }
    }
}