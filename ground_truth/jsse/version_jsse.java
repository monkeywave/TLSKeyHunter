import javax.net.ssl.SSLContext;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

public class version_jsse {
    public static void main(String[] args) {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            String providerInfo = "JSSE Provider: " + context.getProvider();
            System.out.println(providerInfo);

            // Write the provider information to version.md
            try (BufferedWriter writer = new BufferedWriter(new FileWriter("version.md"))) {
                writer.write(providerInfo);
            } catch (IOException e) {
                e.printStackTrace();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
