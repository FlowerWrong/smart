package flowerwrong.github.com.smart;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;

import flowerwrong.github.com.smart.core.LocalVpnService;

public class URLReqTest {
    @Test
    public void testDownload() {
        try {
            URL u = new URL(LocalVpnService.remoteConfigFile);
            InputStream in = u.openStream();
            System.out.println(IOUtils.toString(in, Charset.defaultCharset()));
            in.close();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
