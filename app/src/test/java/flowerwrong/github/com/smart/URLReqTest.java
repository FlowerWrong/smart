package flowerwrong.github.com.smart;

import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;

import flowerwrong.github.com.smart.core.LocalVpnService;
import flowerwrong.github.com.smart.core.ProxyConfig;
import flowerwrong.github.com.smart.tcpip.CommonMethods;

public class URLReqTest {
    @Test
    public void testDownload() {
        try {
            URL u = new URL(LocalVpnService.remoteConfigFile);
            InputStream in = u.openStream();

            String rules = IOUtils.toString(in, Charset.defaultCharset());
            ProxyConfig.Instance.loadFromLines(rules.split("\\r?\\n"));

            String domain = "feed.baidu.com";
            String ip = "61.135.186.217";

            Assert.assertEquals(true, domain.endsWith("baidu.com"));

            String action = ProxyConfig.Instance.needProxy(domain, 0);
            Assert.assertEquals("direct", action);

            action = ProxyConfig.Instance.needProxy(domain, CommonMethods.ipStringToInt(ip));
            Assert.assertEquals("direct", action);
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
