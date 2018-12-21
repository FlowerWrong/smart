package flowerwrong.github.com.smart.util;

import org.junit.Assert;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;

public class SubnetUtilTest {
    @Test
    public void testIpCIDR32() {
        String ip = "47.97.225.117";
        String cidr = "47.97.225.117/32";
        Assert.assertThat(String.format("%s should in %s", ip, cidr), SubnetUtil.inSubnet(cidr, ip), is(true));

        String ip2 = "47.97.225.118";
        Assert.assertThat(String.format("%s should not in %s", ip2, cidr), SubnetUtil.inSubnet(cidr, ip2), is(false));
    }
}
