package flowerwrong.github.com.smart.util;

import org.apache.commons.net.util.SubnetUtils;

public final class SubnetUtil {

    private SubnetUtil() {
        throw new UnsupportedOperationException("u can't instantiate me...");
    }

    public static boolean inSubnet(String cidr, String ip) {
        if (cidr.endsWith("/32")) {
            if (cidr.substring(0, cidr.length() - 3).equals(ip)) {
                return true;
            }
            return false;
        }
        SubnetUtils subnetUtils = new SubnetUtils(cidr);
        return subnetUtils.getInfo().isInRange(ip);
    }
}
