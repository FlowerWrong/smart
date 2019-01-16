package flowerwrong.github.com.smart.core;

import android.annotation.SuppressLint;

import com.google.common.base.Splitter;

import flowerwrong.github.com.smart.net.TcpUdpClientInfo;
import flowerwrong.github.com.smart.tcpip.CommonMethods;
import flowerwrong.github.com.smart.tcpip.IPHeader;
import flowerwrong.github.com.smart.tunnel.Config;
import flowerwrong.github.com.smart.tunnel.Tunnel;
import flowerwrong.github.com.smart.tunnel.httpconnect.HttpConnectConfig;
import flowerwrong.github.com.smart.tunnel.shadowsocks.ShadowsocksConfig;
import flowerwrong.github.com.smart.util.SubnetUtil;

import org.apache.http.conn.util.InetAddressUtils;

import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class ProxyConfig {
    public static final ProxyConfig Instance = new ProxyConfig();
    public static String AppInstallID;
    public static String AppVersion;
    public final static int FAKE_NETWORK_MASK = CommonMethods.ipStringToInt("255.255.0.0");
    public final static int FAKE_NETWORK_IP = CommonMethods.ipStringToInt("172.25.0.0");

    // config item
    ArrayList<IPAddress> m_IpList;
    ArrayList<IPAddress> m_DnsList;
    ArrayList<IPAddress> m_RouteList;
    public ArrayList<Config> m_ProxyList;

    // rules
    HashMap<String, String> m_DomainMap; // 完全匹配
    HashMap<String, String> m_DomainKeywordMap; // 关键词匹配
    HashMap<String, String> m_DomainSuffixMap; // 前缀匹配
    HashMap<String, String> m_IPCountryMap; // ip country
    HashMap<String, String> m_IPCidrMap; // ip cidr
    HashMap<String, String> m_ProcessMap; // process

    public static boolean IS_DEBUG = false;
    public boolean globalMode = false;
    public boolean firewallMode = true;

    int m_dns_ttl;
    String m_welcome_info;
    String m_session_name;
    String m_user_agent;
    boolean m_isolate_http_host_header = true;
    int m_mtu;
    String m_final_action = "direct";

    Timer m_Timer;

    // eg: domain:action or ip:action
    private static ConcurrentHashMap<String, String> ruleActionCache;

    public class IPAddress {
        public final String Address;
        public final int PrefixLength;

        public IPAddress(String address, int prefixLength) {
            this.Address = address;
            this.PrefixLength = prefixLength;
        }

        public IPAddress(String ipAddresString) {
            String[] arrStrings = Splitter.on('/').splitToList(ipAddresString).toArray(new String[0]);
            String address = arrStrings[0];
            int prefixLength = 32;
            if (arrStrings.length > 1) {
                prefixLength = Integer.parseInt(arrStrings[1]);
            }
            this.Address = address;
            this.PrefixLength = prefixLength;
        }

        @SuppressLint("DefaultLocale")
        @Override
        public String toString() {
            return String.format("%s/%d", Address, PrefixLength);
        }

        @Override
        public boolean equals(Object o) {
            if (o == null) {
                return false;
            } else {
                return this.toString().equals(o.toString());
            }
        }
    }

    public ProxyConfig() {
        m_IpList = new ArrayList<IPAddress>();
        m_DnsList = new ArrayList<IPAddress>();
        m_RouteList = new ArrayList<IPAddress>();
        m_ProxyList = new ArrayList<Config>();

        m_DomainMap = new HashMap<String, String>();
        m_DomainKeywordMap = new HashMap<String, String>();
        m_DomainSuffixMap = new HashMap<String, String>();

        m_IPCountryMap = new HashMap<String, String>();
        m_IPCidrMap = new HashMap<String, String>();

        m_ProcessMap = new HashMap<String, String>();

        ruleActionCache = new ConcurrentHashMap<>();

        m_Timer = new Timer();
        m_Timer.schedule(m_Task, 120000, 120000); // 每两分钟刷新一次。
    }

    TimerTask m_Task = new TimerTask() {
        @Override
        public void run() {
            refreshProxyServer(); // 定时更新dns缓存
        }

        // 定时更新dns缓存
        void refreshProxyServer() {
            try {
                for (int i = 0; i < m_ProxyList.size(); i++) {
                    try {
                        Config config = m_ProxyList.get(0);
                        InetAddress address = InetAddress.getByName(config.ServerAddress.getHostName());
                        if (address != null && !address.equals(config.ServerAddress.getAddress())) {
                            config.ServerAddress = new InetSocketAddress(address, config.ServerAddress.getPort());
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    };


    public static boolean isFakeIP(int ip) {
        return (ip & ProxyConfig.FAKE_NETWORK_MASK) == ProxyConfig.FAKE_NETWORK_IP;
    }

    public Config getDefaultProxy() {
        if (m_ProxyList.size() > 0) {
            return m_ProxyList.get(0);
        } else {
            return null;
        }
    }

    public Config getDefaultTunnelConfig(InetSocketAddress destAddress) {
        return getDefaultProxy();
    }

    public IPAddress getDefaultLocalIP() {
        if (m_IpList.size() > 0) {
            return m_IpList.get(0);
        } else {
            return new IPAddress("172.25.0.1", 32);
        }
    }

    public ArrayList<IPAddress> getDnsList() {
        return m_DnsList;
    }

    public ArrayList<IPAddress> getRouteList() {
        return m_RouteList;
    }

    public int getDnsTTL() {
        if (m_dns_ttl < 30) {
            m_dns_ttl = 30;
        }
        return m_dns_ttl;
    }

    public String getWelcomeInfo() {
        return m_welcome_info;
    }

    public String getSessionName() {
        if (m_session_name == null) {
            m_session_name = getDefaultProxy().ServerAddress.getHostName();
        }
        return m_session_name;
    }

    public String getUserAgent() {
        if (m_user_agent == null || m_user_agent.isEmpty()) {
            m_user_agent = System.getProperty("http.agent");
        }
        return m_user_agent;
    }

    public int getMTU() {
        if (m_mtu > 1400 && m_mtu <= Tunnel.BUFFER_SIZE) {
            return m_mtu;
        } else {
            return 1500;
        }
    }

    private String getDomainState(String domain) {
        domain = domain.toLowerCase();
        if (m_DomainMap.get(domain) != null) {
            return m_DomainMap.get(domain);
        }
        for (String key : m_DomainSuffixMap.keySet()) {
            if (domain.endsWith(key)) {
                return m_DomainSuffixMap.get(key);
            }
        }

        for (String key : m_DomainKeywordMap.keySet()) {
            if (domain.contains(key)) {
                return m_DomainKeywordMap.get(key);
            }
        }

        return null;
    }

    public String needProxy(String host, int ip, int protocol, int uid) {
        // 无视配置文件，都走代理
        if (globalMode)
            return "proxy";

        String ipStr = "";
        if (ip != 0) {
            ipStr = CommonMethods.ipIntToString(ip);
        }

        if (host != null) {
            if (InetAddressUtils.isIPv4Address(host) || InetAddressUtils.isIPv6Address(host)) {
                if (DnsProxy.NoneProxyIPDomainMaps.get(ip) != null) {
                    host = DnsProxy.NoneProxyIPDomainMaps.get(ip);
                }
            }

            String action = ruleActionCache.get(host);
            if (action != null) {
                return action;
            }

            action = getDomainState(host);
            if (action != null) {
                ruleActionCache.put(host, action);
                return action;
            }
        }

        if (ip != 0) {
            if (isFakeIP(ip)) {
                return "proxy";
            }

            String action = ruleActionCache.get(ipStr);
            if (action != null) {
                return action;
            }

            String domain = DnsProxy.NoneProxyIPDomainMaps.get(ip);
            // ip cidr
            for (String key : m_IPCidrMap.keySet()) {
                if (SubnetUtil.inSubnet(key, ipStr)) {
                    if (ProxyConfig.IS_DEBUG) {
                        LocalVpnService.Instance.writeLog("[IPCIDR] " + (domain == null ? host : domain) + " -> " + ipStr + " in " + key + " via " + m_IPCidrMap.get(key) + " " + IPHeader.protocol(protocol) + ((firewallMode && uid > 0) ? (" " + TcpUdpClientInfo.getPackageNameForUid(LocalVpnService.packageManager, uid)) : ""));
                    }

                    action = m_IPCidrMap.get(key);
                    ruleActionCache.put(ipStr, action);
                    return action;
                }
            }

            // ip country
            String countryIsoCode = LocalVpnService.Instance.getCountryIsoCodeByIP(ipStr);
            if (countryIsoCode != null) {
                countryIsoCode = countryIsoCode.toLowerCase(); // 统一使用小写
                if (m_IPCountryMap.get(countryIsoCode) != null) {
                    if (ProxyConfig.IS_DEBUG) {
                        LocalVpnService.Instance.writeLog("[GEOIP] " + (domain == null ? host : domain) + " -> " + ipStr + " " + countryIsoCode + " via " + m_IPCountryMap.get(countryIsoCode) + " " + IPHeader.protocol(protocol) + ((firewallMode && uid > 0) ? (" " + TcpUdpClientInfo.getPackageNameForUid(LocalVpnService.packageManager, uid)) : ""));
                    }

                    action = m_IPCountryMap.get(countryIsoCode);
                    ruleActionCache.put(ipStr, action);
                    return action;
                }
            }
        }

        return m_final_action;
    }

    public boolean isIsolateHttpHostHeader() {
        return m_isolate_http_host_header;
    }

    public int loadFromFile(InputStream inputStream) throws Exception {
        byte[] bytes = new byte[inputStream.available()];
        inputStream.read(bytes);
        String[] lines = Splitter.onPattern("\r?\n").splitToList(new String(bytes)).toArray(new String[0]);
        return loadFromLines(lines);
    }

    public int loadFromLines(String[] lines) throws Exception {
        m_IpList.clear();
        m_DnsList.clear();
        m_RouteList.clear();
        m_ProxyList.clear();
        m_DomainMap.clear();
        m_DomainKeywordMap.clear();
        m_DomainSuffixMap.clear();

        m_IPCountryMap.clear();
        m_IPCidrMap.clear();
        m_ProcessMap.clear();

        int lineNumber = 0;
        for (String line : lines) {
            lineNumber++;

            if (line.trim().isEmpty() || line.trim().startsWith("#")) {
                continue;
            }

            String[] items = line.split("\\s+");
            if (items.length < 2) {
                continue;
            }

            String tagString = items[0].toLowerCase(Locale.ENGLISH).trim();
            try {
                if (!tagString.startsWith("#")) {
                    if (tagString.equals("ip")) {
                        addIPAddressToList(items, 1, m_IpList);
                    } else if (tagString.equals("dns")) {
                        addIPAddressToList(items, 1, m_DnsList);
                    } else if (tagString.equals("dns_ttl")) {
                        m_dns_ttl = Integer.parseInt(items[1]);
                    } else if (tagString.equals("mtu")) {
                        m_mtu = Integer.parseInt(items[1]);
                    } else if (tagString.equals("route")) {
                        addIPAddressToList(items, 1, m_RouteList);
                    } else if (tagString.equals("proxy")) {
                        addProxyToList(items, 1);
                    } else if (tagString.equals("welcome_info")) {
                        m_welcome_info = line.substring(line.indexOf(" ")).trim();
                    } else if (tagString.equals("session_name")) {
                        m_session_name = items[1];
                    } else if (tagString.equals("debug")) {
                        ProxyConfig.IS_DEBUG = convertToBool(items[1]);
                    } else if (tagString.equals("global_mode")) {
                        ProxyConfig.Instance.globalMode = convertToBool(items[1]);
                    } else if (tagString.equals("firewall_mode")) {
                        ProxyConfig.Instance.firewallMode = convertToBool(items[1]);
                    } else if (tagString.equals("proxy_domain")) {
                        addDomainToHashMap(items, 1, "proxy");
                    } else if (tagString.equals("direct_domain")) {
                        addDomainToHashMap(items, 1, "direct");
                    } else if (tagString.equals("block_domain")) {
                        addDomainToHashMap(items, 1, "block");
                    } else if (tagString.equals("proxy_domain_keyword")) {
                        addDomainKeywordToHashMap(items, 1, "proxy");
                    } else if (tagString.equals("direct_domain_keyword")) {
                        addDomainKeywordToHashMap(items, 1, "direct");
                    } else if (tagString.equals("block_domain_keyword")) {
                        addDomainKeywordToHashMap(items, 1, "block");
                    } else if (tagString.equals("proxy_domain_suffix")) {
                        addDomainSuffixToHashMap(items, 1, "proxy");
                    } else if (tagString.equals("direct_domain_suffix")) {
                        addDomainSuffixToHashMap(items, 1, "direct");
                    } else if (tagString.equals("block_domain_suffix")) {
                        addDomainSuffixToHashMap(items, 1, "block");
                    } else if (tagString.equals("proxy_ip_country")) {
                        addIPCountryToHashMap(items, 1, "proxy");
                    } else if (tagString.equals("direct_ip_country")) {
                        addIPCountryToHashMap(items, 1, "direct");
                    } else if (tagString.equals("block_ip_country")) {
                        addIPCountryToHashMap(items, 1, "block");
                    } else if (tagString.equals("proxy_ip_cidr")) {
                        addIPCidrToHashMap(items, 1, "proxy");
                    } else if (tagString.equals("direct_ip_cidr")) {
                        addIPCidrToHashMap(items, 1, "direct");
                    } else if (tagString.equals("block_ip_cidr")) {
                        addIPCidrToHashMap(items, 1, "block");
                    } else if (tagString.equals("proxy_process")) {
                        addProcessToHashMap(items, 1, "proxy");
                    } else if (tagString.equals("direct_process")) {
                        addProcessToHashMap(items, 1, "direct");
                    } else if (tagString.equals("block_process")) {
                        addProcessToHashMap(items, 1, "block");
                    } else if (tagString.equals("user_agent")) {
                        m_user_agent = line.substring(line.indexOf(" ")).trim();
                    } else if (tagString.equals("isolate_http_host_header")) {
                        m_isolate_http_host_header = convertToBool(items[1]);
                    } else if (tagString.equals("final")) {
                        m_final_action = items[1].trim();
                    }
                }
            } catch (Exception e) {
                throw new Exception(String.format("config file parse error: line:%d, tag:%s, error:%s", lineNumber, tagString, e));
            }

        }

        // 查找默认代理。
        if (m_ProxyList.size() == 0) {
            tryAddProxy(lines);
        }

        return m_DomainMap.size() + m_DomainSuffixMap.size() + m_DomainKeywordMap.size() + m_IPCountryMap.size() + m_IPCidrMap.size() + m_ProcessMap.size();
    }

    private void tryAddProxy(String[] lines) {
        for (String line : lines) {
            Pattern p = Pattern.compile("proxy\\s+([^:]+):(\\d+)", Pattern.CASE_INSENSITIVE);
            Matcher m = p.matcher(line);
            while (m.find()) {
                HttpConnectConfig config = new HttpConnectConfig();
                config.ServerAddress = new InetSocketAddress(m.group(1), Integer.parseInt(m.group(2)));
                if (!m_ProxyList.contains(config)) {
                    m_ProxyList.add(config);
                    m_DomainMap.put(config.ServerAddress.getHostName(), "direct");
                }
            }
        }
    }

    public void addProxyToList(String proxyString) throws Exception {
        Config config = null;
        if (proxyString.startsWith("ss://")) {
            config = ShadowsocksConfig.parse(proxyString);
        } else {
            if (!proxyString.toLowerCase().startsWith("http://")) {
                proxyString = "http://" + proxyString;
            }
            config = HttpConnectConfig.parse(proxyString);
        }
        if (!m_ProxyList.contains(config)) {
            m_ProxyList.add(config);
            m_DomainMap.put(config.ServerAddress.getHostName(), "direct");
        }
    }

    private void addProxyToList(String[] items, int offset) throws Exception {
        for (int i = offset; i < items.length; i++) {
            addProxyToList(items[i].trim());
        }
    }

    private void addDomainToHashMap(String[] items, int offset, String state) {
        for (int i = offset; i < items.length; i++) {
            String domainString = items[i].toLowerCase().trim();
            if (domainString.charAt(0) == '.') {
                domainString = domainString.substring(1);
            }
            m_DomainMap.put(domainString, state);
        }
    }

    private void addDomainKeywordToHashMap(String[] items, int offset, String state) {
        for (int i = offset; i < items.length; i++) {
            String domainString = items[i].toLowerCase().trim();
            if (domainString.charAt(0) == '.') {
                domainString = domainString.substring(1);
            }
            m_DomainKeywordMap.put(domainString, state);
        }
    }

    private void addDomainSuffixToHashMap(String[] items, int offset, String state) {
        for (int i = offset; i < items.length; i++) {
            String domainString = items[i].toLowerCase().trim();
            if (domainString.charAt(0) == '.') {
                domainString = domainString.substring(1);
            }
            m_DomainSuffixMap.put(domainString, state);
        }
    }

    private void addIPCountryToHashMap(String[] items, int offset, String state) {
        for (int i = offset; i < items.length; i++) {
            String domainString = items[i].toLowerCase().trim();
            if (domainString.charAt(0) == '.') {
                domainString = domainString.substring(1);
            }
            m_IPCountryMap.put(domainString, state);
        }
    }

    private void addIPCidrToHashMap(String[] items, int offset, String state) {
        for (int i = offset; i < items.length; i++) {
            String domainString = items[i].toLowerCase().trim();
            if (domainString.charAt(0) == '.') {
                domainString = domainString.substring(1);
            }
            m_IPCidrMap.put(domainString, state);
        }
    }

    private void addProcessToHashMap(String[] items, int offset, String state) {
        for (int i = offset; i < items.length; i++) {
            m_ProcessMap.put(items[i].toLowerCase().trim(), state);
        }
    }

    public List<String> getProcessListByAction(String action) {
        List<String> apps = new ArrayList<>();
        for (String key : m_ProcessMap.keySet()) {
            if (m_ProcessMap.get(key).equals(action)) {
                apps.add(key);
            }
        }
        return apps;
    }

    private boolean convertToBool(String valueString) {
        if (valueString == null || valueString.isEmpty())
            return false;
        valueString = valueString.toLowerCase(Locale.ENGLISH).trim();
        if (valueString.equals("on") || valueString.equals("1") || valueString.equals("true") || valueString.equals("yes")) {
            return true;
        } else {
            return false;
        }
    }


    private void addIPAddressToList(String[] items, int offset, ArrayList<IPAddress> list) {
        for (int i = offset; i < items.length; i++) {
            String item = items[i].trim().toLowerCase();
            if (item.startsWith("#")) {
                break;
            } else {
                IPAddress ip = new IPAddress(item);
                if (!list.contains(ip)) {
                    list.add(ip);
                }
            }
        }
    }

}
