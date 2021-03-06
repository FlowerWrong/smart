package flowerwrong.github.com.smart.core;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.ParcelFileDescriptor;

import com.google.common.base.Splitter;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.AddressNotFoundException;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.CountryResponse;
import com.maxmind.geoip2.record.Country;

import org.apache.commons.io.IOUtils;

import flowerwrong.github.com.smart.net.TcpUdpClientInfo;
import flowerwrong.github.com.smart.tunnel.Tunnel;
import flowerwrong.github.com.smart.ui.MainActivity;
import flowerwrong.github.com.smart.R;
import flowerwrong.github.com.smart.core.ProxyConfig.IPAddress;
import flowerwrong.github.com.smart.dns.DnsPacket;
import flowerwrong.github.com.smart.tcpip.CommonMethods;
import flowerwrong.github.com.smart.tcpip.IPHeader;
import flowerwrong.github.com.smart.tcpip.TCPHeader;
import flowerwrong.github.com.smart.tcpip.UDPHeader;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class LocalVpnService extends VpnService implements Runnable {

    public static LocalVpnService Instance;
    public static String ProxyUrl;
    public static boolean IsRunning = false;
    public static DatabaseReader maxmindReader;
    private int DEFAULT_IDLE_TIME = 1;
    private int MAX_IDLE_TIME = 20;

    public static Context context;
    public static PackageManager packageManager;
    public static String configFile = "smart-config.txt";
    public static String remoteConfigFile = "https://gist.githubusercontent.com/FlowerWrong/bccee4d63a6f0542523074f2ae184094/raw/smart-config.txt";

    private static int ID;
    private static int LOCAL_IP;
    private static ConcurrentHashMap<onStatusChangedListener, Object> m_OnStatusChangedListeners = new ConcurrentHashMap<onStatusChangedListener, Object>();

    private Thread m_VPNThread;
    private ParcelFileDescriptor m_VPNInterface;
    private boolean blockingMode = true;
    private TcpProxyServer m_TcpProxyServer;
    private DnsProxy m_DnsProxy;
    private FileOutputStream m_VPNOutputStream;

    private byte[] m_Packet;
    private IPHeader m_IPHeader;
    private TCPHeader m_TCPHeader;
    private UDPHeader m_UDPHeader;
    private ByteBuffer m_DNSBuffer;
    private Handler m_Handler;
    private long m_SentBytes;
    private long m_ReceivedBytes;

    public LocalVpnService() {
        ID++;
        m_Handler = new Handler();
        m_Packet = new byte[Tunnel.BUFFER_SIZE];
        m_IPHeader = new IPHeader(m_Packet, 0);
        m_TCPHeader = new TCPHeader(m_Packet, 20);
        m_UDPHeader = new UDPHeader(m_Packet, 20);
        m_DNSBuffer = ((ByteBuffer) ByteBuffer.wrap(m_Packet).position(28)).slice();
        Instance = this;
    }

    public static void addOnStatusChangedListener(onStatusChangedListener listener) {
        if (!m_OnStatusChangedListeners.containsKey(listener)) {
            m_OnStatusChangedListeners.put(listener, 1);
        }
    }

    public static void removeOnStatusChangedListener(onStatusChangedListener listener) {
        if (m_OnStatusChangedListeners.containsKey(listener)) {
            m_OnStatusChangedListeners.remove(listener);
        }
    }

    @Override
    public void onCreate() {
        // Start a new session by creating a new thread.
        m_VPNThread = new Thread(this, "VPNServiceThread");
        m_VPNThread.start();
        super.onCreate();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        IsRunning = true;
        return super.onStartCommand(intent, flags, startId);
    }

    private void onStatusChanged(final String status, final boolean isRunning) {
        m_Handler.post(new Runnable() {
            @Override
            public void run() {
                for (Map.Entry<onStatusChangedListener, Object> entry : m_OnStatusChangedListeners.entrySet()) {
                    entry.getKey().onStatusChanged(status, isRunning);
                }
            }
        });
    }

    public void writeLog(final String format, Object... args) {
        final String logString = String.format(format, args);
        m_Handler.post(new Runnable() {
            @Override
            public void run() {
                for (Map.Entry<onStatusChangedListener, Object> entry : m_OnStatusChangedListeners.entrySet()) {
                    entry.getKey().onLogReceived(logString);
                }
            }
        });
    }

    public void sendUDPPacket(IPHeader ipHeader, UDPHeader udpHeader) {
        try {
            CommonMethods.ComputeUDPChecksum(ipHeader, udpHeader);
            this.m_VPNOutputStream.write(ipHeader.m_Data, ipHeader.m_Offset, ipHeader.getTotalLength());
        } catch (IOException e) {
            LocalVpnService.Instance.writeLog("sendUDPPacket failed ", e.getLocalizedMessage());
            e.printStackTrace();
        }
    }

    String getAppInstallID() {
        SharedPreferences preferences = getSharedPreferences("SmartProxy", MODE_PRIVATE);
        String appInstallID = preferences.getString("AppInstallID", null);
        if (appInstallID == null || appInstallID.isEmpty()) {
            appInstallID = UUID.randomUUID().toString();
            Editor editor = preferences.edit();
            editor.putString("AppInstallID", appInstallID);
            editor.apply();
        }
        return appInstallID;
    }

    String getVersionName() {
        try {
            PackageManager packageManager = getPackageManager();
            // getPackageName()是你当前类的包名，0代表是获取版本信息
            PackageInfo packInfo = packageManager.getPackageInfo(getPackageName(), 0);
            return packInfo.versionName;
        } catch (Exception e) {
            return "0.0";
        }
    }

    @Override
    public synchronized void run() {
        try {
            LocalVpnService.Instance.writeLog("VPNService(%s) work thread is runing...", ID);

            ProxyConfig.AppInstallID = getAppInstallID(); // 获取安装ID
            ProxyConfig.AppVersion = getVersionName(); // 获取版本号
            writeLog("Android version: %s", Build.VERSION.RELEASE);
            writeLog("App version: %s", ProxyConfig.AppVersion);

            waitUntilPreapred(); // 检查是否准备完毕

            FileInputStream fis = null;
            try {
                fis = context.openFileInput(LocalVpnService.configFile);
                String rules = IOUtils.toString(fis, Charset.defaultCharset());
                String[] lines = Splitter.onPattern("\r?\n").splitToList(rules).toArray(new String[0]);
                int ruleCount = ProxyConfig.Instance.loadFromLines(lines);
                writeLog("Load config from file done, " + ruleCount + " rules");
            } catch (Exception e) {
                String errString = e.getMessage();
                if (errString == null || errString.isEmpty()) {
                    errString = e.toString();
                }
                writeLog("Load failed with error: %s", errString);
            } finally {
                if (fis != null) {
                    try {
                        fis.close();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
            writeLog("Final action: %s", ProxyConfig.Instance.m_final_action);

            // init maxmind
            InputStream maxmindInputStream = getResources().openRawResource(R.raw.geolite2);
            maxmindReader = new DatabaseReader.Builder(maxmindInputStream).build();

            m_TcpProxyServer = new TcpProxyServer(0);
            m_TcpProxyServer.start();
            writeLog("LocalTcpServer started.");

            m_DnsProxy = new DnsProxy();
            m_DnsProxy.start();
            writeLog("LocalDnsProxy started.");

            writeLog("Blacklist apps " + String.join(", ", ProxyConfig.Instance.getProcessListByAction("block")));

            while (true) {
                if (IsRunning) {
                    // 加载配置文件
                    try {
                        ProxyConfig.Instance.m_ProxyList.clear();
                        ProxyConfig.Instance.addProxyToList(ProxyUrl);
                    } catch (Exception e) {
                        String errString = e.getMessage();
                        if (errString == null || errString.isEmpty()) {
                            errString = e.toString();
                        }
                        IsRunning = false;
                        onStatusChanged(errString, false);
                        continue;
                    }
                    String welcomeInfoString = ProxyConfig.Instance.getWelcomeInfo();
                    if (welcomeInfoString != null && !welcomeInfoString.isEmpty()) {
                        writeLog("%s", ProxyConfig.Instance.getWelcomeInfo());
                    }
                    writeLog("Global mode is " + (ProxyConfig.Instance.globalMode ? "on" : "off"));
                    writeLog("Firewall mode is " + (ProxyConfig.Instance.firewallMode ? "on" : "off"));

                    runVPN();
                } else {
                    Thread.sleep(100);
                }
            }
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
            writeLog("Fatal error: %s", e.toString());
        } finally {
            writeLog("App terminated.");
            dispose();
        }
    }

    private void runVPN() throws Exception {
        this.m_VPNInterface = establishVPN();
        this.m_VPNOutputStream = new FileOutputStream(m_VPNInterface.getFileDescriptor());
        FileInputStream in = new FileInputStream(m_VPNInterface.getFileDescriptor());
        int size = 0;
        int idle = DEFAULT_IDLE_TIME;
        while (size != -1 && IsRunning) {
            while ((size = in.read(m_Packet)) > 0 && IsRunning) {
                idle = DEFAULT_IDLE_TIME;
                if (m_DnsProxy.Stopped || m_TcpProxyServer.Stopped) {
                    in.close();
                    throw new Exception("LocalServer stopped.");
                }
                onIPPacketReceived(m_IPHeader, size);
            }
            if (!blockingMode) {
                if (idle < MAX_IDLE_TIME) {
                    idle += 1;
                }
                Thread.sleep(idle);
            }
        }
        in.close();
        disconnectVPN();
    }

    /**
     * 收到ip数据包
     *
     * @param ipHeader
     * @param size
     * @throws IOException
     */
    void onIPPacketReceived(IPHeader ipHeader, int size) throws IOException {
        switch (ipHeader.getProtocol()) {
            case IPHeader.TCP:
                TCPHeader tcpHeader = m_TCPHeader;
                tcpHeader.m_Offset = ipHeader.getHeaderLength();

                int uid = 0;
                /**
                 * 以下代码易导致性能问题
                 */
                if (ProxyConfig.Instance.firewallMode) {
                    try {
                        uid = TcpUdpClientInfo.getUidForConnectionFromJni(
                                ipHeader.getVersion(), IPHeader.TCP,
                                CommonMethods.ipIntToString(ipHeader.getSourceIP()), tcpHeader.getSourcePort(),
                                CommonMethods.ipIntToString(ipHeader.getDestinationIP()), tcpHeader.getDestinationPort()
                        );
                        if (uid > 0) {
                            String packageName = TcpUdpClientInfo.getPackageNameForUid(LocalVpnService.packageManager, uid);
                            if (packageName != null && ProxyConfig.Instance.getProcessListByAction("block").contains(packageName)) {
                                return;
                            }
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }

                if (ipHeader.getSourceIP() == LOCAL_IP) {
                    if (tcpHeader.getSourcePort() == m_TcpProxyServer.Port) { // 收到本地TCP服务器数据
                        NatSession session = NatSessionManager.getSession(tcpHeader.getDestinationPort());
                        if (session != null) {
                            ipHeader.setSourceIP(ipHeader.getDestinationIP());
                            tcpHeader.setSourcePort(session.RemotePort);
                            ipHeader.setDestinationIP(LOCAL_IP);

                            CommonMethods.ComputeTCPChecksum(ipHeader, tcpHeader);

                            // write to tun
                            m_VPNOutputStream.write(ipHeader.m_Data, ipHeader.m_Offset, size);
                            m_ReceivedBytes += size;
                        }
                    } else {
                        // 添加端口映射
                        int portKey = tcpHeader.getSourcePort();
                        NatSession session = NatSessionManager.getSession(portKey);
                        if (session == null || session.RemoteIP != ipHeader.getDestinationIP() || session.RemotePort != tcpHeader.getDestinationPort()) {
                            session = NatSessionManager.createSession(portKey, ipHeader.getDestinationIP(), tcpHeader.getDestinationPort(), uid);
                        }

                        session.LastNanoTime = System.nanoTime();
                        session.PacketSent++; // 注意顺序

                        int tcpDataSize = ipHeader.getDataLength() - tcpHeader.getHeaderLength();
                        if (session.PacketSent == 2 && tcpDataSize == 0) {
                            return; // 丢弃tcp握手的第二个ACK报文。因为客户端发数据的时候也会带上ACK，这样可以在服务器Accept之前分析出HOST信息。
                        }

                        // 分析数据，找到host
                        if (session.BytesSent == 0 && tcpDataSize > 10) {
                            int dataOffset = tcpHeader.m_Offset + tcpHeader.getHeaderLength();
                            String host = HttpHostHeaderParser.parseHost(tcpHeader.m_Data, dataOffset, tcpDataSize);
                            if (host != null) {
                                session.RemoteHost = host;
                            }
                        }

                        // 转发给本地TCP服务器
                        ipHeader.setSourceIP(ipHeader.getDestinationIP());
                        ipHeader.setDestinationIP(LOCAL_IP);
                        tcpHeader.setDestinationPort(m_TcpProxyServer.Port);

                        CommonMethods.ComputeTCPChecksum(ipHeader, tcpHeader);
                        m_VPNOutputStream.write(ipHeader.m_Data, ipHeader.m_Offset, size);
                        session.BytesSent += tcpDataSize; // 注意顺序
                        m_SentBytes += size;
                    }
                }
                break;
            case IPHeader.UDP:
                // 转发DNS数据包
                UDPHeader udpHeader = m_UDPHeader;
                udpHeader.m_Offset = ipHeader.getHeaderLength();

                if (ipHeader.getSourceIP() == LOCAL_IP && udpHeader.getDestinationPort() == 53) {
                    m_DNSBuffer.clear();
                    m_DNSBuffer.limit(ipHeader.getDataLength() - 8);
                    DnsPacket dnsPacket = DnsPacket.FromBytes(m_DNSBuffer);
                    if (dnsPacket != null && dnsPacket.Header.QuestionCount > 0) {
                        m_DnsProxy.onDnsRequestReceived(ipHeader, udpHeader, dnsPacket);
                    }
                }
                break;
        }
    }

    private void waitUntilPreapred() {
        while (prepare(this) != null) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    private ParcelFileDescriptor establishVPN() throws Exception {
        Builder builder = new Builder();
        // MTU
        builder.setMtu(ProxyConfig.Instance.getMTU());

        // ip address
        IPAddress ipAddress = ProxyConfig.Instance.getDefaultLocalIP();
        LOCAL_IP = CommonMethods.ipStringToInt(ipAddress.Address);
        builder.addAddress(ipAddress.Address, ipAddress.PrefixLength);

        // dns
        for (ProxyConfig.IPAddress dns : ProxyConfig.Instance.getDnsList()) {
            builder.addDnsServer(dns.Address);
            if (dns.Address.replaceAll("\\d", "").length() == 3) { // 防止IPv6地址导致问题
                builder.addRoute(dns.Address, 32);
                if (ProxyConfig.IS_DEBUG)
                    LocalVpnService.Instance.writeLog("addRoute: %s/%d", dns.Address, 32);
            } else {
                builder.addRoute(dns.Address, 128);
                if (ProxyConfig.IS_DEBUG)
                    LocalVpnService.Instance.writeLog("addRoute: %s/%d", dns.Address, 128);
            }
            if (ProxyConfig.IS_DEBUG)
                LocalVpnService.Instance.writeLog("addDnsServer: %s", dns.Address);
        }

        // 添加路由
        if (ProxyConfig.Instance.getRouteList().size() > 0) {
            for (ProxyConfig.IPAddress routeAddress : ProxyConfig.Instance.getRouteList()) {
                builder.addRoute(routeAddress.Address, routeAddress.PrefixLength);
                if (ProxyConfig.IS_DEBUG)
                    LocalVpnService.Instance.writeLog("addRoute: %s/%d", routeAddress.Address, routeAddress.PrefixLength);
            }
            builder.addRoute(CommonMethods.ipIntToString(ProxyConfig.FAKE_NETWORK_IP), 16);

            if (ProxyConfig.IS_DEBUG)
                LocalVpnService.Instance.writeLog("addRoute for fake network: %s/%d", CommonMethods.ipIntToString(ProxyConfig.FAKE_NETWORK_IP), 16);
        } else {
            // 所有的IP包都路由到虚拟端口上去
            builder.addRoute("0.0.0.0", 0);
            if (ProxyConfig.IS_DEBUG)
                LocalVpnService.Instance.writeLog("addDefaultRoute: 0.0.0.0/0");
        }

        if (AppProxyManager.isLollipopOrAbove) {
            if (AppProxyManager.Instance.proxyAppInfo.size() == 0) {
                writeLog("Proxy all app");
            } else {
                for (AppInfo app : AppProxyManager.Instance.proxyAppInfo) {
                    builder.addAllowedApplication("flowerwrong.github.com.smart"); // 需要把自己加入代理，不然会无法进行网络连接
                    try {
                        builder.addAllowedApplication(app.getPkgName());
                        writeLog("Proxy app: " + app.getAppLabel());
                    } catch (Exception e) {
                        e.printStackTrace();
                        writeLog("Proxy app fail: " + app.getAppLabel());
                    }
                }

                for (String pkg : ProxyConfig.Instance.getProcessListByAction("block")) {
                    try {
                        builder.addAllowedApplication(pkg);
                        writeLog("Proxy app from block process: " + pkg);
                    } catch (Exception e) {
                        e.printStackTrace();
                        writeLog("Proxy app from block process Fail: " + pkg);
                    }
                }
            }
        } else {
            writeLog("No Pre-App proxy, due to low Android version.");
        }

        Intent intent = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, intent, 0);
        builder.setConfigureIntent(pendingIntent);

        builder.setSession(ProxyConfig.Instance.getSessionName());

        // https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/net/VpnService.java#736
        builder.setBlocking(blockingMode);

        ParcelFileDescriptor pfdDescriptor = builder.establish();
        onStatusChanged(getString(R.string.vpn_connected_status), true);
        return pfdDescriptor;
    }

    public void disconnectVPN() {
        wakeUpReadWorkaround();
        try {
            if (m_VPNInterface != null) {
                m_VPNInterface.close();
                m_VPNInterface = null;
            }
        } catch (Exception e) {
            // ignore
        }
        onStatusChanged(getString(R.string.vpn_disconnected_status), false);
        this.m_VPNOutputStream = null;
    }

    private synchronized void dispose() {
        // 断开VPN
        disconnectVPN();

        // 停止TcpServer
        if (m_TcpProxyServer != null) {
            m_TcpProxyServer.stop();
            m_TcpProxyServer = null;
            writeLog("LocalTcpServer stopped.");
        }

        // 停止DNS解析器
        if (m_DnsProxy != null) {
            m_DnsProxy.stop();
            m_DnsProxy = null;
            writeLog("LocalDnsProxy stopped.");
        }

        stopSelf();
        IsRunning = false;
        System.exit(0);
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        LocalVpnService.Instance.writeLog("VPNService(%s) destoried", ID);
        disconnectVPN();
        IsRunning = false;
        if (m_VPNThread != null) {
            m_VPNThread.interrupt();
        }
    }

    public String getCountryIsoCodeByIP(String ip) {
        InetAddress ipAddress = null;
        try {
            ipAddress = InetAddress.getByName(ip);
        } catch (UnknownHostException e) {
            e.printStackTrace();
            return null;
        }
        try {
            CountryResponse response = maxmindReader.country(ipAddress);
            Country country = response.getCountry();
            return country.getIsoCode();
        } catch (AddressNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (GeoIp2Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public interface onStatusChangedListener {
        public void onStatusChanged(String status, Boolean isRunning);

        public void onLogReceived(String logString);
    }

    // https://github.com/Genymobile/gnirehtet/blob/master/app/src/main/java/com/genymobile/gnirehtet/Forwarder.java#L144-L168
    private static final byte[] DUMMY_ADDRESS = {42, 42, 42, 42};
    private static final int DUMMY_PORT = 4242;

    /**
     * Neither vpnInterface.close() nor vpnInputStream.close() wake up a blocking
     * vpnInputStream.read().
     * <p>
     * Therefore, we need to make Android send a packet to the VPN interface (here by sending a UDP
     * packet), so that any blocking read will be woken up.
     * <p>
     * Since the tunnel is closed at this point, it will never reach the network.
     */
    private void wakeUpReadWorkaround() {
        // network actions may not be called from the main thread
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    DatagramSocket socket = new DatagramSocket();
                    InetAddress dummyAddr = InetAddress.getByAddress(DUMMY_ADDRESS);
                    DatagramPacket packet = new DatagramPacket(new byte[0], 0, dummyAddr, DUMMY_PORT);
                    socket.send(packet);
                } catch (IOException e) {
                    // ignore
                }
            }
        }).start();
    }
}
