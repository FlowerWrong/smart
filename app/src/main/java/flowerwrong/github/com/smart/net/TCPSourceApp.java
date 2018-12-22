package flowerwrong.github.com.smart.net;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketException;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.http.conn.util.InetAddressUtils;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;

/**
 * copy from https://github.com/dextorer/AndroidTCPSourceApp/blob/master/src/com/megadevs/tcpsourceapp/TCPSourceApp.java
 */
public class TCPSourceApp {

    /*
     * This class represents an Android application. Each application is
     * uniquely identified by its package name (e.g. com.megadevs.tcpsourceapp)
     * and its version (e.g. 1.0).
     */
    public static class AppDescriptor {

        private String packageName;
        private String version;

        public AppDescriptor(String pName, String ver) {
            packageName = pName;
            version = ver;
        }

        public String getPackageName() {
            return packageName;
        }

        public String getVersion() {
            return version;
        }

        public String toString() {
            return packageName + ":" + version;
        }

        /*
         * Override of the 'equals' method, in order to have a proper
         * comparison between two AppDescriptor objects.
         *
         * (non-Javadoc)
         * @see java.lang.Object#equals(java.lang.Object)
         */
        @Override
        public boolean equals(Object o) {

            if (o instanceof AppDescriptor) {
                boolean c1 = ((AppDescriptor) o).packageName.compareTo(this.packageName) == 0;
                boolean c2 = ((AppDescriptor) o).version.compareTo(this.version) == 0;

                return c1 && c2;
            }

            return false;
        }

    }

    /*
     * In a Linux-based OS, each active TCP socket is mapped in the following
     * two files. A socket may be mapped in the '/proc/net/tcp' file in case
     *  of a simple IPv4 address, or in the '/proc/net/tcp6' if an IPv6 address
     *  is available.
     */
    private static final String TCP_4_FILE_PATH = "/proc/net/tcp";
    private static final String TCP_6_FILE_PATH = "/proc/net/tcp6";

    /*
     * Two regular expressions that are able to extract valuable informations
     * from the two /proc/net/tcp* files. More specifically, there are three
     * fields that are extracted:
     * 	- address
     * 	- port
     * 	- PID
     */
    private static final String TCP_6_PATTERN = "\\d+:\\s([0-9A-F]{32}):([0-9A-F]{4})\\s[0-9A-F]{32}:[0-9A-F]{4}\\s[0-9A-F]{2}\\s[0-9]{8}:[0-9]{8}\\s[0-9]{2}:[0-9]{8}\\s[0-9]{8}\\s+([0-9]+)";
    private static final String TCP_4_PATTERN = "\\d+:\\s([0-9A-F]{8}):([0-9A-F]{4})\\s[0-9A-F]{8}:[0-9A-F]{4}\\s[0-9A-F]{2}\\s[0-9A-F]{8}:[0-9A-F]{8}\\s[0-9]{2}:[0-9]{8}\\s[0-9A-F]{8}\\s+([0-9]+)";

    /*
     * Optimises the socket lookup by checking if the connected network
     * interface has a 'valid' IPv6 address (a global address, not a link-local
     * one).
     */
    private static boolean checkConnectedIfaces = true;

    /*
     * Alternative method that receives a Socket object and just extracts the
     * port from it, subsequently calling the overloaded method.
     */
    public static AppDescriptor getApplicationInfo(Context context, Socket socket) {
        return getApplicationInfo(context, socket.getPort());
    }

    /**
     * The main method of the TCPSourceApp library. This method receives an
     * Android Context instance, which is used to access the PackageManager.
     * It parses the /proc/net/tcp* files, looking for a socket entry that
     * matches the given port. If it finds an entry, this method extracts the
     * PID value and it uses the PackageManager.getPackagesFromPid() method to
     * find the originating application.
     *
     * @param context a valid Android Context instance
     * @param port    the (logical) port of the socket
     * @return an AppDescriptor object, representing the found application; null
     * if no application could be found
     */
    @SuppressWarnings("unused")
    public static AppDescriptor getApplicationInfo(Context context, int port) {

        File tcp;
        BufferedReader reader;
        String line;
        StringBuilder builder;
        String content;

        try {
            boolean hasIPv6 = true;

            // if true, checks for a connected network interface with a valid
            // IPv4 / IPv6 address
            if (checkConnectedIfaces) {
                String ipv4Address = getIPAddress(true);
                String ipv6Address = getIPAddress(false);

                hasIPv6 = (ipv6Address.length() > 0);
            }

            tcp = new File(TCP_6_FILE_PATH);
            reader = new BufferedReader(new FileReader(tcp));
            line = "";
            builder = new StringBuilder();

            while ((line = reader.readLine()) != null) {
                builder.append(line);
            }

            content = builder.toString();

            Matcher m6 = Pattern.compile(TCP_6_PATTERN, Pattern.CASE_INSENSITIVE | Pattern.UNIX_LINES | Pattern.DOTALL).matcher(content);

            if (hasIPv6)
                while (m6.find()) {
                    String addressEntry = m6.group(1);
                    String portEntry = m6.group(2);
                    int pidEntry = Integer.valueOf(m6.group(3));

                    if (Integer.parseInt(portEntry, 16) == port) {
                        PackageManager manager = context.getPackageManager();
                        String[] packagesForUid = manager.getPackagesForUid(pidEntry);

                        if (packagesForUid != null) {
                            String packageName = packagesForUid[0];
                            PackageInfo pInfo = manager.getPackageInfo(packageName, 0);
                            String version = pInfo.versionName;

                            return new AppDescriptor(packageName, version);
                        }
                    }
                }

        } catch (SocketException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NameNotFoundException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

        // From here, no connection with the given port could be found in the tcp6 file
        // So let's try the tcp (IPv4) one

        try {
            tcp = new File(TCP_4_FILE_PATH);
            reader = new BufferedReader(new FileReader(tcp));
            line = "";
            builder = new StringBuilder();

            while ((line = reader.readLine()) != null) {
                builder.append(line);
            }

            content = builder.toString();

            Matcher m4 = Pattern.compile(TCP_4_PATTERN, Pattern.CASE_INSENSITIVE | Pattern.UNIX_LINES | Pattern.DOTALL).matcher(content);

            while (m4.find()) {
                String addressEntry = m4.group(1);
                String portEntry = m4.group(2);
                int pidEntry = Integer.valueOf(m4.group(3));

                if (Integer.parseInt(portEntry, 16) == port) {
                    PackageManager manager = context.getPackageManager();
                    String[] packagesForUid = manager.getPackagesForUid(pidEntry);

                    if (packagesForUid != null) {
                        String packageName = packagesForUid[0];
                        PackageInfo pInfo = manager.getPackageInfo(packageName, 0);
                        String version = pInfo.versionName;

                        return new AppDescriptor(packageName, version);
                    }
                }
            }

        } catch (SocketException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NameNotFoundException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    @SuppressLint("DefaultLocale")
    public static String getIPAddress(boolean useIPv4) throws SocketException {

        List<NetworkInterface> interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());

        for (NetworkInterface intf : interfaces) {
            List<InetAddress> addrs = Collections.list(intf.getInetAddresses());

            for (InetAddress addr : addrs) {
                if (!addr.isLoopbackAddress()) {
                    String sAddr = addr.getHostAddress().toUpperCase();
                    boolean isIPv4 = InetAddressUtils.isIPv4Address(sAddr);

                    if (useIPv4) {
                        if (isIPv4)
                            return sAddr;
                    } else {
                        if (!isIPv4) {
                            if (sAddr.startsWith("fe80") || sAddr.startsWith("FE80")) // skipping link-local addresses
                                continue;

                            int delim = sAddr.indexOf('%'); // drop ip6 port suffix
                            return delim < 0 ? sAddr : sAddr.substring(0, delim);
                        }
                    }
                }
            }
        }

        return "";
    }

    /*
     * Sets the connected interfaces optimisation.
     */
    public static void setCheckConnectedIfaces(boolean value) {
        checkConnectedIfaces = value;
    }
}
