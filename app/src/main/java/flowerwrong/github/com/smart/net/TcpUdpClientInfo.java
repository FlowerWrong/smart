package flowerwrong.github.com.smart.net;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.util.Log;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

import java.io.BufferedReader;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import flowerwrong.github.com.smart.nogotofail.Closeables;
import flowerwrong.github.com.smart.nogotofail.HexEncoding;
import flowerwrong.github.com.smart.tcpip.IPHeader;

public class TcpUdpClientInfo {
    private static final String TAG = TcpUdpClientInfo.class.getSimpleName();

    private static Cache<String, Integer> uidCache = CacheBuilder.newBuilder()
            .maximumSize(1000)
            .expireAfterWrite(30, TimeUnit.SECONDS)
            .build();
    private static Cache<Integer, String> uidForPackageCache = CacheBuilder.newBuilder()
            .maximumSize(1000)
            .expireAfterWrite(30, TimeUnit.MINUTES)
            .build();

    static {
        System.loadLibrary("proc");
    }

    public static native int jniGetUid(int version, int protocol,
                                       String saddr, int sport,
                                       String daddr, int dport);

    private static String tcpLocation = "/proc/net/tcp";
    private static String udpLocation = "/proc/net/udp";
    private static String tcp6Location = "/proc/net/tcp6";
    private static String udp6Location = "/proc/net/udp6";

    public static int getUidForConnectionFromJni(int version, int protocol, String sourceIp, int sourcePort, String destinationIp, int destinationPort) {
        String key = sourceIp + ":" + sourcePort + " <-> " + destinationIp + ":" + destinationPort;
        Integer uid = uidCache.getIfPresent(key);
        if (uid != null) {
            return uid;
        }
        uid = jniGetUid(version, protocol, sourceIp, sourcePort, destinationIp, destinationPort);
        if (uid > 0) {
            uidCache.put(key, uid);
        }
        return uid;
    }

    public static Integer getUidForConnection(int version, int protocol,
                                              byte[] sourceIp, int sourcePort,
                                              byte[] destinationIp, int destinationPort) {
        // Convert the IP address to the format used by /proc/net/tcp and /proc/net/tcp6
        if (sourceIp != null) {
            try {
                sourceIp = inetAddressNetworkToProcOrder(sourceIp);
            } catch (IllegalArgumentException e) {
                Log.w(TAG, "Invalid source IP: " + HexEncoding.encode(sourceIp));
                return null;
            }
        }
        if (destinationIp != null) {
            try {
                destinationIp = inetAddressNetworkToProcOrder(destinationIp);
            } catch (IllegalArgumentException e) {
                Log.w(TAG, "Invalid destination IP: " + HexEncoding.encode(destinationIp));
                return null;
            }
        }

        if (protocol == IPHeader.TCP) {
            // Try IPv6 first followed by IPv4.
            String[][] procNetTcp6 = null;
            try {
                procNetTcp6 = readProcNet(new File(tcp6Location));
            } catch (IOException e) {
                Log.w(TAG, "Failed to load IPv6 TCP info", e);
            }
            if (procNetTcp6 != null) {
                Integer uid = getUidForConnection(procNetTcp6, sourceIp, sourcePort, destinationIp, destinationPort);
                if (uid != null) {
                    return uid;
                }
            }

            // Addresses longer than 4 bytes can't match anything in IPv4 table.
            boolean needCheckIpv4Table =
                    ((sourceIp == null) || (sourceIp.length <= 4))
                            && ((destinationIp == null) || (destinationIp.length <= 4));
            String[][] procNetTcp4 = null;
            if (needCheckIpv4Table) {
                try {
                    procNetTcp4 = readProcNet(new File(tcpLocation));
                } catch (IOException e) {
                    Log.w(TAG, "Failed to load IPv4 TCP info", e);
                }
                if (procNetTcp4 != null) {
                    Integer uid = getUidForConnection(
                            procNetTcp4, sourceIp, sourcePort, destinationIp, destinationPort);
                    if (uid != null) {
                        return uid;
                    }
                }
            }

            // No exact match found -- try without matching the source IP because when an Android is on a
            // VPNs the source IP may be different (WLAN address instead of VPN address) but source port
            // (luckily) appears to stay the same.
            if (sourceIp == null) {
                // Source IP wasn't being matched anyway
                return null;
            }
            if (procNetTcp6 != null) {
                Integer uid = getUidForConnection(
                        procNetTcp6, null, sourcePort, destinationIp, destinationPort);
                if (uid != null) {
                    return uid;
                }
            }

            // Addresses longer than 4 bytes can't match anything in IPv4 table.
            needCheckIpv4Table = ((destinationIp == null) || (destinationIp.length <= 4));
            if (needCheckIpv4Table) {
                if (procNetTcp4 == null) {
                    try {
                        procNetTcp4 = readProcNet(new File(tcpLocation));
                    } catch (IOException e) {
                        e.printStackTrace();
                        Log.w(TAG, "Failed to load IPv4 TCP info", e);
                    }
                }
                if (procNetTcp4 != null) {
                    Integer uid = getUidForConnection(
                            procNetTcp4, null, sourcePort, destinationIp, destinationPort);
                    if (uid != null) {
                        return uid;
                    }
                }
            }
        } else if (protocol == IPHeader.UDP) {
            // udp support
            // Try IPv6 first followed by IPv4.
            String[][] procNetUdp6 = null;
            try {
                procNetUdp6 = readProcNet(new File(udp6Location));
            } catch (IOException e) {
                e.printStackTrace();
                Log.w(TAG, "Failed to load IPv6 UDP info", e);
            }
            if (procNetUdp6 != null) {
                Integer uid = getUidForConnection(
                        procNetUdp6, sourceIp, sourcePort, destinationIp, destinationPort);
                if (uid != null) {
                    return uid;
                }
            }

            // Addresses longer than 4 bytes can't match anything in IPv4 table.
            boolean needCheckIpv4Table =
                    ((sourceIp == null) || (sourceIp.length <= 4))
                            && ((destinationIp == null) || (destinationIp.length <= 4));
            String[][] procNetUdp4 = null;
            if (needCheckIpv4Table) {
                try {
                    procNetUdp4 = readProcNet(new File(udpLocation));
                } catch (IOException e) {
                    e.printStackTrace();
                    Log.w(TAG, "Failed to load IPv4 UDP info", e);
                }
                if (procNetUdp4 != null) {
                    Integer uid = getUidForConnection(
                            procNetUdp4, sourceIp, sourcePort, destinationIp, destinationPort);
                    if (uid != null) {
                        return uid;
                    }
                }
            }

            // No exact match found -- try without matching the source IP because when an Android is on a
            // VPNs the source IP may be different (WLAN address instead of VPN address) but source port
            // (luckily) appears to stay the same.
            if (sourceIp == null) {
                // Source IP wasn't being matched anyway
                return null;
            }
            // udp support
            if (procNetUdp6 != null) {
                Integer uid = getUidForConnection(
                        procNetUdp6, null, sourcePort, destinationIp, destinationPort);
                if (uid != null) {
                    return uid;
                }
            }

            // Addresses longer than 4 bytes can't match anything in IPv4 table.
            needCheckIpv4Table = ((destinationIp == null) || (destinationIp.length <= 4));
            if (needCheckIpv4Table) {
                // udp support
                if (procNetUdp4 == null) {
                    try {
                        procNetUdp4 = readProcNet(new File(udpLocation));
                    } catch (IOException e) {
                        e.printStackTrace();
                        Log.w(TAG, "Failed to load IPv4 UDP info", e);
                    }
                }
                if (procNetUdp4 != null) {
                    Integer uid = getUidForConnection(
                            procNetUdp4, null, sourcePort, destinationIp, destinationPort);
                    if (uid != null) {
                        return uid;
                    }
                }
            }
        }

        return null;
    }

    public static String getPackageNameForUid(PackageManager packageManager, int uid) {
        String pkgName = uidForPackageCache.getIfPresent(uid);
        if (pkgName != null) {
            return pkgName;
        }

        String[] packageNames = packageManager.getPackagesForUid(uid);
        if ((packageNames == null) || (packageNames.length == 0)) {
            return null;
        }

        for (String packageName : packageNames) {
            PackageInfo packageInfo = null;
            try {
                packageInfo = packageManager.getPackageInfo(packageName, 0);
            } catch (PackageManager.NameNotFoundException e) {
                e.printStackTrace();
            }
            if (packageInfo != null) {
                pkgName = packageInfo.packageName;
                uidForPackageCache.put(uid, pkgName);
                return pkgName;
            }
        }
        return null;
    }

    private static Integer getUidForConnection(String[][] procNetTcpLines,
                                               byte[] sourceIpInProcFormat, int sourcePort,
                                               byte[] destinationIpInProcFormat, int destinationPort) {
        for (String[] fields : procNetTcpLines) {
            // Skip empty lines
            if (fields.length == 0) {
                continue;
            }
            String srcAddressAndPortText = fields[2];
            String dstAddressAndPortText = fields[3];
            String[] srcAddressAndPort = srcAddressAndPortText.split(":");
            String[] dstAddressAndPort = dstAddressAndPortText.split(":");

            // Match on ports first as it avoid parsing IP addresses if a port-based match fails
            if (sourcePort >= 0) {
                int srcPort = Integer.parseInt(srcAddressAndPort[1], 16);
                if (srcPort != sourcePort) {
                    continue;
                }
            }

            if (destinationPort >= 0) {
                int dstPort = Integer.parseInt(dstAddressAndPort[1], 16);
                if (dstPort != destinationPort) {
                    continue;
                }
            }

            // Match on destination IP address first because it's more likely to differ across the entries
            if (destinationIpInProcFormat != null) {
                byte[] dstIp = HexEncoding.decode(dstAddressAndPort[0]);
                if (!endsWith(dstIp, destinationIpInProcFormat)) {
                    continue;
                }
            }

            if (sourceIpInProcFormat != null) {
                byte[] srcIp = HexEncoding.decode(srcAddressAndPort[0]);
                if (!endsWith(srcIp, sourceIpInProcFormat)) {
                    continue;
                }
            }

            return Integer.parseInt(fields[8]);
        }

        return null;
    }

    private static boolean endsWith(byte[] array, byte[] suffix) {
        if (suffix.length == 0) {
            return true;
        } else if (suffix.length > array.length) {
            return false;
        }
        for (int i = 0; i < suffix.length; i++) {
            if (array[array.length - suffix.length + i] != suffix[i]) {
                return false;
            }
        }
        return true;
    }

    private static final boolean BIG_ENDIAN_NATIVE_PLATFORM =
            ByteOrder.nativeOrder() == ByteOrder.BIG_ENDIAN;

    /**
     * Converts the provided IP address in network order to the corresponding IP address
     * representation used by {@code /proc/net/tcp} and {@code /proc/net/tcp6}.
     */
    private static byte[] inetAddressNetworkToProcOrder(byte[] input) {
        // proc/net/tcp and /proc/net/tcp6 list addresses in a weird format where 32-bit words are in
        // network order, but inside each word the bytes are in native order. This means that on
        // big-endian native platforms there's no need to modify the input, whereas on little-endian
        // native platforms we need to swap the byte order within each 32-bit word.
        if ((input.length % 4) != 0) {
            throw new IllegalArgumentException(
                    "IP address size should be a multiple of four: " + input.length);
        }
        if (BIG_ENDIAN_NATIVE_PLATFORM) {
            // Big-endian native platform -- optimization: no need to modify the input
            return input;
        }

        // Little-endian native platform -- swap the byte order within each 32-bit word
        ByteBuffer in = ByteBuffer.wrap(input);
        in.order(ByteOrder.BIG_ENDIAN);
        byte[] result = new byte[input.length];
        ByteBuffer out = ByteBuffer.wrap(result);
        out.order(ByteOrder.nativeOrder());
        for (int word = 0; word < input.length / 4; word++) {
            out.putInt(in.getInt());
        }
        return result;
    }

    /**
     * 耗时操作
     * Reads the contents of the {@code /proc/net/tcp} (or /proc/net/tcp6 /proc/net/udp /proc/net/udp6) and returns its lines (excluding the header).
     */
    private static String[][] readProcNet(File file) throws IOException {
        /*
         * Sample output of "cat /proc/net/tcp" on emulator:
         *
         * sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  ...
         * 0: 0100007F:13AD 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0   ...
         * 1: 00000000:15B3 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0   ...
         * 2: 0F02000A:15B3 0202000A:CE8A 01 00000000:00000000 00:00000000 00000000     0   ...
         *
         * 4 "%*d: %8s:%X %8s:%X %*X %*lX:%*lX %*X:%*X %*X %d %*d %*ld"
         * 6 "%*d: %32s:%X %32s:%X %*X %*lX:%*lX %*X:%*X %*X %d %*d %*ld"
         *
         */
        BufferedReader in = null;
        try {
            in = new BufferedReader(new InputStreamReader(new FileInputStream(file), "US-ASCII"));
            // Read and skip the header
            String line = in.readLine();
            if (line == null) {
                throw new EOFException("No header in " + file);
            }
            List<String> lines = new ArrayList<String>();
            while ((line = in.readLine()) != null) {
                // Skip empty lines
                if (line.trim().isEmpty()) {
                    continue;
                }
                lines.add(line);
            }
            String[][] result = new String[lines.size()][];
            for (int i = 0; i < result.length; i++) {
                result[i] = lines.get(i).split("\\s+"); // it it very slow
            }
            return result;
        } finally {
            Closeables.closeQuietly(in);
        }
    }
}
