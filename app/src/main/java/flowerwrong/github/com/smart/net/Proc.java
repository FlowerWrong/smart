package flowerwrong.github.com.smart.net;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

// https://android-review.googlesource.com/c/platform/system/sepolicy/+/679054/
public class Proc {
    public static void assertNoAccessibleListeningPorts(
            String procFilePath, boolean isTcp, boolean loopback) throws IOException {
        String errors = "";
        List<ParsedProcEntry> entries = ParsedProcEntry.parse(procFilePath);
        for (ParsedProcEntry entry : entries) {
            String addrPort = entry.localAddress.getHostAddress() + ':' + entry.port;


            // if (ProxyConfig.IS_DEBUG)
                // LocalVpnService.Instance.writeLog("netstat: " + addrPort + " " + entry.state + " " + entry.uid + "\n");
            if (isPortListening(entry.state, isTcp)
                    && (!entry.localAddress.isLoopbackAddress() ^ loopback)) {
                errors += "\nFound port listening on addr="
                        + entry.localAddress.getHostAddress() + ", port="
                        + entry.port + ", UID=" + entry.uid + " in "
                        + procFilePath;
            }
        }
        if (!errors.equals("")) {
        }
    }

    private static boolean isPortListening(String state, boolean isTcp) {
        // 0A = TCP_LISTEN from include/net/tcp_states.h
        String listeningState = isTcp ? "0A" : "07";
        return listeningState.equals(state);
    }

    private static class ParsedProcEntry {
        private final InetAddress localAddress;
        private final int port;
        private final String state;
        private final int uid;

        private ParsedProcEntry(InetAddress addr, int port, String state, int uid) {
            this.localAddress = addr;
            this.port = port;
            this.state = state;
            this.uid = uid;
        }

        private static List<ParsedProcEntry> parse(String procFilePath) throws IOException {
            List<ParsedProcEntry> retval = new ArrayList<ParsedProcEntry>();
            /*
             * Sample output of "cat /proc/net/tcp" on emulator:
             *
             * sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  ...
             * 0: 0100007F:13AD 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0   ...
             * 1: 00000000:15B3 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0   ...
             * 2: 0F02000A:15B3 0202000A:CE8A 01 00000000:00000000 00:00000000 00000000     0   ...
             *
             */
            File procFile = new File(procFilePath);
            Scanner scanner = null;
            try {
                scanner = new Scanner(procFile);
                while (scanner.hasNextLine()) {
                    String line = scanner.nextLine().trim();
                    // Skip column headers
                    if (line.startsWith("sl")) {
                        continue;
                    }
                    String[] fields = line.split("\\s+");
                    final int expectedNumColumns = 12;
                    String state = fields[3];
                    int uid = Integer.parseInt(fields[7]);
                    InetAddress localIp = addrToInet(fields[1].split(":")[0]);
                    int localPort = Integer.parseInt(fields[1].split(":")[1], 16);
                    retval.add(new ParsedProcEntry(localIp, localPort, state, uid));
                }
            } finally {
                if (scanner != null) {
                    scanner.close();
                }
            }
            return retval;
        }

        /**
         * Convert a string stored in little endian format to an IP address.
         */
        private static InetAddress addrToInet(String s) throws UnknownHostException {
            int len = s.length();
            if (len != 8 && len != 32) {
                throw new IllegalArgumentException(len + "");
            }
            byte[] retval = new byte[len / 2];
            for (int i = 0; i < len / 2; i += 4) {
                retval[i] = (byte) ((Character.digit(s.charAt(2 * i + 6), 16) << 4)
                        + Character.digit(s.charAt(2 * i + 7), 16));
                retval[i + 1] = (byte) ((Character.digit(s.charAt(2 * i + 4), 16) << 4)
                        + Character.digit(s.charAt(2 * i + 5), 16));
                retval[i + 2] = (byte) ((Character.digit(s.charAt(2 * i + 2), 16) << 4)
                        + Character.digit(s.charAt(2 * i + 3), 16));
                retval[i + 3] = (byte) ((Character.digit(s.charAt(2 * i), 16) << 4)
                        + Character.digit(s.charAt(2 * i + 1), 16));
            }
            return InetAddress.getByAddress(retval);
        }
    }
}
