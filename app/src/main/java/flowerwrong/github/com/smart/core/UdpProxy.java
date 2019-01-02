package flowerwrong.github.com.smart.core;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;

import flowerwrong.github.com.smart.tcpip.CommonMethods;
import flowerwrong.github.com.smart.tcpip.IPHeader;
import flowerwrong.github.com.smart.tcpip.UDPHeader;

public class UdpProxy implements Runnable {
    private class State {
        public long NanoTime;
        public int ClientIP;
        public short ClientPort;
        public int RemoteIP;
        public short RemotePort;
    }

    private DatagramSocket m_Client;
    private Thread m_ReceivedThread;
    private int DEFAULT_PACKET_SIZE = ProxyConfig.Instance.getMTU();
    private State state;

    public UdpProxy() {
        try {
            m_Client = new DatagramSocket(0);
        } catch (SocketException e) {
            e.printStackTrace();
        }
        state = new State();
    }

    public void start() {
        m_ReceivedThread = new Thread(this);
        m_ReceivedThread.setName("UdpProxyThread" + m_Client.getLocalPort());
        m_ReceivedThread.start();
    }

    public void stop() {
        if (m_Client != null) {
            m_Client.close();
            m_Client = null;
        }
    }

    @Override
    public void run() {
        try {
            m_Client.setSoTimeout(10000);
            byte[] RECEIVE_BUFFER = new byte[DEFAULT_PACKET_SIZE];
            IPHeader ipHeader = new IPHeader(RECEIVE_BUFFER, 0);
            ipHeader.Default();
            UDPHeader udpHeader = new UDPHeader(RECEIVE_BUFFER, 20);

            ByteBuffer udpDataBuffer = ByteBuffer.wrap(RECEIVE_BUFFER);
            udpDataBuffer.position(28);
            udpDataBuffer = udpDataBuffer.slice();

            DatagramPacket packet = new DatagramPacket(RECEIVE_BUFFER, 28, RECEIVE_BUFFER.length - 28);

            while (m_Client != null && !m_Client.isClosed()) {
                packet.setLength(RECEIVE_BUFFER.length - 28);

                try {
                    m_Client.receive(packet);
                } catch (SocketTimeoutException e) {
                    break;
                }

                udpDataBuffer.clear();
                udpDataBuffer.limit(packet.getLength());

                ipHeader.setSourceIP(state.RemoteIP);
                ipHeader.setDestinationIP(state.ClientIP);
                ipHeader.setProtocol(IPHeader.UDP);
                ipHeader.setTotalLength(20 + 8 + udpDataBuffer.remaining());
                udpHeader.setSourcePort(state.RemotePort);
                udpHeader.setDestinationPort(state.ClientPort);
                udpHeader.setTotalLength(8 + udpDataBuffer.remaining());

                LocalVpnService.Instance.sendUDPPacket(ipHeader, udpHeader);
                break;
            }
        } catch (Exception e) {
            LocalVpnService.Instance.writeLog(e.getLocalizedMessage());
            e.printStackTrace();
        } finally {
            LocalVpnService.Instance.writeLog("UDP Proxy Thread %s Exited.", m_ReceivedThread.getName());
            this.stop();
        }
    }

    public void send(IPHeader ipHeader, UDPHeader udpHeader, ByteBuffer buffer) {
        State state = new State();
        state.NanoTime = System.nanoTime();
        state.ClientIP = ipHeader.getSourceIP();
        state.ClientPort = udpHeader.getSourcePort();
        state.RemoteIP = ipHeader.getDestinationIP();
        state.RemotePort = udpHeader.getDestinationPort();

        InetSocketAddress remoteAddress = new InetSocketAddress(CommonMethods.ipIntToInet4Address(ipHeader.getDestinationIP()), udpHeader.getDestinationPort());
        DatagramPacket packet = new DatagramPacket(udpHeader.m_Data, udpHeader.m_Offset + 8, buffer.remaining());
        packet.setSocketAddress(remoteAddress);

        try {
            /**
             * Protect a socket from VPN connections. After protecting, data sent
             * through this socket will go directly to the underlying network,
             * so its traffic will not be forwarded through the VPN.
             * This method is useful if some connections need to be kept
             * outside of VPN. For example, a VPN tunnel should protect itself if its
             * destination is covered by VPN routes. Otherwise its outgoing packets
             * will be sent back to the VPN interface and cause an infinite loop. This
             * method will fail if the application is not prepared or is revoked.
             *
             * <p class="note">The socket is NOT closed by this method.
             *
             * @return {@code true} on success.
             */
            if (LocalVpnService.Instance.protect(m_Client)) {
                m_Client.send(packet);
            } else {
                LocalVpnService.Instance.writeLog("VPN protect udp socket failed.");
            }
        } catch (IOException e) {
            LocalVpnService.Instance.writeLog(e.getLocalizedMessage());
            e.printStackTrace();
        }
    }
}
