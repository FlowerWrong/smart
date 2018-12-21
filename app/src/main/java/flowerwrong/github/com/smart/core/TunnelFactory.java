package flowerwrong.github.com.smart.core;

import flowerwrong.github.com.smart.tunnel.Config;
import flowerwrong.github.com.smart.tunnel.RawTunnel;
import flowerwrong.github.com.smart.tunnel.Tunnel;
import flowerwrong.github.com.smart.tunnel.httpconnect.HttpConnectConfig;
import flowerwrong.github.com.smart.tunnel.httpconnect.HttpConnectTunnel;
import flowerwrong.github.com.smart.tunnel.shadowsocks.ShadowsocksConfig;
import flowerwrong.github.com.smart.tunnel.shadowsocks.ShadowsocksTunnel;

import java.net.InetSocketAddress;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;

public class TunnelFactory {

    public static Tunnel wrap(SocketChannel channel, Selector selector) {
        return new RawTunnel(channel, selector);
    }

    public static Tunnel createTunnelByConfig(InetSocketAddress destAddress, Selector selector) throws Exception {
        if (destAddress.isUnresolved()) {
            Config config = ProxyConfig.Instance.getDefaultTunnelConfig(destAddress);
            if (config instanceof HttpConnectConfig) {
                return new HttpConnectTunnel((HttpConnectConfig) config, selector);
            } else if (config instanceof ShadowsocksConfig) {
                return new ShadowsocksTunnel((ShadowsocksConfig) config, selector);
            }
            throw new Exception("The config is unknow.");
        } else {
            return new RawTunnel(destAddress, selector);
        }
    }

}
