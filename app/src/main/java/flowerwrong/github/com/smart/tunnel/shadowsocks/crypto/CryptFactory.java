package flowerwrong.github.com.smart.tunnel.shadowsocks.crypto;

import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

public class CryptFactory {
    private static final Map<String, String> crypts = new HashMap<String, String>() {{
        putAll(AesCrypt.getCiphers());
        putAll(CamelliaCrypt.getCiphers());
        putAll(BlowFishCrypt.getCiphers());
        putAll(SeedCrypt.getCiphers());
        putAll(Chacha20Crypt.getCiphers());
        putAll(Rc4Md5Crypt.getCiphers());
        // TODO: other crypts
    }};
    private static Logger logger = Logger.getLogger(CryptFactory.class.getName());

    public static boolean isCipherExisted(String name) {
        return (crypts.get(name) != null);
    }

    public static ICrypt get(String name, String password) {
        try {
            Object obj = getObj(crypts.get(name), String.class, name, String.class, password);
            return (ICrypt) obj;

        } catch (Exception e) {
            logger.info(e.getMessage());
        }

        return null;
    }

    public static List<String> getSupportedCiphers() {
        List sortedKeys = new ArrayList<String>(crypts.keySet());
        Collections.sort(sortedKeys);
        return sortedKeys;
    }

    public static Object getObj(String className, Object... args) {
        Object retValue = null;
        try {
            Class c = Class.forName(className);
            if (args.length == 0) {
                retValue = c.newInstance();
            } else if ((args.length & 1) == 0) {
                // args should come with pairs, for example
                // String.class, "arg1_value", String.class, "arg2_value"
                Class[] oParam = new Class[args.length / 2];
                for (int arg_i = 0, i = 0; arg_i < args.length; arg_i += 2, i++) {
                    oParam[i] = (Class) args[arg_i];
                }

                Constructor constructor = c.getConstructor(oParam);
                Object[] paramObjs = new Object[args.length / 2];
                for (int arg_i = 1, i = 0; arg_i < args.length; arg_i += 2, i++) {
                    paramObjs[i] = args[arg_i];
                }
                retValue = constructor.newInstance(paramObjs);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return retValue;
    }
}
