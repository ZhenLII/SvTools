package param;

import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.util.List;

/**
 * @author JiangSenwei
 */
public class HelpBasedParametersTest {

    private final static String CONNECT = "--connect";
    private final static String KEEP_ALIVE = "--keepalive";
    private final static String SN_PREFIX = "--sn_prefix";
    private final static String DELAY = "--delay";
    private final static String NUM = "--num";
    private final static String HOST = "--host";
    private final static String PORT = "--port";
    private final static String REDIS = "--redis";
    private final static String REDIS_PORT = "--redis_port";
    private final static String REDIS_PASSWORD = "--redis_password";
    private final static  List<String> FULL_NAMES = List.of(CONNECT,KEEP_ALIVE,SN_PREFIX,DELAY,NUM,HOST,PORT,REDIS,REDIS_PORT,REDIS_PASSWORD);
    @Test
    public void testParseDefault() {
        boolean err = false;
        HelpBasedParameters parameters = null;
        try {
            parameters = HelpBasedParameters.getInstance();
            parameters.printHelp();
        } catch (IOException e) {
            err = true;
        }

        Assert.assertFalse(err);
        Assert.assertNotNull(parameters);
        Assert.assertEquals(parameters.getIdentifiers().size(),FULL_NAMES.size());
        for(ParameterIdentifier identifier : parameters.getIdentifiers()) {
            Assert.assertTrue(FULL_NAMES.contains(identifier.getFullName()));
            System.out.println("parameter: " + identifier.getFullName() + ", default value: " + parameters.getStringValue(identifier.getFullName()));
        }
    }


}
