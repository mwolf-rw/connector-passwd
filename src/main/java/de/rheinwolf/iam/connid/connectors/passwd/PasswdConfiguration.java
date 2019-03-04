package de.rheinwolf.iam.connid.connectors.passwd;

import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.spi.AbstractConfiguration;
import org.identityconnectors.framework.spi.ConfigurationProperty;

import java.util.Arrays;

/**
 * Configuration for the passwd connector.
 */
public class PasswdConfiguration extends AbstractConfiguration {
    private static final Log LOG = Log.getLog(PasswdConfiguration.class);

    public static final String CONNECTION_TYPE_LOCAL = "local";
    public static final String CONNECTION_TYPE_SSH   = "ssh";

    private String connectionType = CONNECTION_TYPE_LOCAL;

    /**
     * The SSH connection information.
     */
    private static final int SSH_DEFAULT_PORT = 22;

    private String        hostKey    = null;
    private String        hostName   = null;
    private GuardedString password   = null;
    private String        privateKey = null;
    private int           port       = SSH_DEFAULT_PORT;
    private String        userName   = null;

    /**
     * The method used for updating users and groups.
     */
    public static final String METHOD_PW      = "pw";
    public static final String METHOD_USERADD = "useradd";

    public static final String SUBMETHOD_BSD   = "bsd";
    public static final String SUBMETHOD_LINUX = "linux";

    private String method = null;

    /**
     * The method used for gaining the necessary permissions.
     */
    public static final String BECOME_METHOD_DOAS = "doas";
    public static final String BECOME_METHOD_NONE = "none";
    public static final String BECOME_METHOD_SUDO = "sudo";

    private String        becomeMethod   = BECOME_METHOD_NONE;
    private GuardedString becomePassword = null;

    /**
     * Behavior.
     */
    private boolean createHomeDirectory      = false;
    private boolean deleteHomeDirectory      = false;
    private String  homeDirectoryPermissions = null;

    /**
     * Validating the passwd configuration settings.
     */
    @Override
    public void validate() {
        LOG.ok("Validating configuration {0}", this);

        if (CONNECTION_TYPE_SSH.equals(connectionType)) {
            if (StringUtil.isBlank(hostName))
                throw new ConfigurationException("The hostName configuration property is mandatory for SSH connections");
            if (StringUtil.isBlank(userName))
                throw new ConfigurationException("The userName configuration property is mandatory for SSH connections");
            if ((StringUtil.isBlank(privateKey)) && (password == null))
                throw new ConfigurationException("The password configuration property is mandatory for SSH connections if no private key is set");
        }

        if (StringUtil.isBlank(method)) {
            throw new ConfigurationException("The method configuration property is mandatory");
        } else if (!Arrays.asList(METHOD_PW, METHOD_USERADD + ":" + SUBMETHOD_BSD, METHOD_USERADD + ":" + SUBMETHOD_LINUX).contains(method)) {
            throw new ConfigurationException("Unsupported value in configuration property method");
        }

        if (!Arrays.asList(BECOME_METHOD_DOAS, BECOME_METHOD_NONE, BECOME_METHOD_SUDO).contains(becomeMethod)) {
            throw new ConfigurationException("Unsupported value in configuration property becomeMethod");
        }
    }

    /**
     * Retrieving the configuration as string.
     *
     * @return The string value for the configuration instance.
     */
    @Override
    public String toString() {
        return getClass().getSimpleName() + "{" +
                "connectionType=" + connectionType + ", " +
                "hostKey=" + hostKey + ", " +
                "hostName=" + hostName + ", " +
                "port=" + port + ", " +
                "userName=" + userName + ", " +
                "password=" + password + ", " +
                "method=" + method + ", " +
                "becomeMethod=" + becomeMethod + ", " +
                "becomePassword=" + becomePassword + ", " +
                "createHomeDirectory=" + createHomeDirectory + ", " +
                "deleteHomeDirectory=" + deleteHomeDirectory + ", " +
                "homeDirectoryPermissions=" + homeDirectoryPermissions +
                "}";
    }

    @ConfigurationProperty(order = 100, displayMessageKey = "passwd.config.connectionType", helpMessageKey = "passwd.config.connectionType.help")
    public String getConnectionType() {
        return connectionType;
    }

    public void setConnectionType(String connectionType) {
        this.connectionType = connectionType;
    }

    @ConfigurationProperty(order = 130, displayMessageKey = "passwd.config.hostKey", helpMessageKey = "passwd.config.hostKey.help")
    public String getHostKey() {
        return hostKey;
    }

    @SuppressWarnings("unused")
    public void setHostKey(String hostKey) {
        this.hostKey = hostKey;
    }

    @ConfigurationProperty(order = 110, displayMessageKey = "passwd.config.hostname", helpMessageKey = "passwd.config.hostname.help")
    public String getHostName() {
        return hostName;
    }

    @SuppressWarnings("unused")
    public void setHostName(String hostName) {
        this.hostName = hostName;
    }

    @ConfigurationProperty(order = 160, displayMessageKey = "passwd.config.password", helpMessageKey = "passwd.config.password.help")
    public GuardedString getPassword() {
        return password;
    }

    @SuppressWarnings("unused")
    public void setPassword(GuardedString password) {
        this.password = password;
    }

    @ConfigurationProperty(order = 150, displayMessageKey = "passwd.config.privateKey", helpMessageKey = "passwd.config.privateKey.help")
    public String getPrivateKey() {
        return privateKey;
    }

    @SuppressWarnings("unused")
    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    @ConfigurationProperty(order = 120, displayMessageKey = "passwd.config.port", helpMessageKey = "passwd.config.port.help")
    public int getPort() {
        return port;
    }

    @SuppressWarnings("unused")
    public void setPort(int port) {
        this.port = port;
    }

    @ConfigurationProperty(order = 140, displayMessageKey = "passwd.config.username", helpMessageKey = "passwd.config.username.help")
    public String getUserName() {
        return userName;
    }

    @SuppressWarnings("unused")
    public void setUserName(String userName) {
        this.userName = userName;
    }

    @ConfigurationProperty(order = 300, displayMessageKey = "passwd.config.method", helpMessageKey = "passwd.config.method.help")
    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    @ConfigurationProperty(order = 200, displayMessageKey = "passwd.config.becomeMethod", helpMessageKey = "passwd.config.becomeMethod.help")
    public String getBecomeMethod() {
        return becomeMethod;
    }

    public void setBecomeMethod(String becomeMethod) {
        this.becomeMethod = becomeMethod;
    }

    @ConfigurationProperty(order = 210, displayMessageKey = "passwd.config.becomePassword", helpMessageKey = "passwd.config.becomePassword.help")
    public GuardedString getBecomePassword() {
        return becomePassword;
    }

    @SuppressWarnings("unused")
    public void setBecomePassword(GuardedString becomePassword) {
        this.becomePassword = becomePassword;
    }

    @ConfigurationProperty(order = 400, displayMessageKey = "passwd.config.createHomeDirectory", helpMessageKey = "passwd.config.createHomeDirectory.help")
    public boolean getCreateHomeDirectory() {
        return createHomeDirectory;
    }

    @SuppressWarnings("unused")
    public void setCreateHomeDirectory(boolean createHomeDirectory) {
        this.createHomeDirectory = createHomeDirectory;
    }

    @ConfigurationProperty(order = 410, displayMessageKey = "passwd.config.deleteHomeDirectory", helpMessageKey = "passwd.config.deleteHomeDirectory.help")
    public boolean getDeleteHomeDirectory() {
        return deleteHomeDirectory;
    }

    @SuppressWarnings("unused")
    public void setDeleteHomeDirectory(boolean deleteHomeDirectory) {
        this.deleteHomeDirectory = deleteHomeDirectory;
    }

    @ConfigurationProperty(order = 420, displayMessageKey = "passwd.config.homeDirectoryPermissions", helpMessageKey = "passwd.config.homeDirectoryPermissions.help")
    public String getHomeDirectoryPermissions() {
        return homeDirectoryPermissions;
    }

    @SuppressWarnings("unused")
    public void setHomeDirectoryPermissions(String homeDirectoryPermissions) {
        this.homeDirectoryPermissions = homeDirectoryPermissions;
    }
}
