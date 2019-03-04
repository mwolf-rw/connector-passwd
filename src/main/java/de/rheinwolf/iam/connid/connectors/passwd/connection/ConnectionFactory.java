package de.rheinwolf.iam.connid.connectors.passwd.connection;

import de.rheinwolf.iam.connid.connectors.passwd.PasswdConfiguration;

import org.identityconnectors.framework.common.exceptions.ConnectionFailedException;

import static de.rheinwolf.iam.connid.connectors.passwd.PasswdConfiguration.CONNECTION_TYPE_LOCAL;
import static de.rheinwolf.iam.connid.connectors.passwd.PasswdConfiguration.CONNECTION_TYPE_SSH;

/**
 * Creating Connection objects.
 */
public class ConnectionFactory {
    /**
     * Creating a new connection.
     *
     * @param configuration     The current configuration instance.
     *
     * @return Returns a Connection instance.
     */
    public static Connection newInstance(PasswdConfiguration configuration) {
        Connection connection;

        if (CONNECTION_TYPE_LOCAL.equals(configuration.getConnectionType())) {
            connection = new LocalConnection();
        } else if (CONNECTION_TYPE_SSH.equals(configuration.getConnectionType())) {
            connection = new SSHConnection();
        } else {
            throw new ConnectionFailedException("Invalid connection type: " + configuration.getConnectionType());
        }

        connection.init(configuration);

        return connection;
    }
}
