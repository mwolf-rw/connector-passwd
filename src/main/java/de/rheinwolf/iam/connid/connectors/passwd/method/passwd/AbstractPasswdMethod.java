package de.rheinwolf.iam.connid.connectors.passwd.method.passwd;

import de.rheinwolf.iam.connid.connectors.passwd.PasswdConfiguration;
import de.rheinwolf.iam.connid.connectors.passwd.connection.Connection;
import de.rheinwolf.iam.connid.connectors.passwd.method.become.BecomeMethod;

/**
 * Base class for the supported passwd methods.
 */
public abstract class AbstractPasswdMethod implements PasswdMethod {
    protected BecomeMethod        becomeMethod;
    protected PasswdConfiguration configuration;
    protected Connection          connection;

    /**
     * Initializing the method instance.
     *
     * @param connection        The current target system connection.
     * @param configuration     The current configuration.
     * @param becomeMethod      The current become method.
     */
    public void init(Connection connection, PasswdConfiguration configuration, BecomeMethod becomeMethod) {
        this.becomeMethod  = becomeMethod;
        this.configuration = configuration;
        this.connection    = connection;
    }
}
