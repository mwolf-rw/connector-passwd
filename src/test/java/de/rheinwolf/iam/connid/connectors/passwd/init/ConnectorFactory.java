package de.rheinwolf.iam.connid.connectors.passwd.init;

import de.rheinwolf.iam.connid.connectors.passwd.PasswdConfiguration;
import de.rheinwolf.iam.connid.connectors.passwd.PasswdConnector;

public class ConnectorFactory {
    public static PasswdConnector newInstance() {
        PasswdConnector     passwdConnector     = new PasswdConnector();
        PasswdConfiguration passwdConfiguration = new PasswdConfiguration();

        passwdConfiguration.setBecomeMethod(PasswdConfiguration.BECOME_METHOD_NONE);
        passwdConfiguration.setConnectionType(PasswdConfiguration.CONNECTION_TYPE_LOCAL);
        passwdConfiguration.setMethod(PasswdConfiguration.METHOD_PW);

        passwdConnector.init(passwdConfiguration);

        return passwdConnector;
    }
}
