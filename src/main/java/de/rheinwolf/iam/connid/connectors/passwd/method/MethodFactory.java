package de.rheinwolf.iam.connid.connectors.passwd.method;

import de.rheinwolf.iam.connid.connectors.passwd.PasswdConfiguration;
import de.rheinwolf.iam.connid.connectors.passwd.connection.Connection;

import de.rheinwolf.iam.connid.connectors.passwd.method.become.BecomeMethod;
import de.rheinwolf.iam.connid.connectors.passwd.method.become.DoAsBecomeMethod;
import de.rheinwolf.iam.connid.connectors.passwd.method.become.NoneBecomeMethod;
import de.rheinwolf.iam.connid.connectors.passwd.method.become.SuDoBecomeMethod;
import de.rheinwolf.iam.connid.connectors.passwd.method.passwd.AbstractPasswdMethod;
import de.rheinwolf.iam.connid.connectors.passwd.method.passwd.PasswdMethod;
import de.rheinwolf.iam.connid.connectors.passwd.method.passwd.PwPasswdMethod;
import de.rheinwolf.iam.connid.connectors.passwd.method.passwd.UserAddPasswdMethod;
import org.identityconnectors.framework.common.exceptions.ConnectionFailedException;

import static de.rheinwolf.iam.connid.connectors.passwd.PasswdConfiguration.*;

/**
 * Creating method objects.
 */
public class MethodFactory {
    /**
     * Creating a new PasswdMethod instance.
     *
     * @param connection        The current target system connection.
     * @param configuration     The current connector configuration.
     *
     * @return Returns the PasswdMethod instance for the configuration.
     */
    public static PasswdMethod newInstance(Connection connection, PasswdConfiguration configuration) {
        String               methodName = configuration.getMethod();
        AbstractPasswdMethod method;

        if (METHOD_PW.equals(methodName)) {
            method = new PwPasswdMethod();
        } else if (methodName.startsWith(METHOD_USERADD)) {
            method = new UserAddPasswdMethod();
        } else {
            throw new ConnectionFailedException("Invalid passwd method: " + configuration.getMethod());
        }

        method.init(connection, configuration, newBecomeMethodInstance(configuration));

        return method;
    }

    /**
     * Creating a new BecomeMethod instance.
     *
     * @param configuration     The current connector configuration.
     *
     * @return Returns the BecomeMethod instance for the configuration.
     */
    private static BecomeMethod newBecomeMethodInstance(PasswdConfiguration configuration) {
        String       methodName = configuration.getBecomeMethod();
        BecomeMethod method;

        if (BECOME_METHOD_DOAS.equals(methodName)) {
            method = new DoAsBecomeMethod();
        } else if (BECOME_METHOD_NONE.equals(methodName)) {
            method = new NoneBecomeMethod();
        } else if (BECOME_METHOD_SUDO.equals(methodName)) {
            method = new SuDoBecomeMethod();
        } else {
            throw new ConnectionFailedException("Invalid become method: " + configuration.getBecomeMethod());
        }

        method.init(configuration);

        return method;
    }
}
