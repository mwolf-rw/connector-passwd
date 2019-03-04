package de.rheinwolf.iam.connid.connectors.passwd.method.become;

import de.rheinwolf.iam.connid.connectors.passwd.PasswdConfiguration;
import de.rheinwolf.iam.connid.connectors.passwd.connection.CommandResult;
import de.rheinwolf.iam.connid.connectors.passwd.util.GuardedStringAccessor;

import org.identityconnectors.common.security.GuardedString;

import java.util.List;

/**
 * Base implementation for a become method using the password stored in the configuration.
 */
public abstract class AbstractBecomeMethod implements BecomeMethod {
    private GuardedString encrypedPassword = null;

    /**
     * Initializing the method.
     *
     * @param configuration The connector configuration.
     */
    @Override
    public void init(PasswdConfiguration configuration) {
        this.encrypedPassword = configuration.getBecomePassword();
    }

    /**
     * Injecting the password into the byte array.
     *
     * @param input         The input byte array.
     *
     * @return Returns the byte array including the password.
     */
    byte[] injectPassword(byte[] input) {
        byte[] password = GuardedStringAccessor.asByteArray(encrypedPassword);
        byte[] result;

        if ((password == null) && (input == null))
            return null;

        if ((password == null) || (password.length == 0))
            return input;

        if (input == null)
            input = new byte[0];

        result = new byte[password.length + input.length + 1];
        result[password.length] = '\n';

        System.arraycopy(password, 0, result, 0, password.length);
        System.arraycopy(input, 0, result, password.length + 1, input.length);

        return result;
    }

    /**
     * Removing the password prompt from the result.
     *
     * @param result        The command result.
     *
     * @return The command result without password prompt.
     */
    CommandResult removePasswordPrompt(CommandResult result) {
        if (encrypedPassword != null) {
            List<String> stderr = result.getStdErr();

            if (!stderr.isEmpty())
                stderr.remove(0);
        }

        return result;
    }
}
