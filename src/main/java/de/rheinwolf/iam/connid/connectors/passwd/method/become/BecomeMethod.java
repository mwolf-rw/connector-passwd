package de.rheinwolf.iam.connid.connectors.passwd.method.become;

import de.rheinwolf.iam.connid.connectors.passwd.PasswdConfiguration;
import de.rheinwolf.iam.connid.connectors.passwd.connection.CommandResult;
import de.rheinwolf.iam.connid.connectors.passwd.connection.Connection;

/**
 * Executing commands as administrative user.
 */
public interface BecomeMethod {
    /**
     * Executing a command.
     *
     * @param connection        The connection where the command should be executed.
     * @param stdin             The input for the command. Can be null.
     * @param command           The command that should be executed.
     * @param args              The arguments for the command.
     *
     * @return Returns a CommandResult instance.
     */
    CommandResult execute(Connection connection, byte[] stdin, String command, String... args);

    /**
     * Initializing the method.
     *
     * @param configuration     The connector configuration.
     */
    void init(PasswdConfiguration configuration);
}
