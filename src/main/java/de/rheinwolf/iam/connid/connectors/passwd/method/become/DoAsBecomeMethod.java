package de.rheinwolf.iam.connid.connectors.passwd.method.become;

import de.rheinwolf.iam.connid.connectors.passwd.PasswdConfiguration;
import de.rheinwolf.iam.connid.connectors.passwd.connection.CommandResult;
import de.rheinwolf.iam.connid.connectors.passwd.connection.Connection;

import java.util.Arrays;
import java.util.stream.Stream;

/**
 * Using doas as become method.
 *
 * Note: Not using the become password, as we cannot feed
 *       the password to doas without TTY.
 */
public class DoAsBecomeMethod implements BecomeMethod {
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
    @Override
    public CommandResult execute(Connection connection, byte[] stdin, String command, String... args) {
        return connection.execute(stdin, Stream.concat(
                Arrays.stream(new String[]{"doas", command}),
                Arrays.stream(args)
        ).toArray(String[]::new));
    }

    /**
     * Initializing the method.
     *
     * @param configuration The connector configuration.
     */
    @Override
    public void init(PasswdConfiguration configuration) {
        //
    }
}
