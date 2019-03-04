package de.rheinwolf.iam.connid.connectors.passwd.method.become;

import de.rheinwolf.iam.connid.connectors.passwd.connection.CommandResult;
import de.rheinwolf.iam.connid.connectors.passwd.connection.Connection;

import java.util.Arrays;
import java.util.stream.Stream;

/**
 * Using sudo as become method.
 */
public class SuDoBecomeMethod extends AbstractBecomeMethod {
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
        CommandResult result = connection.execute(injectPassword(stdin), Stream.concat(
                Arrays.stream(new String[]{"sudo", "-k", "-S", command}),
                Arrays.stream(args)
        ).toArray(String[]::new));

        return removePasswordPrompt(result);
    }
}
