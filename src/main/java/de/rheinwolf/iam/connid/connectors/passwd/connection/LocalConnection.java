package de.rheinwolf.iam.connid.connectors.passwd.connection;

import de.rheinwolf.iam.connid.connectors.passwd.PasswdConfiguration;
import de.rheinwolf.iam.connid.connectors.passwd.util.CommandBuilder;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConnectionBrokenException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

/**
 * Pseudo-connection to the local system.
 */
public class LocalConnection implements Connection {
    private static final Log LOG = Log.getLog(LocalConnection.class);

    /**
     * Trying to authenticate using a username/password pair.
     *
     * @param configuration The configuration instance.
     * @param username      The username.
     * @param password      The password.
     */
    @Override
    public void authenticate(PasswdConfiguration configuration, String username, GuardedString password) {
        throw new ConnectionBrokenException("Authentication op is not implemented for local connections");
    }

    /**
     * Closing the connection.
     */
    @Override
    public void close() {
        //
    }

    /**
     * Executing a command.
     *
     * @param stdin             The input for the command. Can be null.
     * @param args              The arguments for the command.
     *
     * @return Returns a list of output lines.
     */
    @Override
    public CommandResult execute(byte[] stdin, String... args) {
        CommandResult result = new CommandResult();
        Process       process;

        LOG.ok("Starting process: {0}", Arrays.toString(args));

        try {
            process = new ProcessBuilder(CommandBuilder.asStringArray(args)).start();
        } catch (IOException e) {
            throw new ConnectionBrokenException("Could not execute command: " + Arrays.toString(args));
        }

        if ((stdin != null) && (stdin.length > 0)) {
            try (OutputStream outputStream = process.getOutputStream()) {
                outputStream.write(stdin);
            } catch (IOException e) {
                throw new ConnectionBrokenException("Could not write data to command: " + Arrays.toString(args));
            }
        }

        try (InputStream inputStream = process.getInputStream()) {
            CommandResult.readCommandOutput(inputStream, result::appendStdOut);
        } catch (IOException e) {
            throw new ConnectionBrokenException("Could not read output of command: " + Arrays.toString(args));
        }

        try (InputStream inputStream = process.getErrorStream()) {
            CommandResult.readCommandOutput(inputStream, result::appendStdErr);
        } catch (IOException e) {
            throw new ConnectionBrokenException("Could not read error output of command: " + Arrays.toString(args));
        }

        try {
            process.waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ConnectionBrokenException("Interrupted while trying to execute command", e);
        }

        result.setExitCode(process.exitValue());
        LOG.ok("Process exited with exit code {0}", result.getExitCode());

        return result;
    }

    /**
     * Initializing the connection.
     *
     * @param configuration     The configuration instance.
     */
    @Override
    public void init(PasswdConfiguration configuration) {
        //
    }

    /**
     * Checking whether the connection is alive.
     *
     * @return Returns whether the connection is alive.
     */
    @Override
    public boolean isAlive() {
        return true;
    }
}
