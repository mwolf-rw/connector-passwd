package de.rheinwolf.iam.connid.connectors.passwd.connection;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectionBrokenException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;

/**
 * Representing the result of a command that was executed
 * over a Connection instance.
 */
public class CommandResult {
    private static final Log LOG = Log.getLog(CommandResult.class);

    private final List<String> stdErr = new ArrayList<>(0);
    private final List<String> stdOut = new ArrayList<>(0);

    private int exitCode = -1;

    /**
     * Reading the output from a command and storing it in a consumer.
     *
     * @param inputStream       The input stream for the command.
     * @param consumer          The consumer.
     *
     * @throws IOException if an I/O error occurs.
     */
    static void readCommandOutput(InputStream inputStream, Consumer<String> consumer) throws IOException {
        InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
        BufferedReader    bufferedReader    = new BufferedReader(inputStreamReader);
        String            line;

        while ((line = bufferedReader.readLine()) != null) {
            consumer.accept(line);
        }
    }

    /**
     * Appending a line to the stderr.
     *
     * @param line          The line from the stderr stream.
     */
    void appendStdErr(String line) {
        LOG.ok("stderr: {0}", line);
        stdErr.add(line);
    }

    /**
     * Appending a line to the stdout.
     *
     * @param line          The line from the stdout stream.
     */
    void appendStdOut(String line) {
        LOG.ok("stdout: {0}", line);
        stdOut.add(line);
    }

    /**
     * Retrieving the exit code of the command.
     *
     * @return Returns the exit code as integer.
     */
    public int getExitCode() {
        return exitCode;
    }

    /**
     * Retrieving the stderr of the command.
     *
     * @return Returns the output as a list of String.
     */
    public List<String> getStdErr() {
        return stdErr;
    }

    /**
     * Retrieving the stdout of the command.
     *
     * @return Returns the output as a list of String.
     */
    public List<String> getStdOut() {
        return stdOut;
    }

    /**
     * Checking whether the command exited with the correct exit code.
     *
     * @param exitCodes     The expected exit codes.
     */
    public CommandResult expect(int... exitCodes) {
        if (Arrays.stream(exitCodes).noneMatch(Integer.valueOf(exitCode)::equals))
            throw new ConnectionBrokenException("Expected exit codes " + Arrays.toString(exitCodes) + ", got " + exitCode);

        return this;
    }

    /**
     * Checking whether the stderr stream is empty.
     */
    public CommandResult expectStdErrIsEmpty() {
        if (!stdErr.isEmpty())
            throw new ConnectionBrokenException("Expected empty stderr stream, got: " + stdErr);

        return this;
    }

    /**
     * Setting the exit code for the command.
     *
     * @param exitCode      The exit code.
     */
    void setExitCode(int exitCode) {
        this.exitCode = exitCode;
    }
}
