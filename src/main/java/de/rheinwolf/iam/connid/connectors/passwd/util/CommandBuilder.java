package de.rheinwolf.iam.connid.connectors.passwd.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Helper methods for building commands.
 */
public class CommandBuilder {
    /**
     * Retrieving the command as string.
     *
     * @param args      The input.
     *
     * @return Returns the command as single string.
     */
    public static String asString(String[] args) {
        return String.join(" ", asStringArray(args));
    }

    /**
     * Retrieving the command as string array.
     *
     * @param args      The input.
     *
     * @return Returns the command as string array.
     */
    public static String[] asStringArray(String[] args) {
        List<String> result = new ArrayList<>(args.length);

        for (String arg : args) {
            String escapedArgument = arg.replace("\"", "\\\"");

            if (arg.contains(" ")) {
                escapedArgument = "\"" + escapedArgument + "\"";
            } else {
                escapedArgument = escapedArgument.replace("'", "\\'");
            }

            if (escapedArgument.isEmpty())
                escapedArgument = "\"\"";

            result.add(escapedArgument);
        }

        return result.toArray(new String[0]);
    }

    /**
     * Converting an object to a command value suitable to be used in
     * passwd files. Replacing any characters that are not allowed to
     * be used with an underscore.
     *
     * @param value     The input value.
     *
     * @return Returns the value as string.
     */
    public static String toCommandValue(Object value) {
        String stringValue = Objects.toString(value);

        return stringValue
                .replace(",", "_")
                .replace(":", "_");
    }
}
