package param;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * @author JiangSenwei
 */
public class HelpBasedParameters {

    private static Pattern DEFINED_PARAM = Pattern.compile(
            "^\\s*--[A-Za-z]+[a-zA-Z0-9_]*[a-zA-Z0-9](=\\{\\S+})?\\s+\\[-[A-Za-z]?]\\s+\\S+\\s*$"
    );

    private static Pattern FULL_PARAM_VALUE = Pattern.compile(
      "--[A-Za-z]+[a-zA-Z0-9_]*[a-zA-Z0-9](=\\S+)?"
    );

    private static Pattern ABBREVIATION_PARAM_VALUE = Pattern.compile(
            "-[A-Za-z](\\S+)?"
    );

    private Map<ParameterIdentifier,Value<?>> current = new HashMap<>();


    private HelpBasedParameters() throws IOException {
        InputStream helpStream = HelpBasedParameters.class.getResourceAsStream("/help");
        InputStreamReader streamReader = new InputStreamReader(helpStream, StandardCharsets.UTF_8);
        BufferedReader reader = new BufferedReader(streamReader);
        String line;
        while ((line = reader.readLine()) != null) {
            if(DEFINED_PARAM.matcher(line).matches()) {
                parseDefined(line);
            }
        }
        reader.close();
    }

    private void parseDefined(String defined) {
        boolean needValue = true;
        defined = defined.trim();
        String[] pieces = defined.split("\\s+");
        String fullNameAndValue = pieces[0];
        String fullName;
        Value<?> defaultValue;
        if(fullNameAndValue.contains("=")) {
            String[] tmp = fullNameAndValue.split("=");
            fullName = tmp[0];
            defaultValue = new Value<>(tmp[1].substring(1,tmp[1].length() - 1),String.class);
        } else {
            fullName =  fullNameAndValue;
            needValue = false;
            defaultValue = new Value<>(false,Boolean.class);
        }
        String abbreviation = pieces[1].substring(1,pieces[1].length() -1);
        if("-".equals(abbreviation)) {
            abbreviation = null;
        }
        String description = pieces[2];

        ParameterIdentifier parameterIdentifier = new ParameterIdentifier(fullName,abbreviation,description,needValue);

        for(ParameterIdentifier key : current.keySet()) {
            if(key.match(fullName) || key.match(abbreviation)) {
                throw new IllegalStateException("Parameter key is already exist.");
            }
        }
        current.put(parameterIdentifier,defaultValue);
    }

    private Map.Entry<ParameterIdentifier,Value<?>> findParameter(String k) {
        for(Map.Entry<ParameterIdentifier,Value<?>> kv : current.entrySet()) {
            if(kv.getKey().match(k)) {
                return kv;
            }
        }
        return null;
    }

    public String getStringValue(String key) {
        Map.Entry<ParameterIdentifier, Value<?>> kv = findParameter(key);
        if(kv != null) {
            return kv.getValue().toString();
        }
        return null;
    }


    private static class Holder {
        private static HelpBasedParameters instance;

        static {
            try {
                instance = new HelpBasedParameters();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static HelpBasedParameters getInstance() {
        return Holder.instance;
    }

    public void setValidation(ParameterIdentifier identifier, Predicate<String> validation) {
        Value<?> value = null;
        if((value = current.get(identifier)) != null) {
            value.setValidation(validation);
        }
    }

    public void printHelp() throws IOException {
        InputStream helpStream = HelpBasedParameters.class.getResourceAsStream("/help");
        InputStreamReader streamReader = new InputStreamReader(helpStream, StandardCharsets.UTF_8);
        BufferedReader reader = new BufferedReader(streamReader);
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
        reader.close();
    }

    public void parseArg(String arg) {
        String key;
        String value;
        if(FULL_PARAM_VALUE.matcher(arg).matches()) {
            if(arg.contains("=")) {
                String[] kv = arg.split("=");
                key = kv[0];
                value = kv[1];
            } else  {
                key = arg;
                value = null;
            }
        }
        else if(ABBREVIATION_PARAM_VALUE.matcher(arg).matches()) {
            key = arg.substring(0,2);
            value = arg.substring(2).length() == 0 ? null : arg.substring(2);
        }
        else {
            throw new IllegalArgumentException();
        }

        Map.Entry<ParameterIdentifier,Value<?>> param = findParameter(key);
        if(param != null) {
            if(param.getKey().needValue() && value == null) {
                throw new IllegalArgumentException("Parameter " + key + " need value");
            }
            if(!param.getKey().needValue() && value != null) {
                throw new IllegalArgumentException("Parameter " + key + "don't need value");
            }
            Predicate<String> validation = null;
            if((validation = param.getValue().getValidation()) != null && !validation.test(value)) {
                throw new IllegalArgumentException("Illegal value: " + value);
            }
            if(param.getKey().needValue()) {
                current.put(param.getKey(), new Value<>(value,String.class, validation));
            } else {
                current.put(param.getKey(), new Value<>(true,Boolean.class, validation));
            }
        } else {
            throw new IllegalArgumentException("Unknown parameter: " + key);
        }
    }

    public Set<ParameterIdentifier> getIdentifiers() {
        return current.keySet();
    }
}
