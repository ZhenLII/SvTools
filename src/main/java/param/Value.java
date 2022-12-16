package param;

import java.util.function.Predicate;

/**
 * @author JiangSenwei
 */
public class Value <T> {

    private T value;
    private Class<T> type;
    private Predicate<String> validation;

    public Value(T value,Class<T> type) {
        this.value = value;
        this.type = type;
        validation = null;
    }

    public Value(T value,Class<T> type, Predicate<String> validation) {
        this.value = value;
        this.type = type;
        this.validation = validation;
    }

    public T getValue() {
        return value;
    }

    public Class<T> getType() {
        return type;
    }

    public void setValidation(Predicate<String> validation) {
        this.validation = validation;
    }

    public void setValue(T value) {
        this.value = value;
    }

    public Predicate<String> getValidation() {
        return validation;
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
