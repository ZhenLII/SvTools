package param;

/**
 * @author JiangSenwei
 */
public class ParameterIdentifier {
    private String fullName;
    private String abbreviation;
    private String description;
    private Boolean needValue;

    public ParameterIdentifier(String fullName, String abbreviation, String description,Boolean needValue) {
        this.fullName = fullName;
        this.abbreviation = abbreviation;
        this.description = description;
        this.needValue = needValue;
    }

    public boolean match(String key) {
        if(abbreviation != null) {
            return fullName.equals(key) || abbreviation.equals(key);
        }else {
            return fullName.equals(key);
        }
    }

    public Boolean needValue() {
        return needValue;
    }

    @Override
    public int hashCode() {
        return (fullName + abbreviation).hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        return (obj instanceof ParameterIdentifier) && (fullName.equals(((ParameterIdentifier) obj).fullName));
    }

    public String getFullName() {
        return fullName;
    }

    public String getAbbreviation() {
        return abbreviation;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return "ParameterIdentifier{" +
                "fullName='" + fullName + '\'' +
                ", abbreviation='" + abbreviation + '\'' +
                ", description='" + description + '\'' +
                '}';
    }
}
