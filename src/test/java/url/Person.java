package url;

/**
 * @author JiangSenwei
 */
public class Person extends AbstractUrlParameter {
    @UrlParameter("Name")
    private String name;
    @UrlParameter("Age")
    private Integer age;
    @UrlParameter("Sex")
    private String gender;
    @UrlParameter("Country")
    private String nation;
    @UrlParameter("Id")
    private String identity;

    public Person(String name, Integer age, String gender, String nation, String identity) {
        super("http://mockurl.com/person/add");
        this.name = name;
        this.age = age;
        this.gender = gender;
        this.nation = nation;
        this.identity = identity;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Integer getAge() {
        return age;
    }

    public void setAge(Integer age) {
        this.age = age;
    }

    public String getGender() {
        return gender;
    }

    public void setGender(String gender) {
        this.gender = gender;
    }

    public String getNation() {
        return nation;
    }

    public void setNation(String nation) {
        this.nation = nation;
    }

    public String getIdentity() {
        return identity;
    }

    public void setIdentity(String identity) {
        this.identity = identity;
    }

    static class Student extends Person {

        @UrlParameter("Sid")
        private Integer sid;


        public Student(Integer sid ,String name, Integer age, String gender, String nation, String identity) {
            super(name, age, gender, nation, identity);
            this.sid = sid;
        }
    }
}
