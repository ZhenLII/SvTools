package url;

import org.junit.Test;

/**
 * @author JiangSenwei
 */

public class UrlTest {
    @Test
    public void testBuildUrl(){
        Person person = new Person("Sv",18,"male","CN","123456789");
        Person.Student student = new Person.Student(100,"Sv",18,"male","CN","123456789");
        System.out.println(person.buildUrlParameters());
        System.out.println(student.buildUrlParameters());
    }


}
