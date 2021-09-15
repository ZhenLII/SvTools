import org.junit.Assert;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

/**
 * @author JiangSenwei
 */
public class ListUtilsTest {
    private List<Integer> integers1 = List.of(
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20
    );

    @Test
    public void spliteListTest() {
        // 正常情况
        List<List<Integer>> res1 = ListUtils.splitList(integers1, 3);
        Assert.assertEquals(7, res1.size());
        for (int i = 0; i < integers1.size(); i++) {
            Assert.assertEquals(integers1.get(i), res1.get(i / 3).get(i % 3));
        }


        List<Integer> integers2 = new ArrayList<>();
        for(int i=0;i<9999;i++) {
            integers2.add(i);
        }
        List<List<Integer>> res4 = ListUtils.splitList(integers2, 999);
        Assert.assertEquals(11, res4.size());
        for (int i = 0; i < integers2.size(); i++) {
            Assert.assertEquals(integers2.get(i), res4.get(i / 999).get(i % 999));
        }

        // 分片大小小于等于0
        List<List<Integer>> res2 = ListUtils.splitList(integers1, -1);
        Assert.assertEquals(1, res2.size());
        for (int i = 0; i < integers1.size(); i++) {
            Assert.assertEquals(integers1.get(i), res2.get(0).get(i));
        }

        // 分片大小大于原List
        List<List<Integer>> res3 = ListUtils.splitList(integers1, integers1.size() + 1);
        Assert.assertEquals(1, res3.size());
        for (int i = 0; i < integers1.size(); i++) {
            Assert.assertEquals(integers1.get(i), res3.get(0).get(i));
        }
    }


}
