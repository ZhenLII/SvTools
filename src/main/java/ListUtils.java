import java.util.ArrayList;
import java.util.List;

/**
 * @author JiangSenwei
 */
public class ListUtils {

    /**
     * 将列表按照指定的大小分片成为小列表的集合
     *
     * @param list 大列表
     * @param size 分片大小
     * @return 小列表集合
     */
    public static <T> List<List<T>> splitList(List<T> list, int size) {
        if (size <= 0 || size > list.size()) {
            return List.of(list);
        }
        List<List<T>> res = new ArrayList<>();
        int length = list.size();
        int index = length / size + (length % size == 0 ? 0 : 1);
        for (int i = 0; i < index; i++) {
            res.add(list.subList(i * size, i + 1 == index ? length : (i + 1) * size));
        }
        return res;
    }
}
