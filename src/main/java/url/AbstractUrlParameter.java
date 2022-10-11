package url;

import constants.SymbolConstants;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @author JiangSenwei
 */
public abstract class AbstractUrlParameter {
    private String baseUrl;

    public AbstractUrlParameter(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public AbstractUrlParameter() {
        baseUrl = "";
    }

    public String buildUrlParameters() {
        return buildUrlParameters(baseUrl);
    }

    public String buildUrlParameters(String baseUrl) {
        String parameters = "";
        Class<?> type = this.getClass();
        List<Field> fieldList = new ArrayList<>();
        // 从最终的类开始获取属性， 不断向父类获取属性，将子类父类的所有属性放到同一个List中
        while (Object.class != type){
            fieldList.addAll(new ArrayList<>(Arrays.asList(type.getDeclaredFields())));
            type = type.getSuperclass();
        }

        Map<String,String> kvs = new HashMap<>();
        try {
            for(Field field : fieldList) {
                field.setAccessible(true);
                if(field.isAnnotationPresent(UrlParameter.class)) {
                    Class<?> fieldType = field.getType();
                    Annotation annotation = field.getAnnotation(UrlParameter.class);
                    Method annotationValue = UrlParameter.class.getDeclaredMethod("value");
                    // 获得参数名
                    String paramName = (String)annotationValue.invoke(annotation);
                    if(paramName == null) {
                        throw new IllegalArgumentException("Parameter name can not be null");
                    }
                    if(kvs.containsKey(paramName)){
                        throw new IllegalArgumentException("Duplicate parameter name");
                    }
                    // 获得参数值
                    String value = field.get(this) == null ? null : field.get(this).toString();
                    kvs.put(paramName,value);
                }
            }
        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
            e.printStackTrace();
            throw new RuntimeException("Build Error");
        }
        if(!kvs.isEmpty()) {
            parameters += SymbolConstants.QUESTION;
            parameters += kvs.entrySet().stream().map(e -> e.getKey()+SymbolConstants.EQUAL+e.getValue()).collect(Collectors.joining(SymbolConstants.AND));
        }

        return baseUrl + parameters;

    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }
}
