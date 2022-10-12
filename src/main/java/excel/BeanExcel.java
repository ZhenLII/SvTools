package excel;

import org.apache.poi.hssf.usermodel.HSSFSheet;
import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author JiangSenwei
 *
 * 根据Bean的属性创建Sheet和表格行
 */
public class BeanExcel {
    private Logger log = LoggerFactory.getLogger(this.getClass());
    private HSSFWorkbook wb = new HSSFWorkbook();
    private Map<String,Class<?>> sheetTypeMap = new ConcurrentHashMap<>();
    private Map<String,Map<String,Integer>> sheetRowColumnMap = new ConcurrentHashMap<>();

    private final static String INT = "int";
    private final static String DOUBLE = "double";
    private final static String LONG = "long";
    private final static String FLOAT = "float";
    private final static String BOOL = "boolean";
    private final static String INTEGER = "java.lang.Integer";
    private final static String DOUBLE_TYPE = "java.lang.Double";
    private final static String LONG_TYPE = "java.lang.Long";
    private final static String FLOAT_TYPE = "java.lang.Float";
    private final static String BOOLEAN = "java.lang.Boolean";

    /**
     * 用指定的实体类新建Sheet，表头使用实体类中使用了注解的属性的注解值作为列名
     * */
    public void addSheet(Class<?> clazz, String sheetName) {
        // 实体类必须实现 ExcelRowBean 接口，作为能力校验
        if(!ExcelRowBean.class.isAssignableFrom(clazz)) {
            throw new IllegalArgumentException("Sheet type must implement " + ExcelRowBean.class.getName());
        }
        HSSFSheet sheet = wb.createSheet(sheetName);
        sheetTypeMap.put(sheetName,clazz);
        List<String> columnNames = new ArrayList<>();
        Field[] fields = clazz.getDeclaredFields();
        Map<String,Integer> columnMap = new HashMap<>();
        for(Field field : fields) {
            // 存在RowHeader注解的属性将注解值作为列名
            if(field.isAnnotationPresent(RowHeader.class)) {
                RowHeader rowHeader = field.getAnnotation(RowHeader.class);
                String name = rowHeader.value();
                // 列不能重复
                if (columnNames.contains(name)) {
                    throw new IllegalArgumentException("Repeated row name.");
                } else {
                    columnNames.add(name);
                }
            }
        }
        Row header = sheet.createRow(0);
        for(int i = 0; i < columnNames.size(); i++) {
            columnMap.put(columnNames.get(i),i);
            header.createCell(i).setCellValue(columnNames.get(i));
        }
        sheetRowColumnMap.put(sheetName,columnMap);
    }

    public void addSheetRow(ExcelRowBean rowBean, String sheetName){
        if(rowBean == null || sheetName == null) {
            throw new IllegalArgumentException("Parameter could not be null.");
        }
        if(!sheetTypeMap.containsKey(sheetName)) {
            throw new IllegalArgumentException("Sheet:"+sheetName+" doesn't exist.");
        }
        if(rowBean.getClass() != sheetTypeMap.get(sheetName)) {
            throw new IllegalArgumentException("Wrong row class.");
        }

        Map<String,Integer> columnMap = sheetRowColumnMap.get(sheetName);
        Field[] fields = rowBean.getClass().getDeclaredFields();
        Sheet sheet = wb.getSheet(sheetName);
        int lastRowIndex = sheet.getLastRowNum();
        Row row = sheet.createRow(lastRowIndex + 1);
        try {
            for(Field field : fields) {
                if(field.isAnnotationPresent(RowHeader.class)) {
                    RowHeader rowHeader = field.getAnnotation(RowHeader.class);
                    field.setAccessible(true);
                    String name = rowHeader.value();
                    Type type = field.getGenericType();
                    Cell cell = row.createCell(columnMap.get(name));
                    switch (type.getTypeName()) {
                        case INT:
                        case INTEGER:
                        case LONG:
                        case LONG_TYPE:
                        case FLOAT:
                        case FLOAT_TYPE:
                        case DOUBLE:
                        case DOUBLE_TYPE:
                            cell.setCellValue(Double.parseDouble(field.get(rowBean).toString()));
                            break;
                        case BOOL:
                        case BOOLEAN:
                            cell.setCellValue(Boolean.parseBoolean(field.get(rowBean).toString()));
                            break;
                        default:
                            cell.setCellValue(field.get(rowBean).toString());
                    }
                    field.setAccessible(false);
                }
            }
        } catch (Exception e) {
            log.error(e.getMessage(),e);
            sheet.removeRow(row);
            throw new RuntimeException("Fail to create row.");
        }
    }

    public boolean isEmpty() {
        return sheetTypeMap.isEmpty();
    }

    public void write(OutputStream outputStream) throws IOException {
        wb.write(outputStream);
    }

    public void write(File file) throws IOException {
        wb.write(file);
    }

}
