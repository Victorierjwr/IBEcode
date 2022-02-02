package com.ibe;

import com.utils.FileUtils;
import org.junit.Test;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;

public class IBE_test {

    Properties prop = FileUtils.loadPropFromFile("src/test/resources/data.properties");

    public String UserID = prop.getProperty("UserID");
    public String message_dir = prop.getProperty("message_dir");

    //data/msk.properties
    //src/test/resources/data/ct.properties
    public String dir = prop.getProperty("dir");
    public String pairingParametersFileName = prop.getProperty("pairingParametersFileName");
    public String pkFileName = dir + prop.getProperty("pkFileName");
    public String mskFileName = dir + prop.getProperty("mskFileName");
    public String skFileName = dir + prop.getProperty("skFileName");
    public String ctFileName = dir + prop.getProperty("ctFileName");

    public String message = readMessage(message_dir);

    public String readMessage(String message_dir){

        return readFromFile(message_dir);
    }

    public String readFromFile(String message_dir) {
        StringBuilder sb = new StringBuilder();
        try {
            String encoding="GBK";
            File file=new File(message_dir);
            if(file.isFile() && file.exists()){ //判断文件是否存在
                InputStreamReader read = new InputStreamReader(
                        new FileInputStream(file),encoding);//考虑到编码格式
                BufferedReader bufferedReader = new BufferedReader(read);
                String lineTxt = null;
                while((lineTxt = bufferedReader.readLine()) != null){
                    sb.append(lineTxt);
                    sb.append("\n");
                    //System.out.println(lineTxt);
                }
                read.close();
            }else{
                System.out.println("找不到指定的文件");
            }
        } catch (Exception e) {
            System.out.println("读取文件内容出错");
            e.printStackTrace();
        }
        return sb.toString();
    }

    @Test
    public void test(){
        System.out.println(message);
    }

    @Test
    public void ibeTest() throws NoSuchAlgorithmException {

        Setup setup =  new Setup(pairingParametersFileName,pkFileName,mskFileName);
        setup.setup();
        KeyGen keyGen = new KeyGen(UserID);
        keyGen.keygen(mskFileName,skFileName);
        Encrypt encrypt = new Encrypt(message,UserID);
        encrypt.encrypt(ctFileName);

        //使用无参构造方法进行解密，参数从properties中读取
        Decrypt decrypt = new Decrypt();
        String res_m = decrypt.decrypt(ctFileName, skFileName);

        System.out.println("加密前明文为:\n" + message);
        System.out.println("解密后明文为:\n" + res_m);
    }
}
