package com.ibe;


import com.utils.CryptoUtils;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class testDemo {

    public String idBob = "bob@example.com";
    public String idAlice = "alice@example.com";
    public String message = "i hate you i hate you i hate you i hate you i hate you";

    //data/msk.properties
    //src/test/resources/data/ct.properties
    public String dir = "src/test/resources/data/";
    public String pairingParametersFileName = "com/ibe/params/curves/a.properties";
    public String pkFileName = dir + "pk.properties";
    public String mskFileName = dir + "msk.properties";
    public String skFileName = dir + "sk.properties";
    public String ctFileName = dir + "ct.properties";

    @Test
    public void testSha1() throws NoSuchAlgorithmException {
        String test_s = "2222";
        byte[] m = test_s.getBytes();
        byte[] c = CryptoUtils.sha1(test_s);
        for (byte b : m) {
            System.out.print(b);
        }
        System.out.println("----------");
        for (byte b : c) {
            System.out.print(b);
        }
    }

    @Test
    public void IBE_test(){
        //明文
        System.out.println(message);

    }

    @Test
    public void SetupTest(){
        Setup setup =  new Setup(pairingParametersFileName,pkFileName,mskFileName);
        setup.setup();
    }

    @Test
    public void KeygenTest() throws NoSuchAlgorithmException {
        Setup setup =  new Setup(pairingParametersFileName,pkFileName,mskFileName);
        setup.setup();
        KeyGen keyGen = new KeyGen(idAlice);
        keyGen.keygen(mskFileName,skFileName);
    }

    @Test
    public void EncryptTest() throws NoSuchAlgorithmException {
        Setup setup =  new Setup(pairingParametersFileName,pkFileName,mskFileName);
        setup.setup();
        KeyGen keyGen = new KeyGen(idAlice);
        keyGen.keygen(mskFileName,skFileName);

        Encrypt encrypt = new Encrypt(idAlice,message);
        encrypt.encrypt(ctFileName);
    }

    @Test
    public void DecryptTest() throws NoSuchAlgorithmException {
        Setup setup =  new Setup(pairingParametersFileName,pkFileName,mskFileName);
        setup.setup();
        KeyGen keyGen = new KeyGen(idAlice);
        keyGen.keygen(mskFileName,skFileName);
        Encrypt encrypt = new Encrypt(message,idAlice);
        encrypt.encrypt(ctFileName);

        //使用无参构造方法进行解密，参数从properties中读取
        Decrypt decrypt = new Decrypt();
        String res_m = decrypt.decrypt(ctFileName, skFileName);

        System.out.println("明文为:\n" + message);
        System.out.println("密文为:\n" + res_m);

    }
}
