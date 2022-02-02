package com.ibe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;

import static com.utils.CryptoUtils.sha1;
import static com.utils.FileUtils.*;

/**
 * 用户私钥生成，用于第四步解密
 * 生成 sk = {H(ID)^x}
 */

public class KeyGen {

    /**
     * 密钥生成阶段输入用户id
     */
    private final String id;

    public KeyGen(String id) {
        this.id = id;
    }

    public void keygen(String mskFileName, String skFileName) throws NoSuchAlgorithmException {
        Pairing bp = Setup.bp;

        //用户id映射到群元素
        byte[] idHash = sha1(id);
        Element QID = bp.getG1().newElementFromHash(idHash, 0, idHash.length).getImmutable();

        //获取主私钥，用于生成用户私钥
        Properties mskProp = loadPropFromFile(mskFileName);
        String xString = mskProp.getProperty("x");
        //Element x = bp.getZr().newElement(new BigInteger(xString));  //对应于前面的x.toBigInteger().toString()方式
        Element x = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xString)).getImmutable();  //Base64编码后对应的恢复元素的方法

        //生成用户私钥sk QID_x 将私钥存入到sk.properties配置文件中
        Element sk = QID.powZn(x).getImmutable();
        Properties skProp = GenerateProperties("sk", Base64.getEncoder().encodeToString(sk.toBytes()));
        storePropToFile(skProp, skFileName);
    }

}
