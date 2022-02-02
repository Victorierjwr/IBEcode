package com.ibe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import static com.utils.FileUtils.GenerateProperties;
import static com.utils.FileUtils.storePropToFile;

/**
 * 初始化生成公共参数，以及主密钥，公钥
 * params = {e(),G1,GT,Zr}
 * 主密钥 = x
 * 公钥 = {g_x,g}
 */

public class Setup {

    /**
     * 初始化阶段输入：公共参数（参数值）
     */
    public String pairingParametersFileName;
    public String pkFileName;
    public String mskFileName;

    /**
     * 公共参数，可公开的
     */
    public static Pairing bp;
    public static Element g;
    public static Element g_x;

    private Properties prop;

    public Setup(){}

    /**
     * 初始公共参数文件地址名
     * @param pairingParametersFileName 双线性对初始参数
     * @param pkFileName 生成的公钥存放在这里
     * @param mskFileName 生成的主密钥存放在这里
     */
    public Setup(String pairingParametersFileName, String pkFileName, String mskFileName) {
        this.pairingParametersFileName = pairingParametersFileName;
        this.pkFileName = pkFileName;
        this.mskFileName = mskFileName;
    }

    public void setup() {
        bp = PairingFactory.getPairing(pairingParametersFileName);
        /**
         * 主私钥
         */
        Element x = bp.getZr().newRandomElement().getImmutable();

        /**
         * 存储主私钥到msk.properties文件中
         */
        String x2String = Base64.getEncoder().encodeToString(x.toBytes());
        //mskProp.setProperty("x", x.toBigInteger().toString());
        // x有toBigInteger方法，因此可以用这种方式，但g不能
        //后面对写的元素统一采用如下方法：首先将元素转为字节数组，然后进行Base64编码为可读字符串
        Properties mskProp = GenerateProperties("x",x2String);
        //System.out.println(mskProp);
        storePropToFile(mskProp, mskFileName);

        g = bp.getG1().newRandomElement().getImmutable();
        g_x = g.powZn(x).getImmutable();
        //pkProp.setProperty("g", new String(g.toBytes()));
        //可以用这种方式将g转换为字符串后写入，但文件中显示乱码
        //为了避免乱码问题，采用Base64编码方式
        String g2String = Base64.getEncoder().encodeToString(g.toBytes());
        String g_x2String = Base64.getEncoder().encodeToString(g_x.toBytes());
        Map<String,String> m = new HashMap<>();
        m.put("g",g2String); m.put("g_x",g_x2String);
        Properties pkProp = GenerateProperties(m);
        //System.out.println(pkProp);
        storePropToFile(pkProp, pkFileName);
    }
}
