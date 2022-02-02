package com.ibe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;

import static com.ibe.Setup.bp;
import static com.utils.CryptoUtils.sha1;
import static com.utils.FileUtils.loadPropFromFile;

public class Decrypt {

    /**
     * 解密阶段输入私钥和密文
     */
    private Element sk;
    private Properties ct;

    public Decrypt(){};

    public Decrypt(Element sk, Properties ct) {
        this.sk = sk;
        this.ct = ct;
    }

    public Decrypt(String sk, Properties ct) {
        this.sk = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sk)).getImmutable();
        this.ct = ct;
    }

    public String decrypt(String ctFileName) throws NoSuchAlgorithmException {
        Pairing bp = Setup.bp;

        //获取密文部分(C1,C2)
        String C1_str = ct.getProperty("C1");
        Element C1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C1_str)).getImmutable();
        String C2_str = ct.getProperty("C2");
        byte[] C2 = Base64.getDecoder().decode(C2_str);

        //解密细节
        byte[] res = dec(sk,C1,C2);
        return new String(res);
    }

    private byte[] dec(Element sk, Element c1, byte[] c2) throws NoSuchAlgorithmException {
        //生成密文第二部分左边 e(h(ID)^x,g^r) = e(H(ID),g^x)^r
        Element gID = bp.pairing(sk, c1).getImmutable();
        byte[] HgID = sha1(new String(gID.toBytes()));
        int len = HgID.length;
        byte[] res = new byte[c2.length];
        for (int i = 0; i < c2.length; i++){
            res[i] = (byte)(c2[i] ^ HgID[i%len]);
        }
        return res;
    }

    //重载解密方式
    public String decrypt(String ctFileName, String skFileName) throws NoSuchAlgorithmException {
        Pairing bp = Setup.bp;

        //获取私钥
        Properties skProp = loadPropFromFile(skFileName);
        String skString = skProp.getProperty("sk");
        Element sk = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skString)).getImmutable();

        //获取密文
        Properties ctProp = loadPropFromFile(ctFileName);
        String C1_str = ctProp.getProperty("C1");
        Element C1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C1_str)).getImmutable();
        String C2_str = ctProp.getProperty("C2");
        byte[] C2 = Base64.getDecoder().decode(C2_str);

        //具体解密
        Element gID = bp.pairing(sk, C1).getImmutable();

        String gIDString = new String(gID.toBytes());
        byte[] HgID = sha1(gIDString);
        int len = HgID.length;
        byte[] res = new byte[C2.length];
        for (int i = 0; i < C2.length; i++){
            res[i] = (byte)(C2[i] ^ HgID[i%len]);
        }
        return new String(res);
    }
}
