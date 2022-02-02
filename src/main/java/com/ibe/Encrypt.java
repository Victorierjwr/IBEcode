package com.ibe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import static com.utils.CryptoUtils.sha1;
import static com.utils.FileUtils.*;

/**
 * 输入用户id和明文
 * 输出密文CT = {C1，C2}
 */

public class Encrypt {

    /**
     * 加密阶段输入明文message和用户id进行加密过程
     */
    private final String message;
    private final String id;

    public Encrypt(String message,String id) {
        this.message = message;
        this.id = id;
    }

    public void encrypt(String ctFileName) throws NoSuchAlgorithmException {
        Pairing bp = Setup.bp;

        byte[] idHash = sha1(id);
        Element QID = bp.getG1().newElementFromHash(idHash, 0, idHash.length).getImmutable();

        Element g = Setup.g; Element g_x = Setup.g_x;
        //随机选取r->Zr中
        Element r = bp.getZr().newRandomElement().getImmutable();
        //生成密文第一部分C1 = g_r
        Element C1 = g.powZn(r).getImmutable();
        //生成双线性映射g_ID = e(QID,g_x)^r
        Element g_ID = bp.pairing(QID, g_x).powZn(r).getImmutable();

        //生成密文第二部分C2 = m*e(QID,g_x)^r  文中是使用异或下面使用异或加密
        byte[] C2 = enc(g_ID,message);

        //将密文(C1,C2)写入配置文件ct.properties中
        Map<String,String> m = new HashMap<>();
        m.put("C1", Base64.getEncoder().encodeToString(C1.toBytes()));
        m.put("C2", Base64.getEncoder().encodeToString(C2));
        Properties ctProp = GenerateProperties(m);
        storePropToFile(ctProp, ctFileName);
    }

    //加密细节 为异或 需要修改底层加密细节改此函数
    private byte[] enc(Element g_id, String message) throws NoSuchAlgorithmException {
        byte[] H2gID = sha1(new String(g_id.toBytes()));
        int len = H2gID.length;
        byte[] messageByte = message.getBytes();
//        System.out.println("双线性映射长度为: " + H2gID.length);
//        System.out.println("明文长度为:" + messageByte.length);

        byte[] C2 = new byte[messageByte.length];
        //假设m明文字节长度n小于HgID的长度20，取HgID的前n个字节进行异或
        for (int i = 0; i < messageByte.length; i++){
            C2[i] = (byte)(messageByte[i] ^ H2gID[i%len]);
        }
        return C2;
    }
}
