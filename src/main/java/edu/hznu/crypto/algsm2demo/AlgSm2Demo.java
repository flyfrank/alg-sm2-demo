package edu.hznu.crypto.algsm2demo;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;

/**
 * SM2 算法 Demo
 *
 * @author Cliven
 * @date 2018-12-20 10:42:22
 */
public class AlgSm2Demo {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidCipherTextException {
        // 获取SM2椭圆曲线的参数
        final ECGenParameterSpec sm2Spec = new ECGenParameterSpec("sm2p256v1");
        // 获取一个椭圆曲线类型的密钥对生成器
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        // 使用SM2参数初始化生成器
        kpg.initialize(sm2Spec);

        // 获取密钥对
        KeyPair keyPair = kpg.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();


        // ------------------------ SM2未压缩公钥 ----------------------------
        // 椭圆曲线公钥的点坐标
        ECPoint pubKeyPointQ = ((BCECPublicKey) publicKey).getQ();
        System.out.println("X: \n" + pubKeyPointQ.getXCoord());
        System.out.println("Y: \n" + pubKeyPointQ.getYCoord());
        // 将其表示为SM2未压缩的公钥为
        System.out.println("SM2 public key: \n"
                + "04"
                + pubKeyPointQ.getXCoord().toString()
                + pubKeyPointQ.getYCoord().toString()
        );
        // ------------------------ SM2未压缩公钥 -------------------------------

        System.out.println("Public key: \n" + Hex.toHexString(publicKey.getEncoded()));
        System.out.println("Private key: \n" + Hex.toHexString(privateKey.getEncoded()));

        System.out.println(">> 公钥BASE64: " + Base64.toBase64String(publicKey.getEncoded()));
        System.out.println(">> 私钥BASE64: " + Base64.toBase64String(privateKey.getEncoded()));

        // 生成SM2sign with sm3 签名验签算法实例
        Signature signature = Signature.getInstance("SM3withSm2", new BouncyCastleProvider());

        /*
         * 签名
         */
        // 签名需要使用私钥，使用私钥 初始化签名实例
        signature.initSign(privateKey);
        // 签名原文
        byte[] plainText = "你好".getBytes(StandardCharsets.UTF_8);
        // 写入签名原文到算法中
        signature.update(plainText);
        // 计算签名值
        byte[] signatureValue = signature.sign();
        System.out.printf("signature[%d]: %s\n", signatureValue.length, Hex.toHexString(signatureValue));

        /*
         * 验签
         */
        // 签名需要使用公钥，使用公钥 初始化签名实例
        signature.initVerify(publicKey);
        // 写入待验签的签名原文到算法中
        signature.update(plainText);
        // 验签
        System.out.println("Signature verify result: " + signature.verify(signatureValue));

        String plainText2 = "hello sm2";
        String encrypted = SM2Util.encrypt(plainText2, publicKey);
        System.out.println("encrypted:" + encrypted);
        String result = new String(SM2Util.decrypt(encrypted, privateKey));
        System.out.println("result:" + result);
    }
}
