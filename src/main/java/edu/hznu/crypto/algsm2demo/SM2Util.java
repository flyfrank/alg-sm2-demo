package edu.hznu.crypto.algsm2demo;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * @author YaokeHu
 * @description
 * @date 2022-01-24 17:35
 **/
public class SM2Util {
    /**
     * SM2加密算法
     *
     * @param data      明文数据
     * @param publicKey 公钥
     * @return
     */
    public static String encrypt(String data, PublicKey publicKey) throws InvalidCipherTextException {
        ECPublicKeyParameters ecPublicKeyParameters = null;
        if (publicKey instanceof BCECPublicKey) {
            BCECPublicKey bcecPublicKey = (BCECPublicKey) publicKey;
            ECParameterSpec ecParameterSpec = bcecPublicKey.getParameters();
            ECDomainParameters ecDomainParameters = new ECDomainParameters(ecParameterSpec.getCurve(),
                ecParameterSpec.getG(), ecParameterSpec.getN());
            ecPublicKeyParameters = new ECPublicKeyParameters(bcecPublicKey.getQ(), ecDomainParameters);
        }
        SM2Engine sm2Engine = new SM2Engine();
        sm2Engine.init(true, new ParametersWithRandom(ecPublicKeyParameters, new SecureRandom()));

        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
        byte[] arrayOfBytes = sm2Engine.processBlock(dataBytes, 0, dataBytes.length);
        return Hex.toHexString(arrayOfBytes);
    }

    /**
     * SM2解密算法
     *
     * @param cipherData 密文数据
     * @param privateKey 私钥
     * @return
     */
    public static String decrypt(String cipherData, PrivateKey privateKey) throws InvalidCipherTextException {
        BCECPrivateKey bcecPrivateKey = (BCECPrivateKey) privateKey;
        ECParameterSpec ecParameterSpec = bcecPrivateKey.getParameters();

        ECDomainParameters ecDomainParameters = new ECDomainParameters(ecParameterSpec.getCurve(),
            ecParameterSpec.getG(), ecParameterSpec.getN());
        ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(bcecPrivateKey.getD(),
            ecDomainParameters);

        SM2Engine sm2Engine = new SM2Engine();
        sm2Engine.init(false, ecPrivateKeyParameters);

        byte[] cipherDataBytes = Hex.decode(cipherData);
        byte[] arrayOfBytes = sm2Engine.processBlock(cipherDataBytes, 0, cipherDataBytes.length);
        return new String(arrayOfBytes, StandardCharsets.UTF_8);
    }

}
