package exemple.org;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

public class Cifrar {

    public static SecretKey keygenKeyGeneration(int keySize) {
        SecretKey sKey = null;
        if ((keySize == 128) || (keySize == 192) || (keySize == 256)) {
            try {
                KeyGenerator kgen = KeyGenerator.getInstance("AES");
                kgen.init(keySize);
                sKey = kgen.generateKey();

            } catch (NoSuchAlgorithmException ex) {
                System.err.println("Generador no disponible.");
            }
        }
        return sKey;
    }

    public static KeyPair randomGenerate(int len) {
        KeyPair keys = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(len);
            keys = keyGen.genKeyPair();
        } catch (Exception ex) {
            System.err.println("Generador no disponible.");
        }
        return keys;
    }

    public static byte[] encryptData(byte[] data, PublicKey pub) {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");
            cipher.init(Cipher.ENCRYPT_MODE, pub);
            encryptedData = cipher.doFinal(data);
        } catch (Exception ex) {
            System.err.println("Error xifrant: " + ex);
        }
        return encryptedData;
    }

    public static byte[] decryptData(byte[] data, PrivateKey pri) {
        byte[] decryptData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");
            cipher.init(Cipher.DECRYPT_MODE, pri);
            decryptData = cipher.doFinal(data);
        } catch (Exception ex) {
            System.err.println("Error xifrant: " + ex);
        }
        return decryptData;
    }

    public static KeyStore loadKeyStore(String ksFile, String ksPwd) throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        File f = new File(ksFile);
        if (f.isFile()) {
            FileInputStream in = new FileInputStream(f);
            ks.load(in, ksPwd.toCharArray());
        }
        return ks;
    }

    public static PublicKey getPublicKey(String fichero) throws FileNotFoundException, CertificateException {
        InputStream certificateInputStream = new FileInputStream(fichero);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = certificateFactory.generateCertificate(certificateInputStream);
        return certificate.getPublicKey();
    }

    public static PublicKey getPublicKey(KeyStore keyStore, String alias, String password) throws KeyStoreException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException {
        Key key;
        key = keyStore.getKey("lamevaclaum9", "123456789".toCharArray());
        PublicKey publicKey = null;
        if (key instanceof PrivateKey) {
            Certificate certificate = keyStore.getCertificate(alias);
            publicKey = certificate.getPublicKey();
        }
        return publicKey;
    }

    public static byte[] signData(byte[] data, PrivateKey priv) {
        byte[] signature = null;
        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initSign(priv);
            signer.update(data);
            signature = signer.sign();
        } catch (Exception ex) {
            System.err.println("Error signant les dades: " + ex);
        }
        return signature;
    }

    public static boolean validateSignature(byte[] data, byte[] signature, PublicKey pub) {
        boolean isValid = false;
        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initVerify(pub);
            signer.update(data);
            isValid = signer.verify(signature);
        } catch (Exception ex) {
            System.err.println("Error validant les dades: " + ex);
        }
        return isValid;
    }

    public static byte[][] encryptWrappedData(byte[] data, PublicKey pub) {
        byte[][] encWrappedData = new byte[2][];
        try {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128);
            SecretKey sKey = kgen.generateKey();
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, sKey);
            byte[] encMsg = cipher.doFinal(data);
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.WRAP_MODE, pub);
            byte[] encKey = cipher.wrap(sKey);
            encWrappedData[0] = encMsg;
            encWrappedData[1] = encKey;
        } catch (Exception ex) {
            System.err.println("Ha succeït un error xifrant: " + ex);
        }
        return encWrappedData;
    }
    public static byte[] dencryptWrappedData(byte[][] data, PrivateKey priv) {
        byte[] mensajeDesc = new byte[0];
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.UNWRAP_MODE, priv);
            SecretKey secretkey = (SecretKey) cipher.unwrap(data[1], "AES", Cipher.SECRET_KEY);
            Cipher cipher2 = Cipher.getInstance("AES");
            cipher2.init(Cipher.DECRYPT_MODE, secretkey);
            mensajeDesc = cipher2.doFinal(data[0]);
        } catch (Exception  ex) {
            System.err.println("Ha succeït un error desxifrant: " + ex);
        }
        return mensajeDesc;

    }
}

