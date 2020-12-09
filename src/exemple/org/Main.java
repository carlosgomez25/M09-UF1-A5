package exemple.org;


import jdk.jfr.internal.Utils;

import javax.crypto.SecretKey;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws Exception {
        Ejercicio1_1();

        Ejercicio1_2();

        Ejercicio1_3();

        Ejercicio1_4();

        Ejercicio1_5();

        Ejercicio1_6();

        Ejercicio2();
    }



    private static void Ejercicio1_1() {
        Scanner scanner = new Scanner(System.in);

        int length = 1024;
        Cifrar.randomGenerate(length);
        KeyPair keyPair = Cifrar.randomGenerate(length);
        keyPair.getPrivate();
        keyPair.getPublic();
        System.out.println("Escribe el texto que quieras encriptytar: ");
        String text = scanner.nextLine();
        byte[] textoEncriptado = Cifrar.encryptData(text.getBytes(), keyPair.getPublic());
        byte[] textoDesencriptado = Cifrar.decryptData(textoEncriptado, keyPair.getPrivate());
        System.out.println("Texto encriptado: " + new String(textoEncriptado));
        System.out.println("Texto desencriptado: " + new String(textoDesencriptado));
    }

    public static void Ejercicio1_2() throws Exception {
        Scanner scanner = new Scanner(System.in);
        KeyStore keyStore = Cifrar.loadKeyStore("/home/carlos/keystore_carlos.ks", "123456789");
        System.out.println("Tipo de Keystore: " + keyStore.getType());
        System.out.println("Tamaño del almacenamiento: " + keyStore.size());
        Enumeration enumeration = keyStore.aliases();

        while (enumeration.hasMoreElements()) {
            System.out.println("Alias: " + enumeration.nextElement());
        }
        System.out.print("Dime el alias que quieres mostrar");
        String alias = scanner.next();
        System.out.println("Certificado: " + keyStore.getCertificate(alias));
        char[] password = "123456789".toCharArray();
        SecretKey secretKey = Cifrar.keygenKeyGeneration(128);
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(password);
        keyStore.setEntry("mykey", secretKeyEntry, protectionParameter);
        keyStore.store(new FileOutputStream("/home/carlos/keystore_carlos.ks"), "123456789".toCharArray());
    }

    public static void Ejercicio1_3() throws FileNotFoundException, CertificateException {
        String fichero = ("/home/carlos/Escritorio/jordi.cer");
        try {
            PublicKey publicKey = Cifrar.getPublicKey(fichero);
            System.out.println(publicKey);
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            System.out.println("El fichero no existe");
        }
    }

    public static void Ejercicio1_4() {
        String ksFile = "/home/carlos/keystore_carlos.ks";
        String alias = "lamevaclaum9";
        String password = "123456789";
        try {
            KeyStore keyStore = Cifrar.loadKeyStore(ksFile, password);
            PublicKey publicKey = Cifrar.getPublicKey(keyStore, alias, password);
            System.out.println(publicKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void Ejercicio1_5() {
        KeyPair keyPair = Cifrar.randomGenerate(1024);
        byte[] firm = Cifrar.signData("carlos".getBytes(), keyPair.getPrivate());
        System.out.println(new String(firm));
    }

    public static void Ejercicio1_6() {
        KeyPair keyPair= Cifrar.randomGenerate(1024);
        byte[] texto = "Carlos".getBytes();
        byte[] firm = Cifrar.signData(texto, keyPair.getPrivate());
        boolean firmBuena = Cifrar.validateSignature(texto, firm, keyPair.getPublic());
        System.out.println(firmBuena);
    }

    public static void Ejercicio2() {
        KeyPair keyPair= Cifrar.randomGenerate(1024);
        byte[] texto = "Carlos".getBytes();
        byte[][] textoEncriptado = Cifrar.encryptWrappedData(texto,keyPair.getPublic());

        byte[] textoDesencriptado = Cifrar.dencryptWrappedData(textoEncriptado,keyPair.getPrivate());
        System.out.println(new String(textoDesencriptado));


    }



}
