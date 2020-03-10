package net.devh.boot.grpc.server.util;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.*;


/**
 * @author Sev.Gao
 */
public class KeyPairUtils {


    public static PrivateKey readEncryptedKeyFromFile(String password, File keyFile) throws Exception{
        try (FileInputStream in = new FileInputStream(keyFile)) {
            byte[] buff = new byte[1024];
            StringBuilder pem = new StringBuilder();
            int len;
            while ((len = in.read(buff)) != -1) {
                pem.append(new String(buff, 0, len));
            }
            return readEncryptedKeyFromPem(password.toCharArray(), pem.toString());
        } catch (Exception e) {
            throw e;
        }
    }

    /**
     * Reading a private key from pem text
     *
     * @param password password
     * @param pemEncoding pem text
     */
    public static PrivateKey readEncryptedKeyFromPem(char[] password, String pemEncoding)
        throws IOException, PKCSException {
        PEMParser parser = new PEMParser(new StringReader(pemEncoding));
        PKCS8EncryptedPrivateKeyInfo encPrivKeyInfo = (PKCS8EncryptedPrivateKeyInfo) parser.readObject();
        InputDecryptorProvider pkcs8Prov =
            new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build(password);
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        return converter.getPrivateKey(encPrivKeyInfo.decryptPrivateKeyInfo(pkcs8Prov));
    }
}
