package net.devh.boot.grpc.server.util;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.springframework.util.Assert;

import java.io.File;
import java.io.FileInputStream;
import java.io.StringReader;
import java.security.cert.X509Certificate;


/**
 * @author Sev.Gao
 */
public class CertificateUtils {

    public static X509Certificate readCertificateFromFile(File keyCertChainFile) throws Exception{
        try (FileInputStream in = new FileInputStream(keyCertChainFile)) {
            byte[] buff = new byte[1024];
            StringBuilder pem = new StringBuilder();
            int len;
            while ((len = in.read(buff)) != -1) {
                pem.append(new String(buff, 0, len));
            }
            return readCertificateFromPem(pem.toString());
        } catch (Exception e) {
            throw e;
        }
    }

    /**
     * Read a certificate from pem text.
     *
     * @param pemEncoding pem text
     * @return Certificate
     */
    public static X509Certificate readCertificateFromPem(String pemEncoding) throws Exception {
        PEMParser parser = new PEMParser(new StringReader(pemEncoding));
        X509CertificateHolder certHolder = (X509CertificateHolder) parser.readObject();
        Assert.notNull(certHolder, "Illegal pem, could not parse to X509 certification.");
        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }

}
