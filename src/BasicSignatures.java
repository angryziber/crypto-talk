import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;

import static java.time.LocalDate.now;

public class BasicSignatures {
  public static void main(String[] args) throws GeneralSecurityException, IOException, OperatorCreationException {
    Security.addProvider(new BouncyCastleProvider());

    Crypto crypto = new GOSTCrypto();
    KeyPair root = crypto.generateKeyPair();
    X509Certificate rootCert = crypto.issueSelfSignedCert(root, "Root", now().plusYears(5));

    KeyPair subject = crypto.generateKeyPair();
    X509Certificate subjectCert = crypto.issueCert(subject.getPublic(), root, "Anton Keks", BigInteger.ONE, now().plusYears(1));
    System.out.println(subjectCert);
  }
}
