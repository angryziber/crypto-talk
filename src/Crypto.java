import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;

public abstract class Crypto {
  String dnSuffix = "OU=DevClub, O=Codeborne, C=EE";
  JcaX509CertificateConverter jcaConverter = new JcaX509CertificateConverter();

  public abstract KeyPair generateKeyPair() throws GeneralSecurityException;

  public abstract ContentSigner getContentSigner(PrivateKey privateKey) throws OperatorCreationException;

  protected X509Certificate issueSelfSignedCert(KeyPair keyPair, String cn, LocalDate expiresAt) throws GeneralSecurityException, IOException, OperatorCreationException {
    return issueCert(keyPair.getPublic(), keyPair, cn, BigInteger.ONE, expiresAt);
  }

  protected X509Certificate issueCert(PublicKey subject, KeyPair issuer, String cn, BigInteger serial, LocalDate expiresAt) throws GeneralSecurityException, IOException, OperatorCreationException {
    String subjectDn = "CN=" + cn + ", " + dnSuffix;

    JcaX509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(new X500Principal(subjectDn),
        serial, new Date(), toDate(expiresAt), new X500Principal(subjectDn), subject);

    JcaX509ExtensionUtils x509Utils = new JcaX509ExtensionUtils();
    certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
    certGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.cRLSign | KeyUsage.digitalSignature | KeyUsage.keyCertSign));
    certGen.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(new KeyPurposeId[]{
        KeyPurposeId.id_kp_OCSPSigning, KeyPurposeId.id_kp_timeStamping, KeyPurposeId.id_kp_codeSigning}));
    certGen.addExtension(Extension.subjectKeyIdentifier, false, x509Utils.createSubjectKeyIdentifier(subject));
    certGen.addExtension(Extension.authorityKeyIdentifier, false, x509Utils.createAuthorityKeyIdentifier(issuer.getPublic()));

    X509CertificateHolder holder = certGen.build(getContentSigner(issuer.getPrivate()));
    return jcaConverter.getCertificate(holder);
  }

  private Date toDate(LocalDate date) {
    return Date.from(date.atStartOfDay().atZone(ZoneId.systemDefault()).toInstant());
  }

  public String toPEM(Object obj) throws IOException {
    StringWriter out = new StringWriter();
    try (PEMWriter pem = new PEMWriter(out)) {
      pem.writeObject(obj);
    }
    return out.toString();
  }
}
