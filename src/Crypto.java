import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;

import static org.bouncycastle.asn1.x509.Extension.*;
import static org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_OCSPSigning;
import static org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_codeSigning;
import static org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_timeStamping;
import static org.bouncycastle.asn1.x509.KeyUsage.cRLSign;
import static org.bouncycastle.asn1.x509.KeyUsage.digitalSignature;
import static org.bouncycastle.asn1.x509.KeyUsage.keyCertSign;

public abstract class Crypto {
  String dnSuffix = "OU=Joker, O=Codeborne, C=EE";
  JcaX509CertificateConverter jcaConverter = new JcaX509CertificateConverter();

  protected abstract KeyPair generateKeyPair() throws GeneralSecurityException;

  protected abstract ContentSigner getContentSigner(PrivateKey privateKey) throws OperatorCreationException;

  protected X509Certificate issueSelfSignedCert(KeyPair keyPair, String cn, LocalDate expiresAt) throws GeneralSecurityException, IOException, OperatorCreationException {
    return issueCert(keyPair, null, keyPair.getPublic(), cn, BigInteger.ONE, expiresAt);
  }

  protected X509Certificate issueCert(KeyPair issuer, X509Certificate issuerCert, PublicKey subject, String cn, BigInteger serial, LocalDate expiresAt) throws GeneralSecurityException, IOException, OperatorCreationException {
    String subjectDn = "CN=" + cn + ", " + dnSuffix;
    String issuerDn = issuerCert != null ? issuerCert.getSubjectDN().toString() : subjectDn;

    JcaX509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(new X500Principal(issuerDn),
        serial, new Date(), toDate(expiresAt), new X500Principal(subjectDn), subject);

    JcaX509ExtensionUtils x509Utils = new JcaX509ExtensionUtils();
    certGen.addExtension(basicConstraints, true, new BasicConstraints(true));
    certGen.addExtension(keyUsage, true, new KeyUsage(cRLSign | digitalSignature | keyCertSign));
    certGen.addExtension(extendedKeyUsage, true, new ExtendedKeyUsage(new KeyPurposeId[]{id_kp_OCSPSigning, id_kp_timeStamping, id_kp_codeSigning}));
    certGen.addExtension(subjectKeyIdentifier, false, x509Utils.createSubjectKeyIdentifier(subject));
    certGen.addExtension(authorityKeyIdentifier, false, x509Utils.createAuthorityKeyIdentifier(issuer.getPublic()));

    X509CertificateHolder holder = certGen.build(getContentSigner(issuer.getPrivate()));
    return jcaConverter.getCertificate(holder);
  }

  public byte[] sign(String data, PrivateKey key) throws OperatorCreationException, IOException {
    ContentSigner signer = getContentSigner(key);
    signer.getOutputStream().write(data.getBytes());
    return signer.getSignature();
  }

  public CMSSignedData signCades(String data, PrivateKey privateKey, X509Certificate certificate) throws CertificateEncodingException, OperatorCreationException, CMSException {
    CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
    gen.addCertificate(new JcaX509CertificateHolder(certificate));
    gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build())
        .build(getContentSigner(privateKey), certificate));
    return gen.generate(new CMSProcessableByteArray(data.getBytes()), true);
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
