import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;

public class RSACrypto extends Crypto {
  @Override public KeyPair generateKeyPair() throws GeneralSecurityException {
    KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
    return keyGenerator.generateKeyPair();
  }

  @Override public ContentSigner getContentSigner(PrivateKey privateKey) throws OperatorCreationException {
    return new JcaContentSignerBuilder("SHA256withRSA").build(privateKey);
  }
}
