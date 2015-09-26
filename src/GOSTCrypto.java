import org.bouncycastle.jce.ECGOST3410NamedCurveTable;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;

public class GOSTCrypto extends Crypto {
  public KeyPair generateKeyPair() throws GeneralSecurityException {
    KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("ECGOST3410"); // this is called GOST3410EL in CryptoPro JCP
    keyGenerator.initialize(ECGOST3410NamedCurveTable.getParameterSpec("GostR3410-2001-CryptoPro-A"));
    return keyGenerator.generateKeyPair();
  }

  @Override public ContentSigner getContentSigner(PrivateKey privateKey) throws OperatorCreationException {
    return new JcaContentSignerBuilder("GOST3411withECGOST3410").build(privateKey);
  }
}
