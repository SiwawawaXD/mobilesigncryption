package Project;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.*;
import java.util.*;

public class test {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    static class GroupManager {
        private List<KeyPair> memberKeys = new ArrayList<>();
        private List<PublicKey> publicKeys = new ArrayList<>();

        public void addMember() throws NoSuchAlgorithmException, NoSuchProviderException {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "BC");
            KeyPair kp = kpg.generateKeyPair();
            memberKeys.add(kp);
            publicKeys.add(kp.getPublic());
        }

        public KeyPair getMemberKey(int index) {
            return memberKeys.get(index);
        }

        public List<PublicKey> getGroupPublicKeys() {
            return publicKeys;
        }
    }

    public static byte[] sign(byte[] message, PrivateKey privateKey)
            throws Exception {
        Signature sig = Signature.getInstance("Ed25519", "BC");
        sig.initSign(privateKey);
        sig.update(message);
        return sig.sign();
    }

    public static boolean verify(byte[] message, byte[] signature, List<PublicKey> groupKeys)
            throws Exception {
        for (PublicKey pubKey : groupKeys) {
            Signature sig = Signature.getInstance("Ed25519", "BC");
            sig.initVerify(pubKey);
            sig.update(message);
            if (sig.verify(signature)) {
                return true; // Valid signature from a group member
            }
        }
        return false; // Not a valid group signature
    }

    public static void main(String[] args) throws Exception {
        GroupManager manager = new GroupManager();
        manager.addMember();
        manager.addMember();
        manager.addMember();

        String message = "Group signed message!";
        byte[] msgBytes = message.getBytes();

        // Member 2 signs the message
        KeyPair member = manager.getMemberKey(1);
        byte[] signature = sign(msgBytes, member.getPrivate());

        // Anyone can verify against group public keys
        boolean valid = verify(msgBytes, signature, manager.getGroupPublicKeys());
        System.out.println(manager.getGroupPublicKeys());
        System.out.println("✅ Signature valid from group? " + valid);
    }
}