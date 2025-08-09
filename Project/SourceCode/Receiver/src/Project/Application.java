package Project;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.util.Random;
import java.util.Base64;
import java.util.Arrays;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;


public class Application {


    public static class Ed25519KeyPair {
        public Ed25519PrivateKeyParameters privateKey;
        public Ed25519PublicKeyParameters publicKey;

        public Ed25519KeyPair(Ed25519PrivateKeyParameters priv, Ed25519PublicKeyParameters pub) {
            this.privateKey = priv;
            this.publicKey = pub;
        }

		public Ed25519PrivateKeyParameters getPrivate() {
			// TODO Auto-generated method stub
			return privateKey;
		}

		public Ed25519PublicKeyParameters getPublic() {
			// TODO Auto-generated method stub
			return publicKey;
		}
    }

    public static Ed25519KeyPair generateEd25519Keypair() {
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new org.bouncycastle.crypto.KeyGenerationParameters(new SecureRandom(), 256));
        AsymmetricCipherKeyPair pair = gen.generateKeyPair();
        return new Ed25519KeyPair((Ed25519PrivateKeyParameters) pair.getPrivate(), (Ed25519PublicKeyParameters) pair.getPublic());
    }

    public static byte[] signMessage(String privateKey, byte[] message) throws Exception {
    	// Create BouncyCastle private key object from raw 32-byte key
        Ed25519PrivateKeyParameters privateKey2 = new Ed25519PrivateKeyParameters(hexToBytes(privateKey), 0);

        // Sign the message
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, privateKey2);
        signer.update(message, 0, message.length);
        return signer.generateSignature();
    }

    public static boolean verifySignature(String publicKey, byte[] message, byte[] signature) throws Exception {
    	byte[] publicKeyBytes = hexToBytes(publicKey);
    	
    	KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
        PublicKey publicKey2 = keyFactory.generatePublic(new X509EncodedKeySpec(encodeEd25519PublicKey(publicKeyBytes)));

        // 6. Verify the signature
        long start1 = System.nanoTime();
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(publicKey2);
        verifier.update(message);

        long end1 = System.nanoTime();
	    long duration1 = end1 - start1;

        boolean isValid = verifier.verify(signature);
        System.out.println("✅ Signature valid? " + isValid);
        
        try (FileWriter writer = new FileWriter("storage3.txt", true)) {
            writer.write("Signature verify duration:"+duration1/ 1_000_000.0 + " ms\n");
            System.out.println("Signature verify duration:"+duration1/ 1_000_000.0 + " ms\n");
        } catch (IOException e) {
            System.err.println("Error writing to file: " + e.getMessage());
        }
        
        //System.out.println("✅ Signature valid? " + isValid);
        return isValid;
    }
    

    public static String deriveSharedKey(String privateKey1, String publicKey1) throws Exception{
    	Security.addProvider(new BouncyCastleProvider());

        // Example hex keys (replace with your own)
        String privateKeyHex = privateKey1;
        String publicKeyHex  = publicKey1;

        byte[] privateKeyBytes = hexToBytes(privateKeyHex);
        byte[] publicKeyBytes = hexToBytes(publicKeyHex);

        // Create PrivateKey object
        KeyFactory keyFactory = KeyFactory.getInstance("X25519");
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(encodePrivateKey(privateKeyBytes));
        PrivateKey privateKey = keyFactory.generatePrivate(privSpec);

        // Create PublicKey object
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(encodePublicKey(publicKeyBytes));
        PublicKey publicKey = keyFactory.generatePublic(pubSpec);

        // Derive shared secret
        long start1 = System.nanoTime();
        KeyAgreement agreement = KeyAgreement.getInstance("X25519");
        agreement.init(privateKey);
        agreement.doPhase(publicKey, true);
        byte[] sharedSecret = agreement.generateSecret();
        long end1 = System.nanoTime();
	    long duration1 = end1 - start1;
	    

        try (FileWriter writer = new FileWriter("storage3.txt", false)) {
            writer.write("key derive duration:"+duration1/ 1_000_000.0 + " ms\n");
            System.out.println("key derive duration:"+duration1/ 1_000_000.0 + " ms\n");
        } catch (IOException e) {
            System.err.println("Error writing to file: " + e.getMessage());
        }
        

        return bytesToHex(sharedSecret);
    }

    public static String deterministicRandomText(String text) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(text.getBytes("UTF-8"));
        long seed = 0;
        for (int i = 0; i < 8; i++) {
            seed = (seed << 8) | (hash[i] & 0xff);
        }
        Random random = new Random(seed);
        String characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            result.append(characters.charAt(random.nextInt(characters.length())));
        }
        return result.toString();
    }
    
    public static EncryptionResult encrypt(byte[] sharedSecretKey, String plaintext) throws Exception {
        // Derive AES key (first 16 bytes of shared secret)
    	int AES_KEY_SIZE = 16;
    	int GCM_NONCE_LENGTH = 12;
    	int GCM_TAG_LENGTH = 128;
        byte[] aesKey = new byte[16];
        System.arraycopy(sharedSecretKey, 0, aesKey, 0, AES_KEY_SIZE);
        SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");

        // Generate random nonce
        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(nonce);

        // Initialize cipher
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);

        // Encrypt
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        return new EncryptionResult(nonce, ciphertext);
    }

    // Helper class to store encryption output
    public static class EncryptionResult {
        public byte[] nonce;
        public byte[] ciphertext;

        public EncryptionResult(byte[] nonce, byte[] ciphertext) {
            this.nonce = nonce;
            this.ciphertext = ciphertext;
        }

        public String toBase64() {
            return "Nonce: " + Base64.getEncoder().encodeToString(nonce) +
                 "\nCiphertext: " + Base64.getEncoder().encodeToString(ciphertext);
        }
    }

    public static String vernamCipher(String text, String key) {
        String repeatedKey = repeatKeyToLength(key, text.length());
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            result.append((char)(text.charAt(i) ^ repeatedKey.charAt(i)));
        }
        return result.toString();
    }
    
    public static String decryptVernam(String ciphertext, String key) {
        String repeatedKey = repeatKeyToLength(key, ciphertext.length());
        StringBuilder plaintext = new StringBuilder();
        for (int i = 0; i < ciphertext.length(); i++) {
            plaintext.append((char)(ciphertext.charAt(i) ^ repeatedKey.charAt(i)));
        }
        return plaintext.toString();
    }

    public static String repeatKeyToLength(String key, int length) {
        StringBuilder sb = new StringBuilder();
        while (sb.length() < length) {
            sb.append(key);
        }
        return sb.substring(0, length);
    }
    
    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                + Character.digit(hex.charAt(i+1), 16));
        return data;
    }
    
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }
    
    private static byte[] encodePrivateKey(byte[] raw) {
        // PKCS#8 header for X25519 private key
        byte[] prefix = hexToBytes("302e020100300506032b656e04220420");
        byte[] result = new byte[prefix.length + raw.length];
        System.arraycopy(prefix, 0, result, 0, prefix.length);
        System.arraycopy(raw, 0, result, prefix.length, raw.length);
        return result;
    }
    
    private static byte[] encodePublicKey(byte[] raw) {
        // X.509 header for X25519 public key (SubjectPublicKeyInfo)
        byte[] prefix = hexToBytes("302a300506032b656e032100");
        byte[] result = new byte[prefix.length + raw.length];
        System.arraycopy(prefix, 0, result, 0, prefix.length);
        System.arraycopy(raw, 0, result, prefix.length, raw.length);
        return result;
    }
    
    private static byte[] encodeEd25519PublicKey(byte[] rawKey) {
        return Hex.decode("302a300506032b6570032100" + Hex.toHexString(rawKey));
    }
    
    public static byte[] decrypt(byte[] sharedSecretKey, byte[] nonce, byte[] ciphertext) throws Exception {
        // Derive AES key (first 16 bytes from shared secret)
    	int AES_KEY_SIZE = 16;
    	int GCM_TAG_LENGTH = 128;
        byte[] aesKey = new byte[AES_KEY_SIZE];
        System.arraycopy(sharedSecretKey, 0, aesKey, 0, AES_KEY_SIZE);
        SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");

        // Setup cipher
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, spec);

        // Decrypt
        long start1 = System.nanoTime();
        byte[] plaintextBytes = cipher.doFinal(ciphertext);
        long end1 = System.nanoTime();
	    long duration1 = end1 - start1;
        
        
        try (FileWriter writer = new FileWriter("storage3.txt", true)) {
            writer.write("AES Decrypt duration:"+duration1/ 1_000_000.0 + " ms\n");
            System.out.println("AES Decrypt duration:"+duration1/ 1_000_000.0 + " ms\n");
        } catch (IOException e) {
            System.err.println("Error writing to file: " + e.getMessage());
        }
        
        return plaintextBytes;
    }
    
    public static void decrypt2(byte[] sharedSecretKey, String inputFilePath) {
	    try {	
	    	// AES-GCM settings
	        int AES_KEY_SIZE = 16; // 128-bit
	        int GCM_TAG_LENGTH = 128; // bits
	
	        // Derive AES key
	        byte[] aesKey = new byte[AES_KEY_SIZE];
	        System.arraycopy(sharedSecretKey, 0, aesKey, 0, AES_KEY_SIZE);
	        SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
	
	        // Read ciphertext from file
	        
	        byte[] fileData = Files.readAllBytes(Paths.get(inputFilePath));
	        byte[] nonce = Arrays.copyOfRange(fileData, 0, 12);
            byte[] ciphertext = Arrays.copyOfRange(fileData, 12, fileData.length);
	        // Set up cipher
	        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
	        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
	        cipher.init(Cipher.DECRYPT_MODE, keySpec, spec);
	
	        // Decrypt
	        long start = System.nanoTime();
	        byte[] decryptedData = cipher.doFinal(ciphertext);
	        long end = System.nanoTime();
	        long duration = end - start;
	
	        // Output filename
	        String outputFile = inputFilePath.replace(".enc", "");
	        Files.write(Paths.get(outputFile), decryptedData);
	
	        // Log
	        try (FileWriter logWriter = new FileWriter("storage3.txt", true)) {
	            logWriter.write("AES Decrypt duration: " + duration / 1_000_000.0 + " ms\n");
	            System.out.println("✅ Decryption complete: " + outputFile);
	            System.out.println("AES Decrypt duration: " + duration / 1_000_000.0 + " ms");
	        }
	
	    } catch (Exception e) {
	        System.err.println("❌ Decryption failed:");
	        e.printStackTrace();
	    }
    }

}

