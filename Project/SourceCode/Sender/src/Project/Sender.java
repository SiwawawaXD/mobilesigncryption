package Project;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.json.JSONArray;
import org.json.JSONObject;

import Project.Application.Ed25519KeyPair;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;
import java.util.HexFormat;
import java.util.Base64;


public class Sender extends Application{
	static String name = "Jack";
	static byte[] EncprivateKey;
	static byte[] EncpublicKey;
	static String privateKey2 ;
	static String publicKey2;
	static Ed25519PrivateKeyParameters privateKey;
	static Ed25519PublicKeyParameters publicKey;
	private static Scanner scanner;
	static String receiverPK;
	static String GroupPri;
	static String MD;
    static String message;
    static String PEmessage;
    static int rID;
    static int ID;
    static byte[] decryptedMessage;
	
	public static void main(String[] args) throws Exception{
		//Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		/*
		 * 
		Ed25519KeyPair keyPair = Application.generateEd25519Keypair();
        privateKey = (Ed25519PrivateKeyParameters) keyPair.getPrivate();
        publicKey = (Ed25519PublicKeyParameters) keyPair.getPublic();
        
        //System.out.println(privateKey);
        // 2. Create a test message
        String message = "Hello secure world!";
        byte[] messageBytes = message.getBytes();
        */
        /*
        // 3. Sign the message
        byte[] signature = Application.signMessage(privateKey, messageBytes);

        // 4. Verify the signature
        boolean isValid = Application.verifySignature(publicKey, messageBytes, signature);

        // 5. Print result
        if (isValid) {
            System.out.println("✅ Signature is valid.");
        } else {
            System.out.println("❌ Signature is invalid.");
        }
        String PEmessage = vernamCipher("Hello secure world!","XiaSenpaiDaisukiDesuwa");
        System.out.println(PEmessage);
        
        
        try {
            // Build JSON payload
            JSONObject payload = new JSONObject();
            payload.put("PEmessage", PEmessage);

            // URL of your Flask endpoint
            URL url = new URL("https://ferrous-syntax-457506-i2.et.r.appspot.com/prehash");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();

            // Configure connection
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json; utf-8");
            conn.setRequestProperty("Accept", "application/json");
            conn.setDoOutput(true);

            // Send JSON data
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = payload.toString().getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            // Read the response
            StringBuilder response = new StringBuilder();
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), "utf-8"))) {
                String responseLine;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }
            }

            // Parse JSON response
            JSONObject jsonResponse = new JSONObject(response.toString());
            String MD = jsonResponse.getString("MD");

            System.out.println("Received MD: " + MD);

        } catch (Exception e) {
            e.printStackTrace();
        }
        */
        /*
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
        kpg.initialize(new NamedParameterSpec("X25519"));
        KeyPair kp = kpg.generateKeyPair();
        
        XECPrivateKey EncfullprivateKey = (XECPrivateKey) kp.getPrivate();
        XECPublicKey EncfullpublicKey = (XECPublicKey) kp.getPublic();
        
        byte[] encoded1 = EncfullpublicKey.getEncoded();
        EncpublicKey = Arrays.copyOfRange(encoded1, encoded1.length - 32, encoded1.length);
        byte[] encoded2 = EncfullprivateKey.getEncoded();
        EncprivateKey = Arrays.copyOfRange(encoded2, encoded2.length - 32, encoded2.length);
        
        System.out.println("Private Key: " + bytesToHex(privateKey.getEncoded()));
        System.out.println("Public Key: " + bytesToHex(publicKey.getEncoded()));
        System.out.println("EncPrivate Key: " + HexFormat.of().formatHex(EncprivateKey));
        System.out.println("EncPublic Key: " +HexFormat.of().formatHex(EncpublicKey));
        */
        /*
        try (FileWriter writer = new FileWriter("storage.txt", false)) {
            // 'false' means overwrite mode (not append)
            writer.write('8');
            System.out.println("File overwritten successfully.");
        } catch (IOException e) {
            System.err.println("Error writing to file: " + e.getMessage());
        }
        */
        //String filename = "storage"; // Make sure this file exists in the same folder
        /*
        try {
            File myObj = new File("storage.txt");
            Scanner myReader = new Scanner(myObj);
            
            while (myReader.hasNextLine()) {
              String data = myReader.nextLine();
              System.out.println(data);
            }
            myReader.close();
          } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
          }
        */
        //signup();
		//8576caedbeed3794e7ad2b2d
		/*
		byte[] CTwithsignature = Base64.getDecoder().decode("aau7nBpcyUCbEdLNgmb58CmRbLkQwNnVXJmnwFpPWmrC50/MYwVKGNiwi4nvduAFSGjNU53khGne0aizCppsBnMSQ5kcEGubv75ZWRBXJUTlzLV/zFSEli4HJlFPFw=="); 
		System.out.println(CTwithsignature.length);
		byte[] ciphertext = Arrays.copyOfRange(CTwithsignature, 64, CTwithsignature.length);
		System.out.println(bytesToHex(ciphertext));
		String SharedSecret =  deriveSharedKey(bytesToHex(EncprivateKey), receiverPK);
		byte[] sharedSecret = hexToBytes(SharedSecret);
        
        
        try {
            decryptedMessage = decrypt(sharedSecret, hexToBytes("4b819382715b662516a870e1"), ciphertext);
            System.out.println("✅ Decrypted message: " + new String(decryptedMessage, StandardCharsets.UTF_8));
        } catch (Exception e) {
            System.out.println("❌ Decryption failed: " + e.getMessage());
        }
        */
        //SendMessage1();
		while(true) {
			scanner = new Scanner(System.in);
		    System.out.println("what do you want to do? press\n"
		    				  + "1 - Sign up (keygen)\n"
		    				  + "2 - Create group signature\n"
		    				  + "3 - Send a message\n"
		    				  + "4 - Load private key to program (required when restart program)\n"
		    				  + "5 - Exit program");
		    int num5 = scanner.nextInt(); 
			if(num5 == 0) {
				break;
			}else if(num5 == 2) {
				creategroup();
			}else if(num5 == 3) {
				getgrouppri();
				SendMessage2();
			}else if(num5 == 1) {
				signup();
			}else if(num5 == 4) {
				try {
		            File myObj = new File("id.txt");
		            Scanner myReader = new Scanner(myObj);
		            
		            while (myReader.hasNextLine()) {
		            	String id = myReader.nextLine();
		                ID = Integer.parseInt(id);
		                System.out.println("ID: "+id);
		            }
		            myReader.close();
		            
		            File myObj2 = new File("EncPri.txt");
		            Scanner myReader2 = new Scanner(myObj2);
		            
		            while (myReader2.hasNextLine()) {
		                String pri1 = myReader2.nextLine();
		                EncprivateKey = hexToBytes(pri1);
		                System.out.println("Enc Private: "+pri1);
		            }
		            myReader2.close();
		            
		            File myObj3 = new File("SignPri.txt");
		            Scanner myReader3 = new Scanner(myObj3);
		            
		            while (myReader3.hasNextLine()) {
		                String pri2 = myReader3.nextLine();
		                privateKey2 = pri2;
		                System.out.println("Sign Private: "+pri2);
		            }
		            myReader3.close();
		            
		          } catch (FileNotFoundException e) {
		            System.out.println("An error occurred.");
		            e.printStackTrace();
		          }
			}
			else if (num5==5) {
		    	System.exit(0);
		    }
		}
	}
	static void getReceiverPublicKey() {
		try {
            // Build JSON payload
            JSONObject payload = new JSONObject();
            payload.put("ReceiverID", rID);
            System.out.println(payload);
            // URL of your Flask endpoint
            URL url = new URL("https://ferrous-syntax-457506-i2.et.r.appspot.com/getpk");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();

            // Configure connection
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json; utf-8");
            conn.setRequestProperty("Accept", "application/json");
            conn.setDoOutput(true);

            // Send JSON data
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = payload.toString().getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            // Read the response
            StringBuilder response = new StringBuilder();
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), "utf-8"))) {
                String responseLine;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }
            }

            JSONObject jsonResponse = new JSONObject(response.toString());
            String res = jsonResponse.getString("pk");
            receiverPK = res;
            System.out.println("Received response: " + receiverPK);
        } catch (Exception e) {
            e.printStackTrace();
        }
	}
	
	static void getgrouppri() {
		try {
            // Build JSON payload
            JSONObject payload = new JSONObject();
            payload.put("myID", ID);
            //System.out.println(payload);
            scanner = new Scanner(System.in);
            
		    System.out.println("Enter group name");
		    String name = scanner.nextLine();
		    payload.put("name", name);
            // URL of your Flask endpoint
            URL url = new URL("https://ferrous-syntax-457506-i2.et.r.appspot.com/getgroupprik");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();

            // Configure connection
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json; utf-8");
            conn.setRequestProperty("Accept", "application/json");
            conn.setDoOutput(true);

            // Send JSON data
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = payload.toString().getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            // Read the response
            StringBuilder response = new StringBuilder();
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), "utf-8"))) {
                String responseLine;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }
            }

            JSONObject jsonResponse = new JSONObject(response.toString());
            String res = jsonResponse.getString("prik");
            GroupPri = res;
            //System.out.println("Received response: " + GroupPri);
            

            byte[] priv2 = hexToBytes(res);
            System.out.println("Fullpriv length " + priv2.length);
            byte[] nonce = Arrays.copyOfRange(priv2, 0, 12);
            byte[] priv3 = Arrays.copyOfRange(priv2, 12, priv2.length);
            //System.out.println("sig: " + bytesToHex(signature));
            //System.out.println("nonce: " + bytesToHex(nonce));
            System.out.println("priv length " + priv3.length);
            
            String SharedSecret =  deriveSharedKey(bytesToHex(EncprivateKey), "20873a41532b8cb38c828ccdf3d5f50fe1a79ebeaaf7ae423f3609d674edd776");
            byte[] sharedSecret = hexToBytes(SharedSecret);
            try {
                decryptedMessage = decrypt(sharedSecret, nonce, priv3);
                //System.out.println("✅ Decrypted message: " + new String(decryptedMessage, StandardCharsets.UTF_8));
                //System.out.println("Real Decrypted message: " + decryptVernam(new String(decryptedMessage, StandardCharsets.UTF_8), "XiaSenpaiDaisukiDesuwa"));
                GroupPri = bytesToHex(decryptedMessage);
                System.out.println("Group Private Key received");
            } catch (Exception e) {
                //System.out.println("❌ Decryption failed: " + e.getMessage());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
	}
	
	public static void signup() throws Exception {
		Ed25519KeyPair keyPair = Application.generateEd25519Keypair();
        privateKey = (Ed25519PrivateKeyParameters) keyPair.getPrivate();
        publicKey = (Ed25519PublicKeyParameters) keyPair.getPublic();
        
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
        kpg.initialize(new NamedParameterSpec("X25519"));
        KeyPair kp = kpg.generateKeyPair();
        
        XECPrivateKey EncfullprivateKey = (XECPrivateKey) kp.getPrivate();
        XECPublicKey EncfullpublicKey = (XECPublicKey) kp.getPublic();
        
        byte[] encoded1 = EncfullpublicKey.getEncoded();
        EncpublicKey = Arrays.copyOfRange(encoded1, encoded1.length - 32, encoded1.length);
        byte[] encoded2 = EncfullprivateKey.getEncoded();
        EncprivateKey = Arrays.copyOfRange(encoded2, encoded2.length - 32, encoded2.length);
        
        
		try {
            // Build JSON payload
            JSONObject payload = new JSONObject();
            payload.put("Name", name);
            payload.put("signPK", bytesToHex(publicKey.getEncoded()));
            payload.put("encPK", HexFormat.of().formatHex(EncpublicKey));
            System.out.println("sign private key: "+ bytesToHex(privateKey.getEncoded()));
            System.out.println("sign public key: "+ bytesToHex(publicKey.getEncoded()));
            
            System.out.println("encrypt private key: "+ HexFormat.of().formatHex(EncprivateKey));
            System.out.println("encrypt public key: "+ HexFormat.of().formatHex(EncpublicKey));
            
            //System.out.println(payload);
            // URL of your Flask endpoint
            URL url = new URL("https://ferrous-syntax-457506-i2.et.r.appspot.com/signup");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();

            // Configure connection
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json; utf-8");
            conn.setRequestProperty("Accept", "application/json");
            conn.setDoOutput(true);

            // Send JSON data
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = payload.toString().getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            // Read the response
            StringBuilder response = new StringBuilder();
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), "utf-8"))) {
                String responseLine;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }
            }

            JSONObject jsonResponse = new JSONObject(response.toString());
            int res = jsonResponse.getInt("userID");
            ID = res;
            System.out.println("Received response: " + res);
            //write userID
            try (FileWriter writer = new FileWriter("storage.txt", false)) {
                writer.write(res+"\n"+ bytesToHex(privateKey.getEncoded()) + "\n"+ HexFormat.of().formatHex(EncprivateKey));
                //System.out.println("File overwritten successfully.");
            } catch (IOException e) {
                System.err.println("Error writing to file: " + e.getMessage());
            }
            
            

            try (FileWriter writer = new FileWriter("id.txt", false)) {
                writer.write(""+res);
                //System.out.println("File overwritten successfully.");
            } catch (IOException e) {
                System.err.println("Error writing to file: " + e.getMessage());
            }
            
            try (FileWriter writer = new FileWriter("SignPri.txt", false)) {
                writer.write(bytesToHex(privateKey.getEncoded()));
                //System.out.println("File overwritten successfully.");
            } catch (IOException e) {
                System.err.println("Error writing to file: " + e.getMessage());
            }
            
            try (FileWriter writer = new FileWriter("EncPri.txt", false)) {
                writer.write(HexFormat.of().formatHex(EncprivateKey));
                //System.out.println("File overwritten successfully.");
            } catch (IOException e) {
                System.err.println("Error writing to file: " + e.getMessage());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
	}
	
	
	public static void SendMessage1() throws Exception{
		scanner = new Scanner(System.in);
	    System.out.println("Enter receiver ID");
	    rID = scanner.nextInt();  // Read user
		
		scanner = new Scanner(System.in);
	    System.out.println("Enter message");
	    message = scanner.nextLine();  // Read user input
	    PEmessage = vernamCipher(message,"XiaSenpaiDaisukiDesuwa");
	    getReceiverPublicKey();
	    prehash();
	    
	    String SharedSecret =  deriveSharedKey(bytesToHex(EncprivateKey), receiverPK);
	    byte[] sharedSecret = hexToBytes(SharedSecret);
	    System.out.println("CT: " + bytesToHex(sharedSecret));
	    
        EncryptionResult result = encrypt(sharedSecret, PEmessage);
        System.out.println("CT: " + bytesToHex(result.ciphertext));
        System.out.println("nonce: " + bytesToHex(result.nonce));
        
        try {
            decryptedMessage = decrypt(sharedSecret, result.nonce, result.ciphertext);
            System.out.println("✅ Decrypted message: " + new String(decryptedMessage, StandardCharsets.UTF_8));
        } catch (Exception e) {
            System.out.println("❌ Decryption failed: " + e.getMessage());
        }
        
		try {
			byte[] signature = Application.signMessage(privateKey2, PEmessage.getBytes());
			
		    byte[] nonce = result.nonce;    // Nonce from AES-GCM
		    byte[] ciphertext = result.ciphertext;

		    int totalLength = signature.length + nonce.length + ciphertext.length;
		    byte[] combined = new byte[totalLength];
		    // Copy signature
		    System.arraycopy(signature, 0, combined, 0, signature.length);
		    // Copy nonce (after signature)
		    System.arraycopy(nonce, 0, combined, signature.length, nonce.length);
		    // Copy ciphertext (after signature + nonce)
		    System.arraycopy(ciphertext, 0, combined, signature.length + nonce.length, ciphertext.length);
		    
            // Build JSON payload 
            JSONObject payload = new JSONObject();
            payload.put("Output", Base64.getEncoder().encodeToString(combined));
            payload.put("rID", rID);
            payload.put("sID", ID);
            System.out.println(combined.length);
            //deriveSharedKey();
            System.out.println(payload);
            // URL of your Flask endpoint
            
            URL url = new URL("https://ferrous-syntax-457506-i2.et.r.appspot.com/sendmessage");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();

            // Configure connection
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json; utf-8");
            conn.setRequestProperty("Accept", "application/json");
            conn.setDoOutput(true);

            // Send JSON data
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = payload.toString().getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            // Read the response
            StringBuilder response = new StringBuilder();
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), "utf-8"))) {
                String responseLine;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }
            }

            JSONObject jsonResponse = new JSONObject(response.toString());
            String res = jsonResponse.getString("result");

            System.out.println("Received response: " + res);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
	}
	
	
	public static void SendMessage2() throws Exception{
		scanner = new Scanner(System.in);
	    System.out.println("Enter receiver ID");
	    rID = scanner.nextInt();  // Read user
		
		scanner = new Scanner(System.in);
	    System.out.println("Enter file name: ");
	    message = scanner.nextLine();  // Read user input
	    //25
	    byte[] fileData = Files.readAllBytes(Paths.get(message));
	    PEmessage = vernamCipher(bytesToHex(fileData),"XiaSenpaiDaisukiDesuwa");
	    //System.out.println();
	    
	    //PEmessage = vernamCipher(message,"XiaSenpaiDaisukiDesuwa");
	    getgrouppri();
	    getReceiverPublicKey();
	    long start1 = System.nanoTime();
	    prehash();
	    long end1 = System.nanoTime();
	    long duration1 = end1 - start1;
	    //long totalDuration = 0;

        // Operation 1
        //long start1 = System.nanoTime();
        //long end1 = System.nanoTime();
        //long duration1 = end1 - start1;
        //long start1 = System.nanoTime();
	    long start2 = System.nanoTime();
	    String SharedSecret =  deriveSharedKey(bytesToHex(EncprivateKey), receiverPK);
	    long end2 = System.nanoTime();
	    long duration2 = end2 - start2;
	    //System.out.println("Diffie-Hellman key-exchange duration:"+duration2/ 1_000_000.0 + " ms");
	    
	    byte[] sharedSecret = hexToBytes(SharedSecret);
	    System.out.println("Shared secret: " + bytesToHex(sharedSecret));
	    long start5 = System.nanoTime();
	    for (int i = 0; i < 1000; i++) {
	    	
	    }
	   
        EncryptionResult result = encrypt(sharedSecret, message);
        long end5 = System.nanoTime();
        long duration5 = end5 - start5;
        //System.out.println("CT: " + bytesToHex(result.ciphertext));
        //System.out.println("nonce: " + bytesToHex(result.nonce));
        long duration3 =0;
        /*
        try {
        	long start3 = System.nanoTime();
            decryptedMessage = decrypt(sharedSecret, result.nonce, result.ciphertext);
            long end3 = System.nanoTime();
            duration3 = end3 - start3;
            System.out.println("AES-Encryption duration:"+duration3/ 1_000_000.0 + " ms");
            System.out.println("✅ Decrypted message: " + new String(decryptedMessage, StandardCharsets.UTF_8));
        } catch (Exception e) {
            System.out.println("❌ Decryption failed: " + e.getMessage());
        }*/
        
		try {
			long start4 = System.nanoTime();
			byte[] signature = Application.signMessage(GroupPri, PEmessage.getBytes());
			long end4 = System.nanoTime();
			long duration4 = end4 - start4;
			//System.out.println("Digital signature signing duration:"+duration4/ 1_000_000.0 + " ms");
		    byte[] nonce = result.nonce;    // Nonce from AES-GCM
		    System.out.println("nonce: "+bytesToHex(nonce));
		    System.out.println("signature: "+bytesToHex(signature));
		    //byte[] ciphertext = result.ciphertext;

		    // Copy signature
		    // Copy nonce (after signature)
		    // Copy ciphertext (after signature + nonce)
		    
            // Build JSON payload 
		    
		   
            //deriveSharedKey();
            //System.out.println(payload);
            // URL of your Flask endpoint
		    String boundary = "----WebKitFormBoundary" + System.currentTimeMillis();
		    String LINE_FEED = "\r\n";
		    
		    
            URL url = new URL("https://ferrous-syntax-457506-i2.et.r.appspot.com/sendmessage2");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();


            // Set up connection properties BEFORE using getOutputStream()
            conn.setDoOutput(true);  // ✅ Required for sending a POST body
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
            conn.setRequestProperty("Accept-Charset", "UTF-8");
            File file = new File(message+".enc");
            
            if (!file.exists()) {
                System.out.println("❌ File does not exist: " + file.getAbsolutePath());
                return;
            }
            
            try (
                    OutputStream output = conn.getOutputStream();
                    PrintWriter writer = new PrintWriter(new OutputStreamWriter(output, "UTF-8"), true)
                ) {
                    // 1. Send metadata as a JSON field
            		String signatureEncoded = Base64.getEncoder().encodeToString(signature);
                    String metadataJson = String.format("{\"sID\":\"%s\", \"rID\":\"%s\", \"signature\":\"%s\"}", ID, rID, signatureEncoded);
                    writer.append("--").append(boundary).append(LINE_FEED);
                    writer.append("Content-Disposition: form-data; name=\"metadata\"").append(LINE_FEED);
                    writer.append("Content-Type: application/json; charset=UTF-8").append(LINE_FEED);
                    writer.append(LINE_FEED).append(metadataJson).append(LINE_FEED);
                    writer.flush();

                    // 2. Send the actual file
                    writer.append("--").append(boundary).append(LINE_FEED);
                    writer.append("Content-Disposition: form-data; name=\"file\"; filename=\"" + file.getName() + "\"").append(LINE_FEED);
                    writer.append("Content-Type: application/octet-stream").append(LINE_FEED);
                    writer.append(LINE_FEED);
                    writer.flush();

                    try (FileInputStream inputStream = new FileInputStream(file)) {
                        byte[] buffer = new byte[4096];
                        int bytesRead;
                        while ((bytesRead = inputStream.read(buffer)) != -1) {
                            output.write(buffer, 0, bytesRead);
                        }
                        output.flush();
                    }

                    writer.append(LINE_FEED).flush();
                    output.flush(); 
                    writer.append("--").append(boundary).append("--").append(LINE_FEED).flush();
                }

	        System.out.println("Starting file upload...");
	        System.out.println("File name: " + file.getName());
	        System.out.println("File exists: " + file.exists());
	        System.out.println("File size: " + file.length() + " bytes");
	        System.out.println("Sending file: " + file.getAbsolutePath());
	        // Response
	        int responseCode = conn.getResponseCode();
	        InputStream responseStream = (responseCode >= 200 && responseCode < 300) ?
	            conn.getInputStream() : conn.getErrorStream();
	        
	        if (responseStream == null) {
	            System.out.println("❌ No response stream available.");
	            return;
	        }

	        BufferedReader in = new BufferedReader(new InputStreamReader(responseStream));
	        String inputLine;
	        StringBuilder response = new StringBuilder();
	        while ((inputLine = in.readLine()) != null)
	            response.append(inputLine);
	        in.close();

	        System.out.println("Server response: " + response.toString());

            
            /*
            boolean isValid = Application.verifySignature("b27f16ed86ca9279e2ca1105d6eaa1a1a44e55566ac2e44bc7afd1d630226a61", PEmessage.getBytes(), signature);
            
            if (isValid) {
                System.out.println("✅ Group signature is valid.");
            } else {
                System.out.println("❌ Group signature is invalid.");
            }
            */
        } catch (Exception e) {
            e.printStackTrace();
        }
	}
	
	static void prehash() {
		try {
            // Build JSON payload
            JSONObject payload = new JSONObject();
            payload.put("PEmessage", PEmessage);

            // URL of your Flask endpoint
            URL url = new URL("https://ferrous-syntax-457506-i2.et.r.appspot.com/prehash");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();

            // Configure connection
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json; utf-8");
            conn.setRequestProperty("Accept", "application/json");
            conn.setDoOutput(true);

            // Send JSON data
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = payload.toString().getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            // Read the response
            StringBuilder response = new StringBuilder();
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), "utf-8"))) {
                String responseLine;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }
            }

            // Parse JSON response
            JSONObject jsonResponse = new JSONObject(response.toString());
            MD = jsonResponse.getString("MD");

            //System.out.println("Received MD: " + MD);

        } catch (Exception e) {
            e.printStackTrace();
        }
	}
	
	static void creategroup() {
		ArrayList<Integer> userID = new ArrayList<Integer>();
		while(true) {
			scanner = new Scanner(System.in);
		    System.out.println("Enter group member ID");
		    int num = scanner.nextInt();
		    if(num ==0) {
		    	break;
		    }else {
		    	userID.add(num);
		    }
		}
		try {
			JSONArray payload = new JSONArray();
            for(int i=0;i<userID.size();i++) {
            	JSONObject jobj = new JSONObject();
            	System.out.println(userID.get(i));
            	jobj.put("userID", userID.get(i));
            	payload.put(jobj);
            }
            JSONObject jobj = new JSONObject();
            System.out.println(payload);
            scanner = new Scanner(System.in);
		    System.out.println("Enter group name");
		    String name = scanner.nextLine();
		    jobj.put("Gname", name);
		    payload.put(jobj);
		    System.out.println(payload);
            // URL of your Flask endpoint
            
            URL url = new URL("https://ferrous-syntax-457506-i2.et.r.appspot.com/creategroup");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();

            // Configure connection
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json; utf-8");
            conn.setRequestProperty("Accept", "application/json");
            conn.setDoOutput(true);

            // Send JSON data
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = payload.toString().getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            // Read the response
            StringBuilder response = new StringBuilder();
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), "utf-8"))) {
                String responseLine;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }
            }

            // Parse JSON response
            JSONObject jsonResponse = new JSONObject(response.toString());
            String res = jsonResponse.getString("res");

            System.out.println("res: " + res);

        } catch (Exception e) {
            e.printStackTrace();
        }
	}

	public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
	
	public static byte[] hexToBytes(String hex) {
	    int len = hex.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
	                            + Character.digit(hex.charAt(i+1), 16));
	    }
	    return data;
	}
}
