package Project;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.json.JSONArray;
import org.json.JSONObject;

import Project.Application.Ed25519KeyPair;
import Project.Application.EncryptionResult;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import java.util.HexFormat;


public class Receiver extends Application{
	static String name = "Jamica";
	static byte[] EncprivateKey;
	static byte[] EncpublicKey;
	static Ed25519PrivateKeyParameters privateKey;
	static Ed25519PublicKeyParameters publicKey;
	private static Scanner scanner;
	static String privateKey2;
	static String publicKey2;
	static String receiverPK = "";
	static String senderPK = "";
	static String sendersignPK = "";
	static String MD;
    static String message;
    static String PEmessage;
    static String GroupPri;
    static int rID;
    static int sID;
    static int ID;
    static byte[] decryptedMessage;
    static ArrayList<String> GroupPub = new ArrayList<String>();
    
	public static void main(String[] args) throws Exception{
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		//incomemessage();
		//readmessage();
		//getgrouppub();
		while(true) {
			scanner = new Scanner(System.in);
		    System.out.println("what you want to do? press\n"
		    				 + "1 - Sign up (keygen)\n"
		    				 + "2 - Look at incoming messages ID\n"
		    				 + "3 - Read a message\n"
		    				 + "4 - Load private key to program (required when restart program)\n"
		    				 + "5 - Exit program");
		    int num5 = scanner.nextInt();  
		    if(num5==0) {
		    	break;
		    }else if(num5==1) {
		    	signup();
		    }
		    else if(num5==2) {
		    	incomemessage2();
		    }else if(num5 == 3) {
		    	readmessage2();
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
	
	static void readmessage() {
		try {
			scanner = new Scanner(System.in);
		    System.out.println("Enter message ID");
		    int m_ID = scanner.nextInt();  // Read user
			
            // Build JSON payload
            JSONObject payload = new JSONObject();
            payload.put("m_ID", m_ID);
            System.out.println(payload);
            // URL of your Flask endpoint
            URL url = new URL("https://ferrous-syntax-457506-i2.et.r.appspot.com/read");
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
            String res = jsonResponse.getString("message");
            System.out.println("Received message: " + res);
            int res2 = jsonResponse.getInt("from");
            System.out.println("From: " + res2);
            sID = res2;
            getSenderPublicKey();
            
            byte[] CT = Base64.getDecoder().decode(res);
            System.out.println("FullCT length " + CT.length);
            byte[] signature = Arrays.copyOfRange(CT, 0, 64);
            byte[] nonce = Arrays.copyOfRange(CT, 64, 76);
            byte[] ciphertext = Arrays.copyOfRange(CT, 76, CT.length);
            //System.out.println("sig: " + bytesToHex(signature));
            //System.out.println("nonce: " + bytesToHex(nonce));
            System.out.println("CT length " + ciphertext.length);
            
            String SharedSecret =  deriveSharedKey(bytesToHex(EncprivateKey), senderPK);
            byte[] sharedSecret = hexToBytes(SharedSecret);
            try {
                decryptedMessage = decrypt(sharedSecret, nonce, ciphertext);
                System.out.println("✅ Decrypted message: " + new String(decryptedMessage, StandardCharsets.UTF_8));
                System.out.println("Real Decrypted message: " + decryptVernam(new String(decryptedMessage, StandardCharsets.UTF_8), "XiaSenpaiDaisukiDesuwa"));
            } catch (Exception e) {
                System.out.println("❌ Decryption failed: " + e.getMessage());
            }
            
    
            boolean isValid = Application.verifySignature(sendersignPK, decryptedMessage, signature);
            
            if (isValid) {
                System.out.println("✅ Signature is valid.");
            } else {
                System.out.println("❌ Signature is invalid.");
            }
            
		} catch (Exception e) {
            e.printStackTrace();
        }
	}
	static void readmessage2() {
		try {
			//getgrouppub();
			
			scanner = new Scanner(System.in);
		    System.out.println("Enter message ID");
		    int m_ID = scanner.nextInt();  // Read user
		    
		    scanner = new Scanner(System.in);
		    System.out.println("Enter group name");
		    String Gname = scanner.nextLine();
		    
		    JSONObject payload = new JSONObject();
		    payload.put("name", Gname);
		    URL url = new URL("https://ferrous-syntax-457506-i2.et.r.appspot.com/getgrouppubk");
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
            
            BufferedReader in = new BufferedReader(
                new InputStreamReader(conn.getInputStream())
            );
            // Read the response
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = in.readLine()) != null) {
                response.append(line.trim());
            }
            in.close();
            GroupPub.clear();
            JSONArray jsonArray = new JSONArray(response.toString());
            for (int i = 0; i < jsonArray.length(); i++) {
                JSONObject obj = jsonArray.getJSONObject(i);
                String pk = obj.getString("PK");
                //System.out.println("Public Key " + (i + 1) + ": " + pk);
                GroupPub.add(pk);
            }
		    
		    
            // Build JSON payload
            JSONObject payload2 = new JSONObject();
            payload2.put("m_ID", m_ID);
            payload2.put("Gname", Gname);
            //System.out.println(payload);
            // URL of your Flask endpoint
            URL url2 = new URL("https://ferrous-syntax-457506-i2.et.r.appspot.com/read2");
            HttpURLConnection conn2 = (HttpURLConnection) url2.openConnection();

            // Configure connection
            conn2.setRequestMethod("POST");
            conn2.setRequestProperty("Content-Type", "application/json; utf-8");
            conn2.setRequestProperty("Accept", "application/json");
            conn2.setDoOutput(true);
            
            // Send JSON data
            try (OutputStream os = conn2.getOutputStream()) {
                byte[] input = payload2.toString().getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            // Read the response
            StringBuilder response2 = new StringBuilder();
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(conn2.getInputStream(), "utf-8"))) {
                String responseLine;
                while ((responseLine = br.readLine()) != null) {
                    response2.append(responseLine.trim());
                }
            }
            JSONObject jsonResponse2 = new JSONObject(response2.toString());
            
            /*
            try {
                File myObj = new File("storage.txt");
                Scanner myReader = new Scanner(myObj);
                
                while (myReader.hasNextLine()) {
                  String data = myReader.nextLine();
                  //System.out.println(data);
                }
                myReader.close();
              } catch (FileNotFoundException e) {
                System.out.println("An error occurred.");
                e.printStackTrace();
              }
            */
            
            String res = jsonResponse2.getString("message");
            //System.out.println("Received message: " + res);
            int res2 = jsonResponse2.getInt("from");
            String res3 = jsonResponse2.getString("filename");
            String res4 = jsonResponse2.getString("signature");
            //String res5 = jsonResponse2.getString("verify");
            System.out.println(res2);
            System.out.println(res4);
            //System.out.println("Group signature verification: " + res5);
            //System.out.println("From: " + res2);
		
            URL downloadUrl = new URL(res);
            HttpURLConnection downloadConn = (HttpURLConnection) downloadUrl.openConnection();
            InputStream inputStream = downloadConn.getInputStream();
			
            String localFilename = res3;
            Files.copy(inputStream, Paths.get(localFilename), StandardCopyOption.REPLACE_EXISTING);
            inputStream.close();
            System.out.println("✅ File downloaded: " + localFilename);
            
            byte[] fileData = Files.readAllBytes(Paths.get(localFilename));
            byte[] signature = Base64.getDecoder().decode(res4);
            
            sID = res2;
            
            getSenderPublicKey();
            long start1 = System.nanoTime();
            String SharedSecret =  deriveSharedKey(bytesToHex(EncprivateKey), senderPK);
            System.out.println("Shared secret: " +SharedSecret);
            long end1 = System.nanoTime();
    	    long duration1 = end1 - start1;
    	    
            byte[] sharedSecret = hexToBytes(SharedSecret);
    	    long duration3 =0;
            try {
            	long start3 = System.nanoTime();
            	
            	decrypt2(sharedSecret, localFilename);
                //decryptedMessage = decrypt(sharedSecret, nonce, );
                long end3 = System.nanoTime();
        	    duration3 = end3 - start3;
                //System.out.println("✅ First decrypted message: " + new String(decryptedMessage, StandardCharsets.UTF_8));
                //System.out.println("✅ Real decrypted message: " + decryptVernam(new String(decryptedMessage, StandardCharsets.UTF_8), "XiaSenpaiDaisukiDesuwa"));
            } catch (Exception e) {
                System.out.println("❌ Decryption failed: " + e.getMessage());
            }
            
            String localFilename2 = localFilename.replace(".enc", "");
            byte[] fileData2 = Files.readAllBytes(Paths.get(localFilename2));
            PEmessage = vernamCipher(bytesToHex(fileData2),"XiaSenpaiDaisukiDesuwa");
            
            JSONObject payload3 = new JSONObject();
		    payload3.put("Gname", Gname);
		    payload3.put("PEmessage", PEmessage);
		    payload3.put("signature", bytesToHex(signature));
            URL url3 = new URL("https://ferrous-syntax-457506-i2.et.r.appspot.com/messageinput2");
            HttpURLConnection conn3 = (HttpURLConnection) url3.openConnection();

            // Configure connection
            conn3.setRequestMethod("POST");
            conn3.setRequestProperty("Content-Type", "application/json; utf-8");
            conn3.setRequestProperty("Accept", "application/json");
            conn3.setDoOutput(true);
         // Send JSON data
            try (OutputStream os = conn3.getOutputStream()) {
                byte[] input = payload3.toString().getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            // Read the response
            StringBuilder response3 = new StringBuilder();
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(conn3.getInputStream(), "utf-8"))) {
                String responseLine;
                while ((responseLine = br.readLine()) != null) {
                    response3.append(responseLine.trim());
                }
            }
            JSONObject jsonResponse3 = new JSONObject(response3.toString());
            System.out.println("Signature verification on cloud : "+jsonResponse3.getString("verify")+"\n");
            //System.out.println("PEmessage " +PEmessage);
    	    
    	    
/*
            boolean isValid = false;
    	    for (int i = 0; i < GroupPub.size(); i++) {
            	isValid = Application.verifySignature(GroupPub.get(i), PEmessage.getBytes(), signature);
            	if (isValid) {
                    System.out.println("✅ Group signature is valid.");
                    isValid = true;
                    break;
                } else {
                    System.out.println("❌ Group signature is invalid.");
                }
            }
            */
            
            //System.out.println("sig: " + bytesToHex(signature));
            //System.out.println("nonce: " + bytesToHex(nonce));
            //System.out.println("CT length " + ciphertext.length);
            
            /*
            long start4 = System.nanoTime();
            
            long end4 = System.nanoTime();
    	    long duration4= end4 - start4;
            if (isValid) {
                System.out.println("Conclusion: ✅ Group signature is valid.");
            } else {
                System.out.println("Conclusion: ❌ Group signature is invalid.");
            }
            isValid = false;
            */
            
            /*
            try (FileWriter writer = new FileWriter("storage2.txt", false)) {
                writer.write("Pre-Hashing duration:"+duration1/ 1_000_000.0 + " ms\n"+
                			"AES-Decryption duration:"+duration3/ 1_000_000.0 + " ms\n"+
                			"Digital signature verifying duration:"+duration4/ 1_000_000.0 + " ms\n");
                System.out.println("File overwritten successfully.");
            } catch (IOException e) {
                System.err.println("Error writing to file: " + e.getMessage());
            }
            */
		} catch (Exception e) {
            e.printStackTrace();
        }
	}
	
	static void incomemessage() {
		try {
            // Build JSON payload
            JSONObject payload = new JSONObject();
            payload.put("ID", ID);
           // System.out.println(payload);
            // URL of your Flask endpoint
            URL url = new URL("https://ferrous-syntax-457506-i2.et.r.appspot.com/view");
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

            JSONArray jsonArray = new JSONArray(response.toString());
            for (int i = 0; i < jsonArray.length(); i++) {
                JSONObject obj = jsonArray.getJSONObject(i);
                int m_ID = obj.getInt("m_ID");
                System.out.println("Message ID: " + m_ID);
            }
            
		} catch (Exception e) {
            e.printStackTrace();
        }
	}
	
	static void incomemessage2() {
		try {
            // Build JSON payload
            JSONObject payload = new JSONObject();
            payload.put("ID", ID);
            System.out.println(payload);
            // URL of your Flask endpoint
            URL url = new URL("https://ferrous-syntax-457506-i2.et.r.appspot.com/view2");
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

            JSONArray jsonArray = new JSONArray(response.toString());
            for (int i = 0; i < jsonArray.length(); i++) {
                JSONObject obj = jsonArray.getJSONObject(i);
                int m_ID = obj.getInt("m_ID");
                System.out.println("Message ID: " + m_ID);
            }
            
		} catch (Exception e) {
            e.printStackTrace();
        }
	}
	
	static void getReceiverPublicKey() {
		try {
            // Build JSON payload
            JSONObject payload = new JSONObject();
            payload.put("ReceiverID", rID);
           // System.out.println(payload);
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
            //System.out.println("Received response: " + receiverPK);
        } catch (Exception e) {
            e.printStackTrace();
        }
	}
	
	static void getSenderPublicKey() {
		try {
            // Build JSON payload
            JSONObject payload = new JSONObject();
            payload.put("ReceiverID", sID);
            //System.out.println(payload);
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
            senderPK = res;
            //System.out.println("Received response: " + senderPK);
        } catch (Exception e) {
            e.printStackTrace();
        }
	}
	
	static void getSenderPublicSignKey() {
		try {
            // Build JSON payload
            JSONObject payload = new JSONObject();
            payload.put("ReceiverID", sID);
            //System.out.println(payload);
            // URL of your Flask endpoint
            URL url = new URL("https://ferrous-syntax-457506-i2.et.r.appspot.com/getsignpk");
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
            sendersignPK = res;
            //System.out.println("Received response: " + sendersignPK);
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
                System.out.println("✅ Decrypted message: " + new String(decryptedMessage, StandardCharsets.UTF_8));
                System.out.println("Real Decrypted message: " + decryptVernam(new String(decryptedMessage, StandardCharsets.UTF_8), "XiaSenpaiDaisukiDesuwa"));
                GroupPri = bytesToHex(decryptedMessage);
                System.out.println(GroupPri);
            } catch (Exception e) {
                System.out.println("❌ Decryption failed: " + e.getMessage());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
	}
	
	static void getgrouppub() {
		try {
            // Build JSON payload
            JSONObject payload = new JSONObject();
            scanner = new Scanner(System.in);
		    System.out.println("Enter group name");
		    String name = scanner.nextLine();
		    payload.put("name", name);
            // URL of your Flask endpoint
            URL url = new URL("https://ferrous-syntax-457506-i2.et.r.appspot.com/getgrouppubk");
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
            
            BufferedReader in = new BufferedReader(
                new InputStreamReader(conn.getInputStream())
            );
            // Read the response
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = in.readLine()) != null) {
                response.append(line.trim());
            }
            in.close();
            GroupPub.clear();
            JSONArray jsonArray = new JSONArray(response.toString());
            for (int i = 0; i < jsonArray.length(); i++) {
                JSONObject obj = jsonArray.getJSONObject(i);
                String pk = obj.getString("PK");
                //System.out.println("Public Key " + (i + 1) + ": " + pk);
                GroupPub.add(pk);
            }
            //System.out.println(GroupPub);

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
	    
	    String SharedSecret =  deriveSharedKey(privateKey2, receiverPK);
	    byte[] sharedSecret = new byte[32];
        new SecureRandom().nextBytes(hexToBytes(SharedSecret)); // Replace with your real shared secret

        EncryptionResult result = encrypt(sharedSecret, message);
        System.out.println("CT: " + result.ciphertext);
        
		try {
			byte[] signature = Application.signMessage(privateKey2, PEmessage.getBytes());
			
			//byte[] CT = signature + PEmessage.getBytes();
			byte[] combined = new byte[signature.length + PEmessage.getBytes().length];
			System.out.println(signature.length);
			System.arraycopy(signature, 0, combined, 0, signature.length);
		    System.arraycopy(PEmessage.getBytes(), 0, combined, signature.length, PEmessage.getBytes().length);
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
