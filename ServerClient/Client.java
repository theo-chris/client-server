
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.math.BigInteger;
public class Client {

    //java Client host port userid

    static ArrayList<BigInteger> generatedNumbers;
    public static void main(String[] args) throws Exception{

        if(args.length != 3){
            System.err.println("Usage: java Client <host> <port> <userid>");
            System.exit(-1);
        }
        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String userId = args[2];

        generatedNumbers = new ArrayList<BigInteger>();

        Socket socket = new Socket(host,port);
        System.out.println("Connected to the server...");
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());

        out.writeUTF(userId);
        System.out.println("Sent userId: " + userId);

        SecretKey secretKey = keyAgreement(objectInputStream,objectOutputStream);


        try {
            clientAuthentication(userId, out, secretKey);

          if(!verifyServer(in, secretKey)) {
              System.err.println("Failed to verify signature.");
              System.err.println("Terminating...");
//              socket.close();
              System.exit(-1);
          }


        }catch(Exception e){
            System.err.println("Failed authentication");
            System.err.println("Disconnected from the server...");
            System.exit(-1);
        }

        decryption(in,secretKey);

    }

    //Signing the BigIntegers eb and ea - encrypting signature
    private static void clientAuthentication(String userId, DataOutputStream out,SecretKey secretKey) throws Exception{

        ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(userId +".prv"));
        PrivateKey privateKeyB = (PrivateKey) objectInputStream.readObject();

        Signature signature = Signature.getInstance("DSA");
        signature.initSign(privateKeyB);

        ByteBuffer byteBuffer = ByteBuffer.allocate(16);
        byteBuffer.putInt(generatedNumbers.get(0).intValue());
        byteBuffer.putInt(generatedNumbers.get(1).intValue());


        signature.update(byteBuffer.array());
        byte[] sign = signature.sign();

        byte[] encryptedSignature= encryptSignature(sign,secretKey);



        out.writeInt(encryptedSignature.length);
        out.write(encryptedSignature);

    }

    //verify signature sent from Server
    private static boolean verifyServer(DataInputStream in,SecretKey secretKey) throws Exception{
        ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream("server.pub"));

        //PublicKey of Server
        PublicKey publicKeyA = (PublicKey) objectInputStream.readObject();

        int signatureSize = in.readInt();
        byte[] signature =new byte[signatureSize];
        in.readFully(signature);

        signature = decryptSignature(signature,secretKey);


        Signature sign = Signature.getInstance("DSA");
        sign.initVerify(publicKeyA);

        ByteBuffer byteBuffer = ByteBuffer.allocate(16);
        byteBuffer.putInt(generatedNumbers.get(1).intValue());
        byteBuffer.putInt(generatedNumbers.get(0).intValue());

        sign.update(byteBuffer.array());

        return sign.verify(signature);
    }

    //Task 2 - Diffie-Hellman Manual - this side does b
    private static SecretKey keyAgreement(ObjectInputStream in, ObjectOutputStream out) throws Exception{


        String translator1024 =
                "F488FD584E49DBCD20B49DE49107366B336C380D451D0F7C88B31C7C5B2D8EF6"+
                        "F3C923C043F0A55B188D8EBB558CB85D38D334FD7C175743A31D186CDE33212C"+
                        "B52AFF3CE1B1294018118D7C84A70A72D686C40319C807297ACA950CD9969FAB"+
                        "D00A509B0246D3083D66A45D419F9C7CBD894B221926BAABA25EC355E92F78C7";
        BigInteger gBase = BigInteger.valueOf(2);
        BigInteger modulus = new BigInteger(translator1024,16);
        BigInteger b;

        do{
            b= new BigInteger(1024,new Random());
        }while(b.bitLength() < 1024);


        BigInteger eb = gBase.modPow(b, modulus);
        BigInteger ea = (BigInteger)in.readObject();
        out.writeObject(eb);
        BigInteger key = ea.modPow(b,modulus);


        //Adding eb first, ea second
        generatedNumbers.add(eb);
        generatedNumbers.add(ea);
        System.out.println("b generated: " + b);
        System.out.println("received ea: " + ea);
        System.out.println("sent eb: " + eb);
        System.out.println("key generated: " + key);

        SecretKeyFactory desede = SecretKeyFactory.getInstance("DESede");
        byte[] keyBytes = key.toByteArray();


        KeySpec keySpec = new DESedeKeySpec(keyBytes);


        return desede.generateSecret(keySpec);
    }

    //Read and decrypt the message from the server -  contains file contents
    private static void decryption(DataInputStream in, SecretKey secretKey) throws Exception{
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] encrypted = new byte[in.readInt()];
        in.readFully(encrypted,0,encrypted.length);

        String decrypted = new String(cipher.doFinal(encrypted), "UTF8");

        System.out.println(decrypted);
    }


    //Helper methods to encrypt and decrypt signatures
    private static byte[] encryptSignature(byte[] signature, SecretKey secretKey) throws Exception{

        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] encrypted =cipher.doFinal(signature);

        return encrypted;

    }

    private static byte[] decryptSignature(byte[] signature, SecretKey secretKey) throws Exception{

        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        return cipher.doFinal(signature);




    }
}
