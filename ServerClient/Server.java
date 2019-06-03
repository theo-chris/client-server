import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Random;

public class Server {

    //java Server port

    static ArrayList<BigInteger> generatedNumbers;
    public static void main(String[] args) throws Exception{

        if(args.length != 1){
            System.err.println("Usage: java Server <port>");
            System.exit(-1);
        }
        int port = Integer.parseInt(args[0]);


        ServerSocket serverSocket = new ServerSocket(port);

        System.out.println("Waiting for client...");

        while(true) {
            //Need to initialize every time, because the server runs forever
            generatedNumbers = new ArrayList<BigInteger>();
            try {
                Socket client = serverSocket.accept();
                DataInputStream in = new DataInputStream(client.getInputStream());
                DataOutputStream out = new DataOutputStream(client.getOutputStream());
                ObjectOutputStream objectOutputStream = new ObjectOutputStream(client.getOutputStream());
                ObjectInputStream objectInputStream = new ObjectInputStream(client.getInputStream());


                String userId = in.readUTF();
                String contents = readContents(userId);

                SecretKey desedeKey = keyAgreement(objectInputStream, objectOutputStream);

                if (!verifyClient(in,userId,desedeKey)){
                    System.err.println("Failed to authenticate the client...");
                    System.err.println("Closing connection...");
                    client.close();
                }else {

                    serverAuthentication(out, desedeKey);
                    encryption(out, desedeKey, contents);

                }
            }catch(EOFException e){
                System.err.println("Disconnected client.");
                continue;
            }

        }

    }

    //Task 1 - to read the contents of the file <userid>.txt
    private static String readContents(String userId) throws Exception{

        String fileName = userId + ".txt";
        BufferedReader bufferedReader = new BufferedReader(new FileReader(fileName));

        String line = null;
        String s = "";

        while ((line = bufferedReader.readLine()) != null) {

            s += line;
        }

        return s;
    }

    //Task 2 - Diffie-Hellman Manual - this side does a
    private static SecretKey keyAgreement(ObjectInputStream in, ObjectOutputStream out) throws Exception{

        BigInteger gBase = BigInteger.valueOf(2);

        String skip1024String =
                "F488FD584E49DBCD20B49DE49107366B336C380D451D0F7C88B31C7C5B2D8EF6"+
                        "F3C923C043F0A55B188D8EBB558CB85D38D334FD7C175743A31D186CDE33212C"+
                        "B52AFF3CE1B1294018118D7C84A70A72D686C40319C807297ACA950CD9969FAB"+
                        "D00A509B0246D3083D66A45D419F9C7CBD894B221926BAABA25EC355E92F78C7";

        BigInteger modulus = new BigInteger(skip1024String,16);



        BigInteger a;
        do{
            a= new BigInteger(1024,new Random());
        }while(a.bitLength()<1024);

        BigInteger ea = gBase.modPow(a, modulus);
        out.writeObject(ea);
        BigInteger eb = (BigInteger)in.readObject();
        BigInteger key = eb.modPow(a,modulus);

        generatedNumbers.add(ea);
        generatedNumbers.add(eb);


        System.out.println("a generated: " + a);
        System.out.println("sent ea: " + ea);
        System.out.println("received eb: " + eb);
        System.out.println("key calculated: " + key);



        byte[] keyBytes = key.toByteArray();

        SecretKeyFactory desede = SecretKeyFactory.getInstance("DESede");
        KeySpec keySpec = new DESedeKeySpec(keyBytes);


        return desede.generateSecret(keySpec);
    }
    //verify clients signature
    private static boolean verifyClient(DataInputStream in, String userId, SecretKey secretKey) throws Exception{

        ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(userId+".pub"));

        //verify with public key of B
        PublicKey publicKeyB = (PublicKey) objectInputStream.readObject();

       int signatureSize = in.readInt();

       byte[] signature =new byte[signatureSize];

       in.readFully(signature);

       signature = decryptSignature(signature,secretKey);

      Signature sign = Signature.getInstance("DSA");
      sign.initVerify(publicKeyB);

      ByteBuffer byteBuffer = ByteBuffer.allocate(16);
      byteBuffer.putInt(generatedNumbers.get(1).intValue());
      byteBuffer.putInt(generatedNumbers.get(0).intValue());

      sign.update(byteBuffer.array());


      return sign.verify(signature);


    }
    //sent encrypted signature to the client for authentication
    private static void serverAuthentication(DataOutputStream out,SecretKey secretKey) throws Exception{

        ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream("server.prv"));
        PrivateKey privateKeyA = (PrivateKey) objectInputStream.readObject();

        Signature signature = Signature.getInstance("DSA");
        signature.initSign(privateKeyA);

        ByteBuffer byteBuffer = ByteBuffer.allocate(16);
        byteBuffer.putInt(generatedNumbers.get(0).intValue());
        byteBuffer.putInt(generatedNumbers.get(1).intValue());


        signature.update(byteBuffer.array());

        byte[] sign = signature.sign();
        byte[] encryptedSignature= encryptSignature(sign,secretKey);

        out.writeInt(encryptedSignature.length);
        out.write(encryptedSignature);


    }



    //Encrypt contents of the file and send to server
    private static void encryption(DataOutputStream out, SecretKey secretKey, String contents) throws Exception{
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypted = cipher.doFinal(contents.getBytes("UTF8"));

        out.writeInt(encrypted.length);
        out.write(encrypted);
        System.out.println("Sent encrypted contets... ");

    }

    //Helper methods to encrypt and decrypt the signatures
    private static byte[] decryptSignature(byte[] signature, SecretKey secretKey) throws Exception{

        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        return cipher.doFinal(signature);




    }
    private static byte[] encryptSignature(byte[] signature, SecretKey secretKey) throws Exception{

        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] encrypted =cipher.doFinal(signature);

        return encrypted;

    }


}
