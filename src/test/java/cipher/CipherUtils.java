package cipher;

import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;

public class CipherUtils
{

    public static String encrypt(String strToEncrypt, byte[] key)
    {
        try
        {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            final SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            final String encryptedString = Base64.encodeBase64String(cipher.doFinal(strToEncrypt.getBytes()));
            return encryptedString;
        }
        catch (Exception e)
        {
           e.printStackTrace();
        }
        return null;

    }

    public static String decrypt(String strToDecrypt, byte[] key)
    {
        try
        {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            final SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            final String decryptedString = new String(cipher.doFinal(Base64.decodeBase64(strToDecrypt)));
            return decryptedString;
        }
        catch (Exception e)
        {
          e.printStackTrace();

        }
        return null;
    }


    public static void main(String args[])
    {
    	mainMenu();
    }
    
    public static void mainMenu(){
    	
    	System.out.println("################");
		System.out.println("#  The Cipher  #");
		System.out.println("################");
		
		Scanner selection = new Scanner(System.in);
		System.out.println("Main Menu:");
		System.out.println("----------");
		System.out.println("1. Encrypt a message");
		System.out.println("2. Decrypt a message");
		System.out.println("3. Help");
		System.out.println("4. Exit");
		System.out.println();
		System.out.print("Enter a selection: ");
		int sel = selection.nextInt();
			switch(sel){
			case 1:
				cipherFunction( sel );
				//System.out.println("You selected 'encrypt'.");
				break;
			case 2:
				cipherFunction( sel );
				//System.out.println("You selected 'decrypt'.");
				break;
			case 3:
				System.out.println("You selected help.");
				break;
			case 4:
				System.out.println("Goodbye.");
				break;
			default:
				System.out.println("Sorry wrong command.");
			}
    }
    
    public static void cipherFunction(int cmd){
    	
        try
        {
        	Scanner selection = new Scanner(System.in);
        	
        	switch(cmd){
        	case 1:
        		System.out.println("Type the message that you would like to encrypt:");
        		final String strToEncrypt = selection.nextLine();
                System.out.println("Enter a passphrase to encrypt this string:");
        		final String passphraseToEncrypt = selection.nextLine();
        		final byte[] encryptKey = passphraseToEncrypt.getBytes();
                final String encryptedStr = CipherUtils.encrypt(strToEncrypt.trim(),encryptKey);
                System.out.println();
                System.out.println("String to Encrypt: " + strToEncrypt);
                System.out.println("Encrypted: " + encryptedStr);
                System.out.println();
        		System.out.println("##########################");
                System.out.println("#   Program terminated   #");
        		System.out.println("##########################");
				break;
			case 2:
				System.out.println("Type the message that you would like to decrypt:");
				final String strToDecrypt = selection.nextLine();
                System.out.println("Enter a passphrase to decrypt this string:");
        		final String passphraseToDecrypt = selection.nextLine();
        		final byte[] decryptKey = passphraseToDecrypt.getBytes();
                final String decryptedStr = CipherUtils.decrypt(strToDecrypt.trim(), decryptKey);
                System.out.println("String To Decrypt: " + strToDecrypt);
                System.out.println("Decrypted: " + decryptedStr);
                System.out.println();
        		System.out.println("##########################");
                System.out.println("#   Program terminated   #");
        		System.out.println("##########################");
				break;
			default:
				System.out.println("Sorry wrong command.");
				break;
        	}
        	
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }
}