import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import java.util.Base64;

public class PinEncryption {

    public static String encryptPin(String pin, String cardNumber, String publicKeyBase64) throws Exception {
        String hexPINBlock = padRight("0" + pin.length() + pin, 16, 'F');
        cardNumber = cardNumber.substring(0, cardNumber.length() - 1);
        String hexCardlock = ("0000" + cardNumber.substring(cardNumber.length() - 12));
        
        BigInteger dec1 = new BigInteger(hexPINBlock, 16);
        BigInteger dec2 = new BigInteger(hexCardlock, 16);
        BigInteger result = dec1.xor(dec2);
        String hexResult = result.toString(16).toUpperCase();

        if (hexResult.length() < 16) {
            hexResult = "0" + hexResult;
        }

        byte[] bytes = new byte[hexResult.length() / 2];
        for (int i = 0; i < hexResult.length(); i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(hexResult.charAt(i), 16) << 4)
                                    + Character.digit(hexResult.charAt(i+1), 16));
        }

        String hexStringResult = bytesToHex(bytes);

        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // Adjust if needed
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(hexStringResult.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String padRight(String str, int length, char padChar) {
        StringBuilder sb = new StringBuilder(str);
        while (sb.length() < length) {
            sb.append(padChar);
        }
        return sb.toString();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
