package org.meadowhawk.util.crypto

import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import org.apache.commons.io.IOUtils
import org.bouncycastle.crypto.*
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.io.CipherInputStream
import org.bouncycastle.crypto.io.CipherOutputStream
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.paddings.BlockCipherPadding
import org.bouncycastle.crypto.paddings.PKCS7Padding
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.bouncycastle.jce.provider.BouncyCastleProvider


import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import java.security.GeneralSecurityException
import java.security.InvalidParameterException
import java.security.SecureRandom
import java.security.Security


@CompileStatic
@Slf4j
class EncryptionUtil {
    String password = ""
    final int iterations = 12000
    final int keyLength = 256
    final String KEY_ALGORITHM = "PBEWITHSHA256AND256BITAES-CBC-BC"
    static final int AES_NIVBITS = 128
    static final String  UTF8='UTF-8'
    final byte[] pwdSalt = [42,93,-116,80,-32,59,125,-37,-62,-67, 76,19,19,114,91,-115,-70,-89,36,-62]

    EncryptionUtil(String password){
        Security.insertProviderAt(new BouncyCastleProvider(), 1)
        this.password = password
    }

    KeyParameter getAesKey(String passphrase){
        byte[] rawKey

        try{
            if(passphrase == null || passphrase.isEmpty()) throw new InvalidParameterException("passphrase is null or empty")

            PBEKeySpec keySpec = new PBEKeySpec(passphrase.toCharArray(), pwdSalt, iterations, keyLength)
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KEY_ALGORITHM)
            rawKey = keyFactory.generateSecret(keySpec).getEncoded()
        } catch (Exception e){
            log.error "Key factory init failed with the following error: /n${e.toString()}"
        }

        new KeyParameter(rawKey)
    }

    def encodeStream(InputStream inputStream, OutputStream streamOut) throws GeneralSecurityException{
        byte[] ivData = new byte[AES_NIVBITS/8]
        new SecureRandom().nextBytes(ivData)

        //Select encrypt algo and padding: AES with CBC and PCKS7
        //Encrypt input stream using key+iv
        KeyParameter keyParam = getAesKey(this.password)
        CipherParameters params = new ParametersWithIV(keyParam, ivData)

        BlockCipherPadding padding = new PKCS7Padding()
        BufferedBlockCipher blockCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), padding)
        blockCipher.reset()
        blockCipher.init(true, params)

        streamOut.write(ivData)
        CipherOutputStream cipherOut = new CipherOutputStream(streamOut, blockCipher)
        IOUtils.copy(inputStream, cipherOut)
        cipherOut.close()
    }

    def decryptStream(InputStream encStream, OutputStream unEcnOutStream){
        //Extract the IV, which si stored in the next N bytes at the start of fileStream.
        int nIvBytes = AES_NIVBITS/ 8 as int
        byte[] ivBytes = new byte[nIvBytes]
        encStream.read(ivBytes, 0, nIvBytes)

        KeyParameter keyParam = getAesKey(this.password)
        CipherParameters params = new ParametersWithIV(keyParam, ivBytes)
        BlockCipherPadding padding = new PKCS7Padding()
        BufferedBlockCipher blockCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), padding)
        blockCipher.reset()
        blockCipher.init(false, params)

        CipherInputStream cipherIn = new CipherInputStream(encStream, blockCipher)
        IOUtils.copy(cipherIn, unEcnOutStream)
        cipherIn.close()
    }

    def decryptFileToFile(File fileIn, String filePathOut){
        InputStream inStr = fileIn.newInputStream()
        FileOutputStream fileOutStream = new FileOutputStream(filePathOut)
        ByteArrayOutputStream bos = new ByteArrayOutputStream()
        this.decryptStream(inStr, bos)
        bos.writeTo(fileOutStream)
        bos.close()
        fileOutStream.flush()
        fileOutStream.close()
    }
}
