package org.meadowhawk.util.crypto

import org.bouncycastle.crypto.params.KeyParameter
import spock.lang.Specification

import java.security.SecureRandom

class EncryptionUtilSpec extends Specification{
    String password = "1tzaS3cr3t!"
    String encOutFie = './src/test/resources/starWarsIpsum.enc'
    String decryptFileName = 'starWarsIpsum.txt'

    def "Test password encryption using one way hash" () {
        given:
        byte[] pwdSalt2 = new byte[20]
        new SecureRandom().nextBytes(pwdSalt2)

            EncryptionUtil encryptionUtil = new EncryptionUtil(password)

        when:
        KeyParameter key = encryptionUtil.getAesKey(password)

        then:
        assert key != null
        assert key.key.length == 32
    }

    def "Test encrypting a File" () {
        given:
        EncryptionUtil encryptionUtil = new EncryptionUtil(password)
        File inFile = new File('./src/test/resources/starWarsIpsum.txt')
        def unEncLine
        inFile.withReader { unEncLine = it.readLine() }

        InputStream inStr = inFile.newInputStream()
        FileOutputStream fileOutputStream = new FileOutputStream(encOutFie)

        when:
        fileOutputStream.with {fileStream ->
            encryptionUtil.encodeStream(inStr, fileStream)
        }

        then:
        File encOutFile = new File(encOutFie)
        encOutFile.exists()

        assert !encOutFile.text .contains(unEncLine)

        when:
        String decInput = ""
        FileOutputStream decFileOutStream = new FileOutputStream(decryptFileName)

        InputStream encInStr = encOutFile.newInputStream()
        encryptionUtil.decryptStream(encInStr, decFileOutStream)
        decFileOutStream.flush()
        decFileOutStream.close()
        encInStr.close()

        then:
        File decFile = new File(decryptFileName)
        assert decFile.exists()
        assert decFile.text .contains(unEncLine)
    }
}
