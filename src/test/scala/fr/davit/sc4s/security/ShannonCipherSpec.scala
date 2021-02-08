package fr.davit.sc4s.security

import cats.effect.IO
import munit.CatsEffectSuite
import xyz.gianlu.librespot

import java.security.Security
import java.util.Base64
import javax.crypto.spec.SecretKeySpec
import scala.util.Random

class ShannonCipherSpec extends CatsEffectSuite {

  val key = new SecretKeySpec(Base64.getDecoder.decode("FH+xbCHmV//WI+VGgiLMSBp60HpvaZFlcXF6dv+G0jc="), Shannon.Algorithm)
  Security.addProvider(ShannonCipher.ShannonCipherProvider)

  test("encrypt data") {
    val testData = Random.nextBytes(512)

    val input = testData.clone()
    val mac = Array.ofDim[Byte](4)
    val shannon = new librespot.crypto.Shannon()
    shannon.key(key.getEncoded)
    shannon.nonce(Array[Byte](30, 0, 0, 0))
    shannon.encrypt(input)
    shannon.finish(mac)
    val expected = (input ++ mac).toList
    val encrypted = Shannon
      .encryptCipher[IO](key, 42)
      .use(c => IO(c.doFinal(testData).toList))

    assertIO(encrypted, expected)
  }

  test("decrypt data") {
    val testData = Random.nextBytes(512)

    val input = testData.clone()
    val mac = Array.ofDim[Byte](4)
    val shannon = new librespot.crypto.Shannon()
    shannon.key(key.getEncoded)
    shannon.nonce(Array[Byte](42, 0, 0, 0))
    shannon.decrypt(input)
    shannon.finish(mac)
    val expected = input.toList

    val decrypted = Shannon.
      decryptCipher[IO](key, 42)
      .use(c => IO(c.doFinal(testData ++ mac).toList))
    assertIO(decrypted, expected)
  }

}
