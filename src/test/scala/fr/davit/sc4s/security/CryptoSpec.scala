package fr.davit.sc4s.security

import cats.effect.IO
import munit.CatsEffectSuite
import xyz.gianlu.librespot
import xyz.gianlu.librespot.common.Utils

import java.security.MessageDigest

class CryptoSpec extends CatsEffectSuite {

  test("DiffieHellman should generate secret") {
    val (priv, pub) = DiffieHellman.generateKeyPair[IO]().unsafeRunSync()
    val expected    = Utils.toByteArray(pub.getY.modPow(priv.getX, priv.getParams.getP))
    val secret      = DiffieHellman.secret[IO](priv, pub).unsafeRunSync()
    println(secret.head)
    assertEquals(secret.toVector, expected.toVector)
  }

  test("PBKDF2HmacWithSHA1") {
    val password = MessageDigest.getInstance("SHA-1").digest("1234".getBytes)
    val salt     = "5678".getBytes

    val expected = librespot.crypto.PBKDF2.HmacSHA1(password, salt, 0x100, 20)
    val key = PBKDF2HmacWithSHA1
      .generateSecretKey[IO](password, salt, 0x100, 20)
      .unsafeRunSync()

    assertEquals(key.getEncoded.toVector, expected.toVector)
  }

}
