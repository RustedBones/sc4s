/*
 * Copyright 2021 Michel Davit
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.davit.sc4s.security

import cats.effect.IO
import com.google.protobuf.ByteString
import fr.davit.sc4s.ap.authentication.APAck
import munit.CatsEffectSuite
import xyz.gianlu.librespot
import xyz.gianlu.librespot.common.Utils

import java.security.MessageDigest
import scala.util.Random

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
