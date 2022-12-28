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

import fr.davit.sc4s.security.ShannonCipher.ShannonParameterSpec
import munit.CatsEffectSuite
import xyz.gianlu.librespot

import java.security.Security
import java.util.Base64
import javax.crypto.spec.SecretKeySpec
import scala.util.Random

class ShannonCipherSpec extends CatsEffectSuite:

  val key     = Base64.getDecoder.decode("FH+xbCHmV//WI+VGgiLMSBp60HpvaZFlcXF6dv+G0jc=")
  val keySpec = new SecretKeySpec(key, Shannon.Algorithm)

  override def beforeAll(): Unit =
    Security.addProvider(ShannonCipher.ShannonCipherProvider)

  override def afterAll(): Unit =
    Security.removeProvider(ShannonCipher.ShannonCipherProvider.getName)

  def encrypt(s: librespot.crypto.Shannon, nonce: Int, data: Array[Byte]): Array[Byte] =
    val input = data.clone()
    s.nonce(librespot.common.Utils.toByteArray(nonce))
    s.encrypt(input)
    input

  def decrypt(s: librespot.crypto.Shannon, nonce: Int, data: Array[Byte]): Array[Byte] =
    val input = data.clone()
    s.nonce(librespot.common.Utils.toByteArray(nonce))
    s.decrypt(input)
    input

  def mac(s: librespot.crypto.Shannon): Array[Byte] =
    val mac = Array.ofDim[Byte](4)
    s.finish(mac)
    mac

  test("encrypt data") {
    val testData = Random.nextBytes(512)
    val shannon  = new librespot.crypto.Shannon()
    shannon.key(key)
    val expected = encrypt(shannon, 0, testData) ++ mac(shannon)
    val cipher   = Shannon.cipher(Shannon.Encrypt, keySpec)
    val actual   = cipher.update(testData) ++ cipher.doFinal()
    assertEquals(actual.toVector, expected.toVector)
  }

  test("encrypt data with nonce") {
    val testData = Random.nextBytes(512)
    val shannon  = new librespot.crypto.Shannon()
    shannon.key(key)
    val expected = encrypt(shannon, 42, testData) ++ mac(shannon)
    val iv       = Shannon.cipher(Shannon.Encrypt, keySpec).getIV
    val cipher   = Shannon.cipher(Shannon.Encrypt, keySpec, new ShannonParameterSpec(iv, 42))
    val actual   = cipher.update(testData) ++ cipher.doFinal()
    assertEquals(actual.toVector, expected.toVector)
  }

  test("decrypt data") {
    val testData = Random.nextBytes(512)
    val shannon  = new librespot.crypto.Shannon()
    shannon.key(key)
    val expected    = decrypt(shannon, 0, testData)
    val expectedMac = mac(shannon)
    val cipher      = Shannon.cipher(Shannon.Decrypt, keySpec)
    val actual      = cipher.update(testData) ++ cipher.doFinal(expectedMac)
    assertEquals(actual.toVector, expected.toVector)
  }

  test("decrypt data with nonce") {
    val testData = Random.nextBytes(512)
    val shannon  = new librespot.crypto.Shannon()
    shannon.key(key)
    val expected    = decrypt(shannon, 42, testData)
    val expectedMac = mac(shannon)
    val iv          = Shannon.cipher(Shannon.Decrypt, keySpec).getIV
    val cipher      = Shannon.cipher(Shannon.Decrypt, keySpec, new ShannonParameterSpec(iv, 42))
    val actual      = cipher.update(testData) ++ cipher.doFinal(expectedMac)
    assertEquals(actual.toVector, expected.toVector)
  }
