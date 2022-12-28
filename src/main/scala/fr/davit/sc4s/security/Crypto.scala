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
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.params.KeyParameter

import java.security.*
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAPublicKeySpec
import javax.crypto.*
import javax.crypto.interfaces.{DHPrivateKey, DHPublicKey}
import javax.crypto.spec.{DHParameterSpec, DHPrivateKeySpec, DHPublicKeySpec, IvParameterSpec}

object DiffieHellman {

  val Algorithm = "DH"

  // format: off
    private val Prime = BigInt(1, Array(
      0xff.toByte, 0xff.toByte, 0xff.toByte, 0xff.toByte, 0xff.toByte, 0xff.toByte, 0xff.toByte, 0xff.toByte,
      0xc9.toByte, 0x0f.toByte, 0xda.toByte, 0xa2.toByte, 0x21.toByte, 0x68.toByte, 0xc2.toByte, 0x34.toByte,
      0xc4.toByte, 0xc6.toByte, 0x62.toByte, 0x8b.toByte, 0x80.toByte, 0xdc.toByte, 0x1c.toByte, 0xd1.toByte,
      0x29.toByte, 0x02.toByte, 0x4e.toByte, 0x08.toByte, 0x8a.toByte, 0x67.toByte, 0xcc.toByte, 0x74.toByte,
      0x02.toByte, 0x0b.toByte, 0xbe.toByte, 0xa6.toByte, 0x3b.toByte, 0x13.toByte, 0x9b.toByte, 0x22.toByte,
      0x51.toByte, 0x4a.toByte, 0x08.toByte, 0x79.toByte, 0x8e.toByte, 0x34.toByte, 0x04.toByte, 0xdd.toByte,
      0xef.toByte, 0x95.toByte, 0x19.toByte, 0xb3.toByte, 0xcd.toByte, 0x3a.toByte, 0x43.toByte, 0x1b.toByte,
      0x30.toByte, 0x2b.toByte, 0x0a.toByte, 0x6d.toByte, 0xf2.toByte, 0x5f.toByte, 0x14.toByte, 0x37.toByte,
      0x4f.toByte, 0xe1.toByte, 0x35.toByte, 0x6d.toByte, 0x6d.toByte, 0x51.toByte, 0xc2.toByte, 0x45.toByte,
      0xe4.toByte, 0x85.toByte, 0xb5.toByte, 0x76.toByte, 0x62.toByte, 0x5e.toByte, 0x7e.toByte, 0xc6.toByte,
      0xf4.toByte, 0x4c.toByte, 0x42.toByte, 0xe9.toByte, 0xa6.toByte, 0x3a.toByte, 0x36.toByte, 0x20.toByte,
      0xff.toByte, 0xff.toByte, 0xff.toByte, 0xff.toByte, 0xff.toByte, 0xff.toByte, 0xff.toByte, 0xff.toByte
    ))
    // format: on
  private val Generator     = BigInt(2)
  private val KeyLength     = 95
  private val ParameterSpec = new DHParameterSpec(Prime.bigInteger, Generator.bigInteger, KeyLength * 8)

  implicit class RichDHPublicKey(val key: DHPublicKey) extends AnyVal:

    def getBytes: Array[Byte] =
      val bytes = key.getY.toByteArray
      if bytes.head == 0 then bytes.tail else bytes

  def generateKeyPair(): (DHPrivateKey, DHPublicKey) =
    val gen = KeyPairGenerator.getInstance(Algorithm)
    gen.initialize(ParameterSpec)
    val pair = gen.generateKeyPair()
    (pair.getPrivate.asInstanceOf[DHPrivateKey], pair.getPublic.asInstanceOf[DHPublicKey])

  def generatePublicKey(y: BigInt): DHPublicKey =
    val keySpec = new DHPublicKeySpec(y.bigInteger, Prime.bigInteger, Generator.bigInteger)
    val factory = KeyFactory.getInstance(Algorithm)
    factory.generatePublic(keySpec).asInstanceOf[DHPublicKey]

  def generatePrivateKey(x: BigInt, privateKey: DHPrivateKey): DHPublicKey =
    val keySpec = new DHPrivateKeySpec(x.bigInteger, privateKey.getX, Prime.bigInteger)
    val factory = KeyFactory.getInstance(Algorithm)
    factory.generatePublic(keySpec).asInstanceOf[DHPublicKey]

  def secret(privateKey: DHPrivateKey, publicKey: DHPublicKey): Array[Byte] =
    val agreement = KeyAgreement.getInstance(Algorithm)
    agreement.init(privateKey)
    agreement.doPhase(publicKey, true)
    agreement.generateSecret()
}

object Sha1:
  val Algorithm = "SHA1"

  def digest(data: Array[Byte]): Array[Byte] = MessageDigest.getInstance(Algorithm).digest(data)

object HmacSHA1:

  val Algorithm = "HmacSHA1"

  def digest(secretKey: SecretKey, data: Array[Byte]): Array[Byte] =
    val mac = Mac.getInstance(Algorithm)
    mac.init(secretKey)
    mac.doFinal(data)

object PBKDF2HmacWithSHA1:

  val Algorithm = "PBKDF2WithHmacSHA1"

  private class PBEKey(key: Array[Byte], algo: String) extends SecretKey:
    override def getAlgorithm: String    = algo
    override def getFormat: String       = "RAW"
    override def getEncoded: Array[Byte] = key.clone()

  def generateSecretKey(
      password: Array[Byte],
      salt: Array[Byte],
      iterationCount: Int,
      length: Int
  ): SecretKey =
    // user the bouncycastle implementation here
    // jce implementation only accepts UTF-8 passwords
    val gen = new PKCS5S2ParametersGenerator()
    gen.init(password, salt, iterationCount)
    val key = gen.generateDerivedParameters(length * 8).asInstanceOf[KeyParameter].getKey
    new PBEKey(key, "HmacSHA1")

object AES:

  val Algorithm = "AES"

  sealed trait Mode
  case object CTR extends Mode
  case object ECB extends Mode

  sealed trait Padding
  case object NoPadding extends Padding

  val Transformation = "AES/CTR/NoPadding"

  def decrypt(
      mode: Mode,
      padding: Padding,
      encryptionKey: Key,
      data: Array[Byte]
  ): Array[Byte] = decrypt(mode, padding, encryptionKey, None, data)

  def decrypt(
      mode: Mode,
      padding: Padding,
      encryptionKey: Key,
      p: IvParameterSpec,
      data: Array[Byte]
  ): Array[Byte] = decrypt(mode, padding, encryptionKey, Some(p), data)

  private def decrypt(
      mode: Mode,
      padding: Padding,
      encryptionKey: Key,
      params: Option[IvParameterSpec],
      data: Array[Byte]
  ): Array[Byte] =
    val cipher = Cipher.getInstance(s"$Algorithm/$mode/$padding")
    params match
      case Some(p) => cipher.init(Cipher.DECRYPT_MODE, encryptionKey, p)
      case None    => cipher.init(Cipher.DECRYPT_MODE, encryptionKey)
    cipher.doFinal(data)

object RSA:

  val Algorithm = "RSA"

  def generatePublicKey(modulus: BigInt, exponent: BigInt): RSAPublicKey =
    val keySpec = new RSAPublicKeySpec(modulus.bigInteger, exponent.bigInteger)
    val factory = KeyFactory.getInstance(Algorithm)
    factory.generatePublic(keySpec).asInstanceOf[RSAPublicKey]

object SHA1withRSA:

  val Algorithm = "SHA1withRSA"

  def verifySignature(publicKey: RSAPublicKey, data: Array[Byte], signature: Array[Byte]): Boolean =
    val sig = Signature.getInstance(Algorithm)
    sig.initVerify(publicKey)
    sig.update(data)
    sig.verify(signature)

object Shannon:

  sealed abstract class Mode(private[security] val value: Int)
  case object Encrypt extends Mode(Cipher.ENCRYPT_MODE)
  case object Decrypt extends Mode(Cipher.DECRYPT_MODE)

  val Algorithm = "Shannon"

  def cipher(mode: Mode, key: Key, params: ShannonParameterSpec): Cipher = cipher(mode, key, Some(params))

  def cipher(mode: Mode, key: Key): Cipher = cipher(mode, key, None)

  private def cipher(mode: Mode, key: Key, params: Option[ShannonParameterSpec]): Cipher =
    val cipher = Cipher.getInstance(Algorithm)
    params match
      case Some(p) => cipher.init(mode.value, key, p)
      case None    => cipher.init(mode.value, key)
    cipher
