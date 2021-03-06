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

package fr.davit.sc4s.ap

import cats.effect._
import cats.effect.concurrent.Ref
import cats.implicits._
import com.google.protobuf.ByteString
import com.spotify.authentication.{APWelcome, ClientResponseEncrypted}
import com.spotify.keyexchange.{BuildInfo => ApBuildInfo, _}
import fr.davit.sc4s.security.DiffieHellman._
import fr.davit.sc4s.security.ShannonCipher.ShannonParameterSpec
import fr.davit.sc4s.security._
import fs2._
import fs2.io.tcp.Socket
import scalapb.{GeneratedMessage, GeneratedMessageCompanion}
import scodec._
import scodec.bits._
import scodec.codecs._

import java.security.Key
import javax.crypto.Cipher
import javax.crypto.interfaces.DHPublicKey
import javax.crypto.spec.SecretKeySpec
import scala.concurrent.duration.FiniteDuration
import scala.util.Random

trait AccessPointContext[F[_]] {

  def write[T <: GeneratedMessage](message: T): F[Unit]

  def read[T <: GeneratedMessage](): F[T]

  def reads(): Stream[F, GeneratedMessage]
}

object AccessPointContext {

  class HandshakeException(loginFailed: APLoginFailed) extends Exception(loginFailed.errorCode.name)

  // format: off
  private val Modulus = BigInt(1, Array[Byte](
    0xac.toByte, 0xe0.toByte, 0x46.toByte, 0x0b.toByte, 0xff.toByte, 0xc2.toByte, 0x30.toByte, 0xaf.toByte, 0xf4.toByte,
    0x6b.toByte, 0xfe.toByte, 0xc3.toByte, 0xbf.toByte, 0xbf.toByte, 0x86.toByte, 0x3d.toByte, 0xa1.toByte, 0x91.toByte,
    0xc6.toByte, 0xcc.toByte, 0x33.toByte, 0x6c.toByte, 0x93.toByte, 0xa1.toByte, 0x4f.toByte, 0xb3.toByte, 0xb0.toByte,
    0x16.toByte, 0x12.toByte, 0xac.toByte, 0xac.toByte, 0x6a.toByte, 0xf1.toByte, 0x80.toByte, 0xe7.toByte, 0xf6.toByte,
    0x14.toByte, 0xd9.toByte, 0x42.toByte, 0x9d.toByte, 0xbe.toByte, 0x2e.toByte, 0x34.toByte, 0x66.toByte, 0x43.toByte,
    0xe3.toByte, 0x62.toByte, 0xd2.toByte, 0x32.toByte, 0x7a.toByte, 0x1a.toByte, 0x0d.toByte, 0x92.toByte, 0x3b.toByte,
    0xae.toByte, 0xdd.toByte, 0x14.toByte, 0x02.toByte, 0xb1.toByte, 0x81.toByte, 0x55.toByte, 0x05.toByte, 0x61.toByte,
    0x04.toByte, 0xd5.toByte, 0x2c.toByte, 0x96.toByte, 0xa4.toByte, 0x4c.toByte, 0x1e.toByte, 0xcc.toByte, 0x02.toByte,
    0x4a.toByte, 0xd4.toByte, 0xb2.toByte, 0x0c.toByte, 0x00.toByte, 0x1f.toByte, 0x17.toByte, 0xed.toByte, 0xc2.toByte,
    0x2f.toByte, 0xc4.toByte, 0x35.toByte, 0x21.toByte, 0xc8.toByte, 0xf0.toByte, 0xcb.toByte, 0xae.toByte, 0xd2.toByte,
    0xad.toByte, 0xd7.toByte, 0x2b.toByte, 0x0f.toByte, 0x9d.toByte, 0xb3.toByte, 0xc5.toByte, 0x32.toByte, 0x1a.toByte,
    0x2a.toByte, 0xfe.toByte, 0x59.toByte, 0xf3.toByte, 0x5a.toByte, 0x0d.toByte, 0xac.toByte, 0x68.toByte, 0xf1.toByte,
    0xfa.toByte, 0x62.toByte, 0x1e.toByte, 0xfb.toByte, 0x2c.toByte, 0x8d.toByte, 0x0c.toByte, 0xb7.toByte, 0x39.toByte,
    0x2d.toByte, 0x92.toByte, 0x47.toByte, 0xe3.toByte, 0xd7.toByte, 0x35.toByte, 0x1a.toByte, 0x6d.toByte, 0xbd.toByte,
    0x24.toByte, 0xc2.toByte, 0xae.toByte, 0x25.toByte, 0x5b.toByte, 0x88.toByte, 0xff.toByte, 0xab.toByte, 0x73.toByte,
    0x29.toByte, 0x8a.toByte, 0x0b.toByte, 0xcc.toByte, 0xcd.toByte, 0x0c.toByte, 0x58.toByte, 0x67.toByte, 0x31.toByte,
    0x89.toByte, 0xe8.toByte, 0xbd.toByte, 0x34.toByte, 0x80.toByte, 0x78.toByte, 0x4a.toByte, 0x5f.toByte, 0xc9.toByte,
    0x6b.toByte, 0x89.toByte, 0x9d.toByte, 0x95.toByte, 0x6b.toByte, 0xfc.toByte, 0x86.toByte, 0xd7.toByte, 0x4f.toByte,
    0x33.toByte, 0xa6.toByte, 0x78.toByte, 0x17.toByte, 0x96.toByte, 0xc9.toByte, 0xc3.toByte, 0x2d.toByte, 0x0d.toByte,
    0x32.toByte, 0xa5.toByte, 0xab.toByte, 0xcd.toByte, 0x05.toByte, 0x27.toByte, 0xe2.toByte, 0xf7.toByte, 0x10.toByte,
    0xa3.toByte, 0x96.toByte, 0x13.toByte, 0xc4.toByte, 0x2f.toByte, 0x99.toByte, 0xc0.toByte, 0x27.toByte, 0xbf.toByte,
    0xed.toByte, 0x04.toByte, 0x9c.toByte, 0x3c.toByte, 0x27.toByte, 0x58.toByte, 0x04.toByte, 0xb6.toByte, 0xb2.toByte,
    0x19.toByte, 0xf9.toByte, 0xc1.toByte, 0x2f.toByte, 0x02.toByte, 0xe9.toByte, 0x48.toByte, 0x63.toByte, 0xec.toByte,
    0xa1.toByte, 0xb6.toByte, 0x42.toByte, 0xa0.toByte, 0x9d.toByte, 0x48.toByte, 0x25.toByte, 0xf8.toByte, 0xb3.toByte,
    0x9d.toByte, 0xd0.toByte, 0xe8.toByte, 0x6a.toByte, 0xf9.toByte, 0x48.toByte, 0x4d.toByte, 0xa1.toByte, 0xc2.toByte,
    0xba.toByte, 0x86.toByte, 0x30.toByte, 0x42.toByte, 0xea.toByte, 0x9d.toByte, 0xb3.toByte, 0x08.toByte, 0x6c.toByte,
    0x19.toByte, 0x0e.toByte, 0x48.toByte, 0xb3.toByte, 0x9d.toByte, 0x66.toByte, 0xeb.toByte, 0x00.toByte, 0x06.toByte,
    0xa2.toByte, 0x5a.toByte, 0xee.toByte, 0xa1.toByte, 0x1b.toByte, 0x13.toByte, 0x87.toByte, 0x3c.toByte, 0xd7.toByte,
    0x19.toByte, 0xe6.toByte, 0x55.toByte, 0xbd.toByte
  ))
  val Exponent = BigInt(65537)
  // format: on

  implicit def protobufEncoder[T <: GeneratedMessage]: Encoder[T] =
    bytes.asEncoder
      .contramap[Array[Byte]](ByteVector.apply)
      .contramap[T](message => message.companion.asInstanceOf[GeneratedMessageCompanion[T]].toByteArray(message))

  implicit def protobufDecoder[T <: GeneratedMessage](cmp: GeneratedMessageCompanion[T]): Decoder[T] =
    bytes.asDecoder
      .map[Array[Byte]](_.toArray)
      .map[T](cmp.parseFrom)
      .complete

  val codeCodec: Codec[GeneratedMessageCompanion[_ <: GeneratedMessage]] =
    discriminated[GeneratedMessageCompanion[_ <: GeneratedMessage]]
      .by(bytes(1))
      .typecase(hex"ab", provide(ClientResponseEncrypted))
      .typecase(hex"ac", provide(APWelcome))

  def apply[F[_]: Concurrent](
      socket: Socket[F],
      timeout: Option[FiniteDuration] = None
  ): F[AccessPointContext[F]] = {

    def hello(publicKey: DHPublicKey): ClientHello = {
      val info = ApBuildInfo.defaultInstance
        .withProduct(Product.PRODUCT_PARTNER)
        .withPlatform(Platform.PLATFORM_LINUX_X86)
        .withVersion(109800078L)

      val dhHello = LoginCryptoDiffieHellmanHello.defaultInstance
        .withGc(ByteString.copyFrom(publicKey.getBytes))
        .withServerKeysKnown(1)
      val login = LoginCryptoHelloUnion.defaultInstance
        .withDiffieHellman(dhHello)

      ClientHello.defaultInstance
        .withBuildInfo(info)
        .withCryptosuitesSupported(Seq(Cryptosuite.CRYPTO_SUITE_SHANNON))
        .withLoginCryptoHello(login)
        .withClientNonce(ByteString.copyFrom(Random.nextBytes(0x10)))
        .withPadding(ByteString.copyFrom(Array(0x1e.toByte)))
    }

    def challengeResponse(answer: Array[Byte]): ClientResponsePlaintext = {
      val dhResponse = LoginCryptoDiffieHellmanResponse.defaultInstance
        .withHmac(ByteString.copyFrom(answer))
      val login = LoginCryptoResponseUnion.defaultInstance
        .withDiffieHellman(dhResponse)
      ClientResponsePlaintext.defaultInstance
        .withLoginCryptoResponse(login)
    }

    def encode[T](data: T)(implicit encoder: Encoder[T]): F[ByteVector] =
      Sync[F].delay(encoder.encode(data).require.toByteVector)

    def decode[T](bytes: ByteVector)(implicit decoder: Decoder[T]): F[T] =
      Sync[F].delay(decoder.decode(bytes.toBitVector).require.value)

    def writeSocket[T](data: T, encoder: Encoder[T]): F[Unit] =
      for {
        bytes <- encode(data)(encoder)
        _     <- socket.write(Chunk.byteVector(bytes))
      } yield ()

    def readSocket[T](size: Int, decoder: Decoder[T]): F[T] =
      for {
        chunk <- socket.readN(size, timeout)
        bytes <- chunk match {
          case Some(c) if c.size == size => Sync[F].pure(c.toByteVector)
          case _                         => Sync[F].raiseError(new RuntimeException("Missing data"))
        }
        header <- decode(bytes)(decoder)
      } yield header

    def handshake(): F[(Key, Key)] = {

      val headerCodec: Codec[Int]     = uint32.xmap(_.toInt - 4, _ + 4L)
      val initHeaderCodec: Codec[Int] = (constant(ByteVector(0, 4)) ~> headerCodec).xmap(_ - 2, _ + 2)

      for {
        keyPair <- DiffieHellman.generateKeyPair[F]()
        (priv, pub) = keyPair
        clientHelloPayload       <- encode(hello(pub))
        clientHelloHeader        <- encode(clientHelloPayload.size.toInt)(initHeaderCodec)
        _                        <- writeSocket(clientHelloHeader, bytes)
        _                        <- writeSocket(clientHelloPayload, bytes)
        apResponseHeader         <- readSocket(4, bytes)
        apResponseMessageSize    <- decode(apResponseHeader)(headerCodec)
        apResponseMessagePayload <- readSocket(apResponseMessageSize, bytes)
        apResponseMessage        <- decode(apResponseMessagePayload)(protobufDecoder(APResponseMessage))
        challenge       = apResponseMessage.getChallenge.loginCryptoChallenge
        serverKeyData   = challenge.getDiffieHellman.gs.toByteArray
        serverSignature = challenge.getDiffieHellman.gsSignature.toByteArray
        signatureKey <- RSA.generatePublicKey(Modulus, Exponent)
        _            <- SHA1withRSA.verifySignature(signatureKey, serverKeyData, serverSignature)
        serverKey    <- DiffieHellman.generatePublicKey(BigInt(1, serverKeyData))
        secret       <- DiffieHellman.secret(priv, serverKey)
        sharedKey = new SecretKeySpec(secret, HmacSHA1.Algorithm)
        challengeData =
          (clientHelloHeader ++ clientHelloPayload ++ apResponseHeader ++ apResponseMessagePayload).toArray
        data <- (1 to 5).toList
          .traverse(i => HmacSHA1.digest(sharedKey, challengeData ++ Array(i.toByte)))
          .map(_.reduce(_ ++ _))
        secretKey = new SecretKeySpec(data, 0, 20, HmacSHA1.Algorithm)
        encodeKey = new SecretKeySpec(data, 20, 32, Shannon.Algorithm)
        decodeKey = new SecretKeySpec(data, 52, 32, Shannon.Algorithm)
        answer                <- HmacSHA1.digest(secretKey, challengeData)
        clientResponsePayload <- encode(challengeResponse(answer))
        _                     <- writeSocket(clientResponsePayload.size.toInt, headerCodec)
        _                     <- writeSocket(clientResponsePayload, bytes)
        // no response expected in case of success
//        errorSize <- readSocket(4, headerCodec)
//        error     <- readSocket(errorSize, protobufDecoder(APResponseMessage))
//        _         <- Sync[F].raiseError[Unit](new HandshakeException(error.loginFailed.get))
      } yield (encodeKey, decodeKey)
    }

    for {
      keys <- handshake()
      (encryptKey, decryptKey) = keys
      encryptIv <- Shannon
        .cipher[F]()
        .flatTap(c => Sync[F].delay(c.init(Cipher.ENCRYPT_MODE, encryptKey)))
        .map(_.getIV)
      encryptNonce <- Ref.of(0)
      decryptIv <- Shannon
        .cipher[F]()
        .flatTap(c => Sync[F].delay(c.init(Cipher.DECRYPT_MODE, decryptKey)))
        .map(_.getIV)
      decryptNonce <- Ref.of(0)
    } yield new AccessPointContext[F] {

      def crypt(cipher: Cipher): Codec[ByteVector] =
        bytes
          .xmap[Array[Byte]](_.toArray, ByteVector.view)
          .xmap[Array[Byte]](cipher.update, cipher.update)
          .xmap[ByteVector](ByteVector.view, _.toArray)

      private def headerCodec[T](cipher: Cipher) =
        crypt(cipher)
          .xmap[BitVector](_.toBitVector, _.toByteVector)
          .exmap((codeCodec ~ uint16).decode(_).map(_.value), (codeCodec ~ uint16).encode)

      override def write[T <: GeneratedMessage](message: T): F[Unit] = {
        for {
          nonce <- encryptNonce.modify(n => (n + 1, n))
          _     <- Sync[F].delay(println(nonce))
          param = new ShannonParameterSpec(encryptIv, nonce)
          cipher  <- Shannon.cipher().flatTap(c => Sync[F].delay(c.init(Cipher.ENCRYPT_MODE, encryptKey, param)))
          payload <- encode(message)
          _       <- Sync[F].delay(println(payload.toString()))
          cmp = message.companion.asInstanceOf[GeneratedMessageCompanion[T]]
          _   <- writeSocket((cmp, payload.size.toInt), headerCodec(cipher))
          _   <- writeSocket(payload, crypt(cipher))
          mac <- Sync[F].delay(cipher.doFinal())
          _   <- Sync[F].delay(println(ByteVector.view(mac)))
          _   <- writeSocket(ByteVector.view(mac), bytes)
        } yield ()
      }

      def read[T <: GeneratedMessage](): F[T] = {
        for {
          nonce <- decryptNonce.modify(n => (n + 1, n))
          param = new ShannonParameterSpec(decryptIv, nonce)
          cipher <- Shannon.cipher[F]().flatTap(c => Sync[F].delay(c.init(Cipher.DECRYPT_MODE, decryptKey, param)))
          header <- readSocket(3, headerCodec(cipher))
          (cmp, size) = header
          widenedCmp <- Sync[F].delay(cmp.asInstanceOf[GeneratedMessageCompanion[T]]) // TODO better way ?
          payload    <- readSocket(size, crypt(cipher))
          message    <- decode(payload)(protobufDecoder(widenedCmp))
          mac        <- readSocket(ShannonCipher.BlockSize, bytes)
          _          <- Sync[F].delay(cipher.doFinal(mac.toArray))
        } yield message
      }

      override def reads(): Stream[F, GeneratedMessage] = Stream.repeatEval(read[GeneratedMessage]())

    }
  }
}
