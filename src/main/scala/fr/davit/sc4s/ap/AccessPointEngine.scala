package fr.davit.sc4s.ap

import cats.effect._
import cats.implicits._
import com.google.protobuf.ByteString
import com.spotify.authentication.ClientResponseEncrypted
import com.spotify.keyexchange.{BuildInfo => ApBuildInfo, _}
import fr.davit.sc4s.security._
import fs2._
import fs2.io.tcp.Socket
import scalapb.{GeneratedMessage, GeneratedMessageCompanion}
import scodec._
import scodec.bits._
import scodec.codecs._

import java.security.Key
import javax.crypto.interfaces.DHPublicKey
import javax.crypto.spec.SecretKeySpec
import scala.concurrent.duration.FiniteDuration
import scala.util.Random

trait AccessPointEngine[F[_]] {

  def write[T <: GeneratedMessage: GeneratedMessageCompanion](message: T): F[Unit]

  def read[T <: GeneratedMessage: GeneratedMessageCompanion](): F[T]

}

object AccessPointEngine {

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

  implicit def protobufCodec[T <: GeneratedMessage](implicit cmp: GeneratedMessageCompanion[T]): Codec[T] =
    bytes
      .xmap[Array[Byte]](_.toArray, ByteVector.apply)
      .xmap[T](cmp.parseFrom, _.toByteArray)
      .complete

  def codeCodec[T <: GeneratedMessage](implicit cmp: GeneratedMessageCompanion[T]): Codec[Unit] = cmp match {
    case ClientResponseEncrypted => constant(hex"ab")
  }

  def apply[F[_]: Sync](
      socket: Socket[F],
      timeout: Option[FiniteDuration] = None
  ): Resource[F, AccessPointEngine[F]] = {

    def hello(publicKey: DHPublicKey): ClientHello = {
      val info = ApBuildInfo.defaultInstance
        .withProduct(Product.PRODUCT_PARTNER)
        .withPlatform(Platform.PLATFORM_LINUX_X86)
        .withVersion(109800078L)

      val dhHello = LoginCryptoDiffieHellmanHello.defaultInstance
        .withGc(ByteString.copyFrom(publicKey.getY.toByteArray))
        .withServerKeysKnown(1)
      val login = LoginCryptoHelloUnion.defaultInstance
        .withDiffieHellman(dhHello)

      ClientHello.defaultInstance
        .withBuildInfo(info)
        .withCryptosuitesSupported(Seq(Cryptosuite.CRYPTO_SUITE_SHANNON))
        .withLoginCryptoHello(login)
        .withClientNonce(ByteString.copyFrom(Random.nextBytes(16)))
        .withPadding(ByteString.copyFrom(Array(30.toByte)))
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

    def writePayload(headerSize: Int, headerEncoder: Encoder[Int], payload: ByteVector): F[Unit] =
      for {
        header <- encode(headerSize)(headerEncoder)
        _      <- socket.write(Chunk.byteVector(header ++ payload))
      } yield ()

    def readPayload[T](headerSize: Int, headerDecoder: Decoder[Int]): F[ByteVector] =
      for {
        header  <- socket.readN(headerSize, timeout)
        size    <- decode(header.get.toByteVector)(headerDecoder)
        payload <- socket.readN(size, timeout)
      } yield payload.get.toByteVector

    def handshake(): F[(Key, Key)] = {

      val initHeaderCodec: Codec[Int] = (constant(ByteVector(0, 4)) ~> int32).xmap(_ + 6, _ - 6)
      val headerCodec: Codec[Int]     = int32.xmap(_ + 4, _ - 4)

      for {
        keyPair <- DiffieHellman.generateKeyPair[F]()
        (_, pub) = keyPair
        clientHelloPayload       <- encode(hello(pub))
        _                        <- writePayload(6, initHeaderCodec, clientHelloPayload)
        apResponseMessagePayload <- readPayload(4, headerCodec)
        apResponseMessage        <- decode(apResponseMessagePayload)(protobufCodec[APResponseMessage])
        challenge       = apResponseMessage.getChallenge.loginCryptoChallenge
        secret          = challenge.getDiffieHellman.gs.toByteArray
        secretSignature = challenge.getDiffieHellman.gsSignature.toByteArray
        serverKey <- RSA.generatePublicKey(Modulus, Exponent)
        _         <- SHA1withRSA.verifySignature(serverKey, secret, secretSignature)
        sharedKey = new SecretKeySpec(secret, HmacSHA1.Algorithm)
        data <- (1 to 5).toList
          .traverse { i =>
            val chunk = clientHelloPayload ++ apResponseMessagePayload ++ ByteVector(i.toByte)
            HmacSHA1.digest(sharedKey, chunk.toArray)
          }
          .map(_.reduce(_ ++ _))
        secretKey = new SecretKeySpec(data, 0, 20, HmacSHA1.Algorithm)
        encodeKey = new SecretKeySpec(data, 20, 32, Shannon.Algorithm)
        decodeKey = new SecretKeySpec(data, 20 + 32, 32, Shannon.Algorithm)
        answer                <- HmacSHA1.digest(secretKey, (clientHelloPayload ++ apResponseMessagePayload).toArray)
        clientResponsePayload <- encode(challengeResponse(answer))
        _                     <- writePayload(4, headerCodec, clientResponsePayload)
        _                     <- readPayload(4, headerCodec)
      } yield (encodeKey, decodeKey)
    }

    for {
      keys <- Resource.liftF(handshake())
      (encodeKey, decodeKey) = keys
      encryptCipher <- Shannon.encryptCipher(encodeKey)
      decryptCipher <- Shannon.decryptCipher(decodeKey)
    } yield new AccessPointEngine[F] {

      def crypt(doFinal: Boolean = true): Codec[ByteVector] = {
        val encryption: Array[Byte] => Array[Byte] = if (doFinal) encryptCipher.doFinal else encryptCipher.update
        val decryption: Array[Byte] => Array[Byte] = if (doFinal) decryptCipher.doFinal else decryptCipher.update
        bytes
          .xmap[Array[Byte]](_.toArray, ByteVector.apply)
          .xmap[Array[Byte]](decryption, encryption)
          .xmap[ByteVector](ByteVector.apply, _.toArray)
      }

      override def write[T <: GeneratedMessage: GeneratedMessageCompanion](message: T): F[Unit] = {
        val headerEncoder = crypt(false).asEncoder
          .contramap[BitVector](_.toByteVector)
          .econtramap((codeCodec[T] ~> int16).encode)
        for {
          payload   <- encode(message)
          encrypted <- encode(payload)(crypt())
          _         <- writePayload(3, headerEncoder, encrypted)
        } yield ()
      }

      override def read[T <: GeneratedMessage]()(implicit cmp: GeneratedMessageCompanion[T]): F[T] = {
        val headerDecoder = crypt(false).asDecoder
          .map[BitVector](_.toBitVector)
          .emap((codeCodec[T] ~> int16).decode)
          .map(_.value)
        for {
          encrypted <- readPayload(3, headerDecoder)
          payload   <- decode(encrypted)(crypt())
          message   <- decode(payload)
        } yield message
      }
    }
  }
}
