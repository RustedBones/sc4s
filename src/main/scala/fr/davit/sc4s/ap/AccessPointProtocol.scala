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

import com.google.protobuf.ByteString
import com.spotify.authentication.*
import com.spotify.keyexchange.*
import com.spotify.mercury.MercuryHeader
import fr.davit.sc4s.security.DiffieHellman.*
import fr.davit.sc4s.security.{DiffieHellman, RSA, SHA1withRSA}
import scalapb.{GeneratedMessage, GeneratedMessageCompanion}
import scodec.bits.*
import scodec.codecs.*
import scodec.*

import scala.util.Random

object AccessPointProtocol:

  def protobufCodec[T <: GeneratedMessage](cmp: GeneratedMessageCompanion[T]): Codec[T] =
    bytes
      .xmap[Array[Byte]](_.toArray, ByteVector.apply)
      .xmap[T](cmp.parseFrom, cmp.toByteArray)

  val MessageSizeCodec: Codec[Int] = uint16

  private def messageCodec[T](codec: Codec[T]): Codec[T] =
    variableSizeBytes(MessageSizeCodec, codec)

  // format: off
  val AccessPointRequestEncoder: Encoder[AccessPointRequest] = {
    val mercuryCodec = messageCodec(Mercury.RawMercuryMessageCodec)
    discriminated[AccessPointRequest]
      .by(bytes(1))
      .typecase(hex"0xab", messageCodec(Authentication.AuthenticationRequestEncoder.encodeOnly))
      .typecase(hex"0x49", messageCodec(KeepAlive.PongEncoder.encodeOnly))
      .subcaseP(hex"0xb3") { case m: MercuryMessage if m.header.method.contains("SUB") => m }(mercuryCodec) // MercurySub
      .subcaseP(hex"0xb4") { case m: MercuryMessage if m.header.method.contains("UNSUB") => m }(mercuryCodec) // MercuryUnsub
      .subcaseP(hex"0xb2") { case m: MercuryMessage => m }(mercuryCodec) // MercuryReq
  }
  // format: on

  val AccessPointResponseDecoder: Decoder[AccessPointResponse] = discriminated[AccessPointResponse]
    .by(bytes(1))
    .typecase(hex"0xac", messageCodec(Authentication.AuthenticationSuccessDecoder.decodeOnly))
    .typecase(hex"0xad", messageCodec(Authentication.AuthenticationFailureDecoder.decodeOnly))
    .typecase(hex"0x04", messageCodec(KeepAlive.PingDecoder.decodeOnly))
    .typecase(hex"0x4a", messageCodec(KeepAlive.PingDecoder.decodeOnly))
    .typecase(hex"0x02", messageCodec(Session.SecretBockDecoder.decodeOnly))
    .typecase(hex"0x76", messageCodec(Session.LicenseVersionDecoder.decodeOnly))
    .typecase(hex"0x1b", messageCodec(Session.CountryCodeDecoder.decodeOnly))
    .typecase(hex"0x50", messageCodec(Session.ProductInfoDecoder.decodeOnly))
    .typecase(hex"0x69", messageCodec(Session.LegacyWelcomeDecoder.decodeOnly))
    .typecase(hex"0x1f", messageCodec(Session.UnknownDecoder.decodeOnly))
    .typecase(hex"0xb2", messageCodec(Mercury.RawMercuryMessageCodec)) // MercuryReq
    .typecase(hex"0xb3", messageCodec(Mercury.RawMercuryMessageCodec)) // MercurySub
    .typecase(hex"0xb4", messageCodec(Mercury.RawMercuryMessageCodec)) // MercuryUnsub
    .typecase(hex"0xb5", messageCodec(Mercury.RawMercuryMessageCodec)) // MercuryEvent

  object Handshake:

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

    val HeaderCodec: Codec[Int]     = uint32.xmap(_.toInt - 4, _ + 4L)
    val InitHeaderCodec: Codec[Int] = (constant(ByteVector(0, 4)) ~> HeaderCodec).xmap(_ - 2, _ + 2)

    implicit val HandshakeHelloEncoder: Encoder[HandshakeHello] =
      val payloadEncoder = protobufCodec(ClientHello)
        .contramap[HandshakeHello] { case HandshakeHello(publicKey) =>
          val info = BuildInfo.defaultInstance
            .withProduct(Product.PRODUCT_CLIENT)
            .withPlatform(Platform.PLATFORM_LINUX_X86)
            .addProductFlags(ProductFlags.PRODUCT_FLAG_NONE)
            .withVersion(115800820L)
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
      variableSizeBytes(InitHeaderCodec, payloadEncoder.encodeOnly)

    implicit val HandshakeResponseEncoder: Encoder[HandshakeResponse] =
      val payloadEncoder = protobufCodec(ClientResponsePlaintext)
        .contramap[HandshakeResponse] { case HandshakeResponse(response) =>
          val dhResponse = LoginCryptoDiffieHellmanResponse.defaultInstance
            .withHmac(ByteString.copyFrom(response))
          val login = LoginCryptoResponseUnion.defaultInstance
            .withDiffieHellman(dhResponse)
          ClientResponsePlaintext.defaultInstance
            .withLoginCryptoResponse(login)
        }
      variableSizeBytes(HeaderCodec, payloadEncoder.encodeOnly)

    implicit val HandshakeChallengeDecoder: Decoder[HandshakeChallenge] =
      val payloadDecoder = protobufCodec(APResponseMessage)
        .emap { apResponseMessage =>
          val challenge       = apResponseMessage.getChallenge.loginCryptoChallenge
          val serverKeyData   = challenge.getDiffieHellman.gs.toByteArray
          val serverSignature = challenge.getDiffieHellman.gsSignature.toByteArray
          val signatureKey    = RSA.generatePublicKey(Modulus, Exponent)
          if SHA1withRSA.verifySignature(signatureKey, serverKeyData, serverSignature) then
            val serverKey = DiffieHellman.generatePublicKey(BigInt(1, serverKeyData))
            Attempt.Successful(HandshakeChallenge(serverKey))
          else Attempt.Failure(Err("Failed signature check!"))
        }
      variableSizeBytes(HeaderCodec, payloadDecoder.decodeOnly)
  end Handshake

  object KeepAlive:
    val PongEncoder: Encoder[Pong] = bytes.as[Pong]
    val PingDecoder: Decoder[Ping] = bytes.as[Ping]

  object Authentication:

    val AuthenticationRequestEncoder: Encoder[AuthenticationRequest] = protobufCodec(ClientResponseEncrypted)
      .contramap[AuthenticationRequest] { case AuthenticationRequest(deviceId, username, tpe, data) =>
        val loginCredentials = LoginCredentials.defaultInstance
          .withUsername(username)
          .withTyp(tpe)
          .withAuthData(ByteString.copyFrom(data))

        val systemInfo = SystemInfo.defaultInstance
          .withOs(Os.OS_UNKNOWN)
          .withCpuFamily(CpuFamily.CPU_UNKNOWN)
          .withSystemInformationString("sc4s-0.1.0;Java 11;Linux")
          .withDeviceId(deviceId)

        ClientResponseEncrypted.defaultInstance
          .withLoginCredentials(loginCredentials)
          .withSystemInfo(systemInfo)
          .withVersionString("0.1.0")
      }

    val AuthenticationSuccessDecoder: Decoder[AuthenticationSuccess] = protobufCodec(APWelcome)
      .map(apWelcome => AuthenticationSuccess(apWelcome.canonicalUsername))

    val AuthenticationFailureDecoder: Decoder[AuthenticationFailure] = protobufCodec(APLoginFailed)
      .map(apLoginFailed => AuthenticationFailure(apLoginFailed.errorCode))
  end Authentication

  object Session:
    val SecretBockDecoder: Decoder[SecretBlock]        = bytes.as[SecretBlock]
    val LicenseVersionDecoder: Decoder[LicenseVersion] = (int16 :: utf8).as[LicenseVersion]
    val CountryCodeDecoder: Decoder[CountryCode]       = utf8.as[CountryCode]
    val ProductInfoDecoder: Decoder[ProductInfo]       = utf8.as[ProductInfo]
    val LegacyWelcomeDecoder: Decoder[LegacyWelcome]   = bytes.as[LegacyWelcome]
    val UnknownDecoder: Decoder[Unknown]               = bytes.as[Unknown]

  object Mercury:
    //    private val KeyMasterClientId = "65b708073fc0480ea92a077233ca87bd"

    private def mercuryPayloadCodec(size: Int): Codec[Vector[ByteVector]] =
      vectorOfN(provide(size), variableSizeBytes(uint16, bytes))

    private val MercuryHeaderCodec: Codec[MercuryHeader] =
      variableSizeBytes(uint16, protobufCodec(MercuryHeader))

    val SequenceIdCodec: Codec[Long] = uint16.consume { size =>
      require(size == 2 || size == 4 || size == 8, s"expected sequence of 2, 4 or 8 bytes, got $size")
      long(size * 8)
    } { value =>
      if value < Short.MaxValue then 2
      else if value < Int.MaxValue then 4
      else 8
    }

    val RawMercuryMessageCodec: Codec[MercuryMessage] =
      (
        ("sequenceId" | SequenceIdCodec) ::
          ("flag" | constant(ByteVector.fromByte(1))) :: // TODO
          ("parts" | uint16).consume { size =>
            // 1st part is the header, rest is payload
            ("header" | MercuryHeaderCodec) :: ("payload" | mercuryPayloadCodec(size - 1))
          } { case (_, payload) =>
            // 1st part is the header, rest is payload
            1 + payload.size
          }
      ).dropUnits.as[MercuryMessage]

end AccessPointProtocol
