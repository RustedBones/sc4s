package fr.davit.sc4s

import cats.effect.IO
import cats.implicits._
import com.google.protobuf.ByteString
import com.spotify.authentication.{AuthenticationType, LoginCredentials}
import fr.davit.sc4s.ap.AccessPoint
import fr.davit.sc4s.security.{AES, DiffieHellman, HmacSHA1, PBKDF2HmacWithSHA1, Sha1}
import io.circe.literal._
import org.http4s._
import org.http4s.circe._
import org.http4s.dsl.io._
import scodec.Decoder
import scodec.bits._
import scodec.codecs._

import java.security.DigestException
import java.security.spec.InvalidKeySpecException
import java.util.Base64
import javax.crypto.interfaces.{DHPrivateKey, DHPublicKey}
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}

object Discovery {

  private object ActionParam extends QueryParamDecoderMatcher[String]("action")

  private case class AddUser(userName: String, blob: Array[Byte], clientKey: DHPublicKey) {
    lazy val iv: IvParameterSpec    = new IvParameterSpec(blob.take(16))
    lazy val encrypted: Array[Byte] = blob.drop(16).dropRight(20)
    lazy val checksum: Array[Byte]  = blob.takeRight(20)
  }

  implicit private val AddUserEntityDecoder: EntityDecoder[IO, AddUser] =
    UrlForm
      .entityDecoder[IO]
      .flatMapR { form =>
        val result = for {
          _ <- form.getFirst("action") match {
            case Some("addUser") => IO.unit
            case Some(action)    => IO.raiseError(InvalidMessageBodyFailure(s"Unsupported action $action", None))
            case None            => IO.raiseError(InvalidMessageBodyFailure("Missing action", None))
          }
          userName <- form.getFirst("userName") match {
            case Some(userName) => IO.pure(userName)
            case None           => IO.raiseError(InvalidMessageBodyFailure("Missing userName", None))
          }
          blob <- form.getFirst("blob") match {
            case Some(blobStr) => IO(Base64.getDecoder.decode(blobStr))
            case None          => IO.raiseError(InvalidMessageBodyFailure("Missing blob", None))
          }
          y <- form.getFirst("clientKey") match {
            case Some(blobStr) => IO(BigInt(1, Base64.getDecoder.decode(blobStr)))
            case None          => IO.raiseError(InvalidMessageBodyFailure("Missing clientKey", None))
          }
          clientKey <- DiffieHellman.generatePublicKey[IO](y)
        } yield AddUser(userName, blob, clientKey).asRight[DecodeFailure]

        DecodeResult(result.recover {
          case e: DecodeFailure            => Left(e)
          case e: IllegalArgumentException => Left(InvalidMessageBodyFailure(e.getMessage, Some(e)))
          case e: InvalidKeySpecException  => Left(InvalidMessageBodyFailure(e.getMessage, Some(e)))
        })
      }

  private val StopBytes: ByteVector = ByteVector.fromInt(4, 20)

  private val LoginCredentialsDecoder: Decoder[LoginCredentials] = for {
    _        <- ignore(8)
    _        <- variableSizeBytes(vintL, bits)
    _        <- ignore(8)
    typ      <- vintL
    _        <- ignore(8)
    dataSize <- vintL
    data     <- bytes(dataSize)
  } yield LoginCredentials.defaultInstance
    .withTyp(AuthenticationType.fromValue(typ))
    .withAuthData(ByteString.copyFrom(data.toArray))

  private def decryptBlob(deviceId: String, userName: String, blob: Array[Byte]): IO[LoginCredentials] = {
    for {
      data      <- IO(Base64.getDecoder.decode(blob))
      key       <- PBKDF2HmacWithSHA1.generateSecretKey[IO](deviceId, userName.getBytes, 20)
      decrypted <- AES.decrypt[IO](AES.ECB, AES.NoPadding, key, data).map(ByteVector.apply)
      (l, h) = (decrypted ++ StopBytes).splitAt(decrypted.length / 2)
      credentials <- IO(LoginCredentialsDecoder.decode((l xor h).toBitVector).require.value)
    } yield credentials
  }

  def service(
      ap: AccessPoint[IO],
      deviceId: String,
      privateKey: DHPrivateKey,
      publicKey: DHPublicKey
  ): HttpRoutes[IO] = {
    HttpRoutes
      .of[IO] {
        case GET -> Root :? ActionParam("getInfo") =>
          Ok(json"""{
             "status": 101,
             "statusString": "OK",
             "spotifyError": 0,
             "version": "2.7.1",
             "libraryVersion": "0.1.0",
             "accountReq": "PREMIUM",
             "brandDisplayName": "sc4s",
             "modelDisplayName": "sc4s",
             "voiceSupport": "NO",
             "availability": "",
             "productID": 0,
             "tokenType": "default",
             "groupStatus": "NONE",
             "resolverVersion": "0",
             "scope": "streaming,client-authorization-universal",
             "deviceID": $deviceId,
             "remoteName": "sc4s",
             "publicKey": ${Base64.getEncoder.encodeToString(publicKey.getY.toByteArray)},
             "deviceType": "Unknown",
             "activeUser": ""
           }""")
        case request @ POST -> Root =>
          request.decode[AddUser] { addUser =>
            val result = for {
              secret <- DiffieHellman.secret[IO](privateKey, addUser.clientKey)
              sha    <- Sha1.digest[IO](secret)
              secretKey = new SecretKeySpec(sha, 0, 16, HmacSHA1.Algorithm)
              checksum <- HmacSHA1.digest[IO](secretKey, "checksum".getBytes)
              checksumKey = new SecretKeySpec(checksum, HmacSHA1.Algorithm)
              mac <- HmacSHA1.digest[IO](checksumKey, addUser.encrypted)
              _ <- if (mac sameElements addUser.checksum) {
                IO.unit
              } else {
                IO.raiseError(new DigestException("Checksum verrification failed"))
              }
              encryptionKey <- HmacSHA1
                .digest[IO](secretKey, "encryption".getBytes)
                .map(new SecretKeySpec(_, 0, 16, AES.Algorithm))
              blob        <- AES.decrypt[IO](AES.CTR, AES.NoPadding, encryptionKey, addUser.iv, addUser.encrypted)
              credentials <- decryptBlob(deviceId, addUser.userName, blob)
              _           <- IO(println("success"))
              _           <- ap.authenticate(deviceId, credentials)
            } yield json"""{
                     "status": 101,
                     "statusString": "OK",
                     "spotifyError": 0
                   }"""

            Ok(result).handleErrorWith {
              case e: DigestException =>
                BadRequest(
                  json"""{
                   "status": 400,
                   "statusString": "ERROR",
                   "spotifyError": 0
                 }"""
                ).flatTap(_ => IO(e.printStackTrace()))
              case e =>
                InternalServerError(e.getMessage)
                  .flatTap(_ => IO(e.printStackTrace()))
            }
          }
      }
  }
}
