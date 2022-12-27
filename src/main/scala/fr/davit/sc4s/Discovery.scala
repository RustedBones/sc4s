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

package fr.davit.sc4s

import cats.effect.*
import cats.implicits.*
import fr.davit.sc4s.ap.AccessPoint
import fr.davit.sc4s.ap.authentication.AuthenticationType
import fr.davit.sc4s.security.*
import fr.davit.sc4s.security.DiffieHellman.*
import io.circe.literal.*
import org.http4s.*
import org.http4s.circe.*
import org.http4s.dsl.Http4sDsl
import org.http4s.dsl.impl.QueryParamDecoderMatcher
import scodec.Attempt.{Failure, Successful}
import scodec.Err
import scodec.bits.*
import scodec.codecs.*

import java.security.DigestException
import java.util.Base64
import javax.crypto.interfaces.{DHPrivateKey, DHPublicKey}
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}

object Discovery:

  private object ActionParam extends QueryParamDecoderMatcher[String]("action")

  private case class AddUser(userName: String, blob: Array[Byte], clientKey: DHPublicKey):
    lazy val iv: IvParameterSpec    = new IvParameterSpec(blob.take(16))
    lazy val encrypted: Array[Byte] = blob.slice(16, blob.length - 20)
    lazy val checksum: Array[Byte]  = blob.takeRight(20)

  private case class Credentials(tpe: AuthenticationType.Recognized, authData: Array[Byte])

  implicit private def addUserEntityDecoder[F[_]: Async]: EntityDecoder[F, AddUser] =
    UrlForm
      .entityDecoder[F]
      .flatMapR { form =>
        for
          _ <- form.getFirst("action") match
            case Some("addUser") =>
              DecodeResult.successT[F, Unit](())
            case Some(action) =>
              DecodeResult.failureT[F, Unit](InvalidMessageBodyFailure(s"Unsupported action $action", None))
            case None =>
              DecodeResult.failureT[F, Unit](InvalidMessageBodyFailure("Missing action", None))
          userName <- form.getFirst("userName") match
            case Some(userName) =>
              DecodeResult.successT[F, String](userName)
            case None =>
              DecodeResult.failureT[F, String](InvalidMessageBodyFailure("Missing userName", None))
          blob <- form.getFirst("blob") match
            case Some(blobStr) if blobStr.nonEmpty =>
              DecodeResult.success(Sync[F].delay(Base64.getDecoder.decode(blobStr)))
            case _ =>
              DecodeResult.failureT[F, Array[Byte]](InvalidMessageBodyFailure("Missing blob", None))
          clientKey <- form.getFirst("clientKey") match
            case Some(keyStr) if keyStr.nonEmpty =>
              val key = for
                y <- Sync[F].delay(BigInt(1, Base64.getDecoder.decode(keyStr)))
                k <- Sync[F].delay(DiffieHellman.generatePublicKey(y))
              yield k
              DecodeResult.success(key)
            case _ =>
              DecodeResult.failureT[F, DHPublicKey](InvalidMessageBodyFailure("Missing clientKey", None))
        yield AddUser(userName, blob, clientKey)
      }

  val vuint2L: scodec.Codec[Int] =
    (for
      msb <- bool
      l   <- uint(7)
      h   <- if msb then uint(8) else provide(0)
    yield h << 7 | l).decodeOnly

  private val credentialsDecoder: scodec.Decoder[Credentials] =
    for
      _          <- ignore(8L)
      ignoreSize <- vuint2L
      _          <- ignore(ignoreSize * 8L)
      _          <- ignore(8L)
      tpe <- vuint2L.map(AuthenticationType.fromValue).emap {
        case t: AuthenticationType.Recognized      => Successful(t)
        case AuthenticationType.Unrecognized(code) => Failure(Err(s"Unrecognized AuthenticationType: $code"))
      }
      _        <- ignore(8L)
      dataSize <- vuint2L
      authData <- bytes(dataSize.toInt).map(_.toArray)
    yield Credentials(tpe, authData)

  private def decryptBlob[F[_]: Sync](deviceId: String, userName: String, blob: Array[Byte]): F[Credentials] =
    for
      data     <- Sync[F].delay(Base64.getDecoder.decode(blob))
      password <- Sync[F].delay(Sha1.digest(deviceId.getBytes))
      baseKey  <- Sync[F].delay(PBKDF2HmacWithSHA1.generateSecretKey(password, userName.getBytes, 0x100, 20))
      keyHash  <- Sync[F].delay(Sha1.digest(baseKey.getEncoded))
      keyBytes = ByteVector.view(keyHash) ++ ByteVector.fromInt(keyHash.length)
      key      = new SecretKeySpec(keyBytes.toArray, AES.Algorithm)
      decrypted <- Sync[F].delay(ByteVector.view(AES.decrypt(AES.ECB, AES.NoPadding, key, data)))
      credentialsData = decrypted xor (ByteVector.low(16) ++ decrypted)
      credentials <- Sync[F].delay(credentialsDecoder.decode(credentialsData.toBitVector).require.value)
    yield credentials

  def service[F[_]: Async](
      session: Ref[F, Option[Session[F]]],
      ap: AccessPoint[F],
      deviceId: String,
      privateKey: DHPrivateKey,
      publicKey: DHPublicKey
  ): HttpRoutes[F] =
    val dsl = Http4sDsl[F]
    import dsl.*
    HttpRoutes
      .of[F] {
        case GET -> Root :? ActionParam("getInfo") =>
          val result = session.get
            .map { s =>
              json"""{
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
                "publicKey": ${Base64.getEncoder.encodeToString(publicKey.getBytes)},
                "deviceType": "Unknown",
                "activeUser": ${s.map(_.userName)}
              }"""
            }
          Ok(result)
        case request @ POST -> Root =>
          request
            .decode { (addUser: AddUser) =>
              val result = session.get
                .flatMap {
                  case Some(activeSession) if activeSession.userName == addUser.userName =>
                    Sync[F].pure(
                      json"""{
                         "status": 200,
                         "statusString": "OK",
                         "spotifyError": 0
                       }"""
                    )
                  case activeSession =>
                    for
                      secret     <- Sync[F].delay(DiffieHellman.secret(privateKey, addUser.clientKey))
                      secretHash <- Sync[F].delay(Sha1.digest(secret))
                      secretKey = new SecretKeySpec(secretHash, 0, 16, HmacSHA1.Algorithm)
                      checksum <- Sync[F].delay(HmacSHA1.digest(secretKey, "checksum".getBytes))
                      checksumKey = new SecretKeySpec(checksum, HmacSHA1.Algorithm)
                      mac <- Sync[F].delay(HmacSHA1.digest(checksumKey, addUser.encrypted))
                      _ <-
                        if mac sameElements addUser.checksum then Sync[F].unit
                        else Sync[F].raiseError(new DigestException("Checksum verification failed"))
                      encryptionKeyHash <- Sync[F].delay(HmacSHA1.digest(secretKey, "encryption".getBytes))
                      encryptionKey = new SecretKeySpec(encryptionKeyHash, 0, 16, AES.Algorithm)
                      blob <- Sync[F].delay(
                        AES.decrypt(AES.CTR, AES.NoPadding, encryptionKey, addUser.iv, addUser.encrypted)
                      )
                      credentials <- decryptBlob(deviceId, addUser.userName, blob)
                      //                      token <- ap.requestToken(deviceId, Seq("playlist-read"))
                      //                      _     <- Sync[F].delay(println(token))
                      //                      _     <- session.set(Session.Connected(addUser.userName))
                      _ <- activeSession.map(_.close()).getOrElse(Sync[F].unit)
                      s <- ap.authenticate(
                        deviceId,
                        addUser.userName,
                        credentials.tpe,
                        credentials.authData,
                        e => Sync[F].delay(e.printStackTrace()).flatMap(_ => session.set(None))
                      )
                      _ <- session.set(Some(s))
                    yield json"""{
                      "status": 200,
                      "statusString": "OK",
                      "spotifyError": 0
                    }"""
                }
              Ok(result)
            }
            .handleErrorWith { e =>
              val result = for
                _ <- Sync[F].delay(e.printStackTrace())
                _ <- session.set(None)
              yield e.getMessage
              InternalServerError(result)
            }
      }
