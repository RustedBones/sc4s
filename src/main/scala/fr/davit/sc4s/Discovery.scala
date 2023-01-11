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

import cats.effect
import cats.effect.*
import cats.effect.std.Hotswap
import cats.implicits.*
import fr.davit.sc4s.ap.{AccessPoint, Session}
import com.spotify.authentication.AuthenticationType
import fr.davit.sc4s.security.*
import fr.davit.sc4s.security.DiffieHellman.*
import io.circe.literal.*
import org.http4s.*
import org.http4s.client.Client
import org.http4s.circe.*
import org.http4s.dsl.Http4sDsl
import org.http4s.dsl.impl.QueryParamDecoderMatcher
import scodec.Attempt.{Failure, Successful}
import scodec.Err
import scodec.bits.*
import scodec.codecs.*

import java.net.InetSocketAddress
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
      authData <- bytes(dataSize).map(_.toArray)
    yield Credentials(tpe, authData)

  private def decryptBlob[F[_]: Sync](
      privateKey: DHPrivateKey,
      publicKey: DHPublicKey,
      iv: IvParameterSpec,
      checksum: Array[Byte],
      data: Array[Byte]
  ): F[Array[Byte]] = Sync[F].delay {
    val secret       = DiffieHellman.secret(privateKey, publicKey)
    val secretHash   = Sha1.digest(secret)
    val secretKey    = new SecretKeySpec(secretHash, 0, 16, HmacSHA1.Algorithm)
    val checksumHash = HmacSHA1.digest(secretKey, "checksum".getBytes)
    val checksumKey  = new SecretKeySpec(checksumHash, HmacSHA1.Algorithm)
    val mac          = HmacSHA1.digest(checksumKey, data)
    if !mac.sameElements(checksum) then throw new DigestException("Checksum verification failed")
    val encryptionHash = HmacSHA1.digest(secretKey, "encryption".getBytes)
    val encryptionKey  = new SecretKeySpec(encryptionHash, 0, 16, AES.Algorithm)
    AES.decrypt(AES.CTR, AES.NoPadding, encryptionKey, iv, data)
  }

  private def decryptCredentials[F[_]: Sync](
      deviceId: String,
      userName: String,
      blob: Array[Byte]
  ): F[Credentials] = Sync[F].delay {
    val data            = Base64.getDecoder.decode(blob)
    val password        = Sha1.digest(deviceId.getBytes)
    val baseKey         = PBKDF2HmacWithSHA1.generateSecretKey(password, userName.getBytes, 0x100, 20)
    val keyHash         = Sha1.digest(baseKey.getEncoded)
    val keyBytes        = ByteVector.view(keyHash) ++ ByteVector.fromInt(keyHash.length)
    val key             = new SecretKeySpec(keyBytes.toArray, AES.Algorithm)
    val decrypted       = ByteVector.view(AES.decrypt(AES.ECB, AES.NoPadding, key, data))
    val credentialsData = decrypted xor (ByteVector.low(16) ++ decrypted)
    credentialsDecoder.decode(credentialsData.toBitVector).require.value
  }

  def service[F[_]: Async](
      client: Client[F],
      sessionHS: Hotswap[F, Session],
      sessionR: Ref[F, Session],
      deviceId: String,
      privateKey: DHPrivateKey,
      publicKey: DHPublicKey
  ): HttpRoutes[F] =
    val dsl = Http4sDsl[F]
    import dsl.*
    HttpRoutes
      .of[F] {
        case GET -> Root :? ActionParam("getInfo") =>
          val result = for
            session <- sessionR.get
            userName = session match
              case Session.Connected(u) => Some(u)
              case Session.Idle         => None
          yield json"""{
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
              "deviceType": "COMPUTER",
              "activeUser": $userName
            }"""
          Ok(result)
        case request @ POST -> Root =>
          request
            .decode { (addUser: AddUser) =>
              val result = for
                session <- sessionR.get
                _ <- session match
                  case Session.Connected(addUser.userName) => Sync[F].unit
                  case _ =>
                    for
                      blob <- decryptBlob(
                        privateKey,
                        addUser.clientKey,
                        addUser.iv,
                        addUser.checksum,
                        addUser.encrypted
                      )
                      credentials <- decryptCredentials(
                        deviceId,
                        addUser.userName,
                        blob
                      )
                      apAddress <- AccessPoint.resolve(client)
                      _         <- Sync[F].delay(println(s"Connecting to $apAddress"))
                      newSession <- sessionHS.swap(
                        AccessPoint.connect(
                          apAddress,
                          addUser.userName,
                          deviceId,
                          credentials.tpe,
                          credentials.authData
                        )
                      )
                      _ <- sessionR.set(newSession)
                    yield ()
              yield json"""{
                  "status": 200,
                  "statusString": "OK",
                  "spotifyError": 0
                }"""
              Ok(result)
            }
            .handleErrorWith { e =>
              val result = for
                _ <- Sync[F].delay(e.printStackTrace())
                _ <- sessionHS.swap(Resource.pure(Session.Idle)).flatMap(sessionR.set)
              yield e.getMessage
              InternalServerError(result)
            }
      }
