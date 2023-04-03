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
import cats.effect.std.{Hotswap, Mutex}
import cats.effect.implicits.*
import cats.implicits.*
import com.comcast.ip4s.Literals.ipv4
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
import org.http4s.ember.server.EmberServerBuilder
import org.http4s.server.Server
import org.http4s.server.Router
import com.comcast.ip4s.*
import org.http4s.ember.client.EmberClientBuilder
import org.typelevel.log4cats.LoggerFactory
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

  implicit private def addUserEntityDecoder[F[_]](implicit F: Async[F]): EntityDecoder[F, AddUser] =
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
              DecodeResult.success(F.delay(Base64.getDecoder.decode(blobStr)))
            case _ =>
              DecodeResult.failureT[F, Array[Byte]](InvalidMessageBodyFailure("Missing blob", None))
          clientKey <- form.getFirst("clientKey") match
            case Some(keyStr) if keyStr.nonEmpty =>
              val key = for
                y <- F.delay(BigInt(1, Base64.getDecoder.decode(keyStr)))
                k <- F.delay(DiffieHellman.generatePublicKey(y))
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

  private def decryptBlob[F[_]](
      privateKey: DHPrivateKey,
      publicKey: DHPublicKey,
      iv: IvParameterSpec,
      checksum: Array[Byte],
      data: Array[Byte]
  )(implicit F: Sync[F]): F[Array[Byte]] = F.delay {
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

  private def decryptCredentials[F[_]](
      deviceId: String,
      userName: String,
      blob: Array[Byte]
  )(implicit F: Sync[F]): F[Credentials] = F.delay {
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

  def discovery[F[_]: LoggerFactory](
      deviceId: String,
      path: String,
      client: Client[F],
      sessionHotSwap: Hotswap[F, Session]
  )(implicit F: Async[F]): F[HttpApp[F]] =
    for
      keys <- F.delay(DiffieHellman.generateKeyPair())
      (privateKey, publicKey) = keys
      mutex       <- Mutex[F]
      sessionInit <- sessionHotSwap.swap(Resource.pure(Session.Idle))
      sessionRef  <- Ref.of[F, Session](sessionInit)
    yield
      val dsl = Http4sDsl[F]
      import dsl.*
      val routes = HttpRoutes.of[F] {
        case GET -> Root :? ActionParam("getInfo") =>
          val result = sessionRef.get
            .map {
              case Session.Connected(u) => Some(u)
              case Session.Idle         => None
            }
            .map { userName =>
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
              "deviceType": "COMPUTER",
              "activeUser": $userName
            }"""
            }
          Ok(result)
        case request @ POST -> Root =>
          mutex.lock.surround {
            request
              .decode { (addUser: AddUser) =>
                val result = for
                  session <- sessionRef.get
                  _ <- session match
                    case Session.Connected(addUser.userName) => F.unit
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
                        newSession <- sessionHotSwap.swap(
                          AccessPoint.connect(
                            client,
                            deviceId,
                            addUser.userName,
                            credentials.tpe,
                            credentials.authData
                          )
                        )
                        _ <- sessionRef.set(newSession)
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
                  _ <- F.delay(e.printStackTrace())
                  _ <- sessionHotSwap.swap(Resource.pure(Session.Idle)).flatMap(sessionRef.set)
                yield e.getMessage
                InternalServerError(result)
              }
          }
      }

      Router(path -> routes).orNotFound
  end discovery

  def service[F[_]: Concurrent: LoggerFactory](
      deviceId: String,
      path: String,
      host: Host,
      port: Port
  )(implicit F: Async[F]): Resource[F, Server] = for
    client         <- EmberClientBuilder.default[F].build
    sessionHotSwap <- Hotswap.create[F, Session]
    app            <- Resource.eval(discovery(deviceId, path, client, sessionHotSwap))
    server <- EmberServerBuilder
      .default[F]
      .withHost(host)
      .withPort(port)
      .withMaxConnections(1) // serve only one client at a time
      .withHttpApp(app)
      .build
  yield server
