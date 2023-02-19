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

import cats.effect.*
import cats.effect.implicits.*
import cats.effect.std.Queue
import cats.implicits.*
import com.comcast.ip4s.{IpAddress, SocketAddress}
import com.spotify.authentication.*
import com.spotify.keyexchange.ErrorCode
import fr.davit.sc4s.Mercury
import fr.davit.sc4s.TokenProvider
import fs2.io.net.Network
import fs2.Stream
import fs2.concurrent.Topic
import io.circe.*
import org.http4s.*
import org.http4s.circe.*
import org.http4s.implicits.*
import org.http4s.client.Client
import org.http4s.client.websocket.{WSClient, WSConnectionHighLevel, WSRequest}
import org.http4s.implicits.uri
import org.http4s.jdkhttpclient.JdkWSClient
import scalapb.GeneratedMessage

import java.net.InetSocketAddress
import java.net.http.HttpClient
import scala.util.Random

enum ResourceType(val value: String):
  case AccessPoint extends ResourceType("accesspoint")
  case Dealer      extends ResourceType("dealer")

enum Session:
  case Idle
  case Connected(userName: String)

object AccessPoint:

  type Message = AccessPointMessage with GeneratedMessage

  class LoginException(code: ErrorCode) extends Exception(code.name)

  private val DefaultAp: InetSocketAddress = new InetSocketAddress("ap.spotify.com", 443)

  private case class ApResolve(apList: List[InetSocketAddress])

  implicit private val InetSocketAddressDecoder: Decoder[InetSocketAddress] = Decoder.decodeString
    .map(_.split(':'))
    .map {
      case Array(host, port) => new InetSocketAddress(host, port.toInt)
      case _                 => throw new Exception("Failed extraction socket address")
    }

  implicit private val ApResolveDecoder: Decoder[ApResolve] =
    Decoder(_.downField("accesspoint").as[List[InetSocketAddress]].map(ApResolve.apply))

  implicit private def apResolveEntityDecoder[F[_]: Concurrent]: EntityDecoder[F, ApResolve] =
    jsonOf[F, ApResolve]

  def resolve[F[_]: Async](client: Client[F], resourceType: ResourceType): F[InetSocketAddress] =
    client
      .expect[ApResolve](uri"http://apresolve.spotify.com".withQueryParam("type", resourceType.value))
      .map(_.apList)
      .map(Random.shuffle(_))
      .map(_.headOption.getOrElse(DefaultAp))
      .orElse(Sync[F].pure(DefaultAp))

  def connect[F[_]: Spawn: Async](
      client: Client[F],
      deviceId: String,
      userName: String,
      tpe: AuthenticationType.Recognized,
      authData: Array[Byte]
  ): Resource[F, Session] =
    val login = AuthenticationRequest(deviceId, userName, tpe, authData)
    for
      address <- Resource.eval(resolve(client, ResourceType.AccessPoint))
      _       <- Resource.eval(Sync[F].delay(println(s"Connecting to $address")))
      socket  <- Network[F].client(SocketAddress.fromInetSocketAddress(address))
      ap      <- AccessPointSocket.client(socket)
      // login
      _        <- Resource.eval(ap.write(login)(AccessPointProtocol.AccessPointRequestEncoder))
      response <- Resource.eval(ap.read()(AccessPointProtocol.AccessPointResponseDecoder))
      io <- Resource.eval {
        response match
          case _: AuthenticationSuccess =>
            for
              queue <- Queue.bounded[F, AccessPointRequest](60)
              topic <- Topic[F, AccessPointResponse]
            yield (queue, topic)
          case failure: AuthenticationFailure =>
            Sync[F].raiseError(new LoginException(failure.code))
          case response =>
            Sync[F].raiseError(new Exception(s"Unexpected response $response"))
      }
      (out, in) = io
      // write loop
      _ <- Stream
        .fromQueueUnterminated(out)
        .through(ap.writes())
        .compile
        .drain
        .background
      // read loop
      _ <- ap
        .reads()
        .through(in.publish)
        .compile
        .drain
        .background
      mercury <- Mercury.client[F](out, in)
      tokenProvider = TokenProvider(deviceId, mercury)
      _       <- dealer(client, tokenProvider)
    yield Session.Connected(userName)
  end connect

  def dealer[F[_]: Async](
      client: Client[F],
      tokenProvider: TokenProvider[F]
  ): Resource[F, WSConnectionHighLevel[F]] =
    for
      address <- Resource.eval(resolve(client, ResourceType.Dealer))
      token   <- Resource.eval(tokenProvider.getToken(Seq("playlist-read")))
      scheme    = scheme"wss"
      host      = Uri.Host.fromIpAddress(IpAddress.fromInetAddress(address.getAddress))
      port      = address.getPort
      authority = Uri.Authority(host = host, port = Some(port))
      uri       = Uri(scheme = Some(scheme), authority = Some(authority)).withQueryParam("access_token", token.value)
      wsClient <- Resource.eval(Sync[F].delay(JdkWSClient(HttpClient.newHttpClient())))
      ws       <- wsClient.connectHighLevel(WSRequest(uri))
    yield ws
