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

import cats.Show
import cats.effect.*
import cats.effect.implicits.*
import cats.effect.std.Queue
import cats.implicits.*
import com.comcast.ip4s.SocketAddress
import com.spotify.authentication.*
import com.spotify.keyexchange.ErrorCode
import fr.davit.sc4s.{KeepAlive, Mercury, Scope, TokenProvider}
import fs2.Stream
import fs2.concurrent.Topic
import fs2.io.net.Network
import io.circe.*
import org.http4s.*
import org.http4s.circe.*
import org.http4s.client.Client
import org.http4s.client.websocket.*
import org.http4s.implicits.*
import org.http4s.jdkhttpclient.JdkWSClient
import scalapb.GeneratedMessage

import java.net.InetSocketAddress
import java.net.http.HttpClient
import scala.util.Random

enum ResourceType:
  case accesspoint, dealer

enum Session:
  case Idle
  case Connected(userName: String)

object AccessPoint:

  class LoginException(code: ErrorCode) extends Exception(code.name)

  private val DefaultAp: InetSocketAddress = new InetSocketAddress("ap.spotify.com", 443)

  private case class ApResolve(addresses: Map[ResourceType, List[InetSocketAddress]])

  implicit private val InetSocketAddressDecoder: Decoder[InetSocketAddress] = Decoder.decodeString
    .map(_.split(':'))
    .map {
      case Array(host, port) => new InetSocketAddress(host, port.toInt)
      case _                 => throw new Exception("Failed extraction socket address")
    }

  implicit private val ApResolveDecoder: Decoder[ApResolve] =
    Decoder[Map[String, List[InetSocketAddress]]].map { values =>
      ApResolve(values.map { case (k, vs) => ResourceType.valueOf(k) -> vs })
    }

  implicit private def apResolveEntityDecoder[F[_]: Concurrent]: EntityDecoder[F, ApResolve] =
    jsonOf[F, ApResolve]

  implicit private val showWSFrame: Show[WSDataFrame] = {
//    case WSFrame.Close(code, _)   => s"close: $code"
//    case WSFrame.Ping(_)          => "ping"
//    case WSFrame.Pong(_)          => "pong"
    case WSFrame.Text(text, _)    => text
    case WSFrame.Binary(bytes, _) => bytes.toHex
  }

  def resolve[F[_]](client: Client[F], resourceType: ResourceType)(implicit F: Async[F]): F[Option[InetSocketAddress]] =
    client
      .expect[ApResolve](uri"http://apresolve.spotify.com".withQueryParam("type", resourceType.toString))
      .map(_.addresses(resourceType))
      .map(Random.shuffle(_))
      .map(_.headOption)

  def connect[F[_]: Spawn](
      client: Client[F],
      deviceId: String,
      userName: String,
      tpe: AuthenticationType.Recognized,
      authData: Array[Byte]
  )(implicit F: Async[F]): Resource[F, Session] =
    val login = AuthenticationRequest(deviceId, userName, tpe, authData)
    for
      address <- Resource.eval(resolve(client, ResourceType.accesspoint).map(_.getOrElse(DefaultAp)))
      _       <- Resource.eval(F.delay(println(s"Connecting to $address")))
      socket  <- Network[F].client(SocketAddress.fromInetSocketAddress(address))
      ap      <- AccessPointSocket.client(socket)
      // login
      _        <- Resource.eval(ap.write(login)(AccessPointProtocol.AccessPointRequestEncoder))
      response <- Resource.eval(ap.read()(AccessPointProtocol.AccessPointResponseDecoder))
      io <- Resource.eval {
        response match
          case _: AuthenticationSuccess =>
            for
              topic <- Topic[F, AccessPointResponse]
              queue <- Queue.bounded[F, AccessPointRequest](60)
            yield (topic, queue)
          case failure: AuthenticationFailure =>
            F.raiseError(new LoginException(failure.code))
          case response =>
            F.raiseError(new Exception(s"Unexpected response $response"))
      }
      (in, out) = io
      // read loop
      _ <- ap
        .reads()
        .through(in.publish)
        .compile
        .drain
        .background
      // write loop
      _ <- Stream
        .fromQueueUnterminated(out)
        .through(ap.writes())
        .compile
        .drain
        .background
      _       <- KeepAlive.client(in, out)
      mercury <- Mercury.client[F](in, out)
      tokenProvider = TokenProvider(deviceId, mercury)
      ws <- dealer(client, tokenProvider)
      _ <- ws.receiveStream
        .through(fs2.io.stdoutLines[F, WSDataFrame]())
        .compile
        .drain
        .background
      _ <- Resource.eval(F.delay(println(s"Authenticated as $userName")))
    yield Session.Connected(userName)
  end connect

  def dealer[F[_]](
      client: Client[F],
      tokenProvider: TokenProvider[F]
  )(implicit F: Async[F]): Resource[F, WSConnectionHighLevel[F]] =
    for
      address <- Resource.eval(resolve(client, ResourceType.dealer).map(_.get))
      token   <- Resource.eval(tokenProvider.getToken(Seq(Scope.`playlist-read`)))
      scheme    = scheme"wss"
      host      = Uri.Host.unsafeFromString(address.getHostName)
      port      = address.getPort
      authority = Uri.Authority(host = host, port = Some(port))
      uri       = Uri(scheme = Some(scheme), authority = Some(authority)).withQueryParam("access_token", token.value)
      wsClient <- Resource.eval(JdkWSClient.simple)
      ws       <- wsClient.connectHighLevel(WSRequest(uri))
    yield ws
