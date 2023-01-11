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
import cats.implicits.*
import com.comcast.ip4s.SocketAddress
import com.spotify.authentication.*
import com.spotify.keyexchange.ErrorCode
import fs2.io.net.Network
import io.circe.*
import org.http4s.*
import org.http4s.circe.*
import org.http4s.client.Client
import scalapb.GeneratedMessage

import java.net.InetSocketAddress
import scala.util.Random

enum Session:
  case Connected(userName: String)
  case Idle

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

  def resolve[F[_]: Async](client: Client[F]): F[InetSocketAddress] =
    client
      .expect[ApResolve]("http://apresolve.spotify.com?type=accesspoint")
      .map(_.apList)
      .map(Random.shuffle(_))
      .map(_.headOption.getOrElse(DefaultAp))
      .orElse(Sync[F].pure(DefaultAp))

  def connect[F[_]: Async](
      address: InetSocketAddress,
      deviceId: String,
      userName: String,
      tpe: AuthenticationType.Recognized,
      authData: Array[Byte]
  ): Resource[F, Session] = Resource.make {
    val login = AuthenticationRequest(deviceId, userName, tpe, authData)
    val accessPoint = for
      socket   <- Network[F].client(SocketAddress.fromInetSocketAddress(address))
      apSocket <- AccessPointSocket.client(socket)
    yield apSocket

    accessPoint.use { ap =>
      for
        _      <- ap.write(login)(AccessPointProtocol.AccessPointRequestEncoder)
        result <- ap.read()(AccessPointProtocol.AccessPointResponseDecoder)
        _ <- result match
          case _: AuthenticationSuccess =>
            Sync[F].unit
          //       val listen = apSocket.reads().through(topic.publish)
          //       val write  = Stream.fromQueueUnterminated(queue).through(apSocket.writes())
          //       listen.concurrently(write)
          case failure: AuthenticationFailure =>
            Sync[F].raiseError(new LoginException(failure.code))
          case response =>
            Sync[F].raiseError(new Exception(s"Unexpected response $response"))
      yield Session.Connected(userName)
    }
  } { session =>
    Sync[F].unit
  }
