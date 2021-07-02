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
import cats.implicits._
import com.comcast.ip4s.SocketAddress
import fr.davit.sc4s.Session
import fr.davit.sc4s.ap.authentication._
import fr.davit.sc4s.ap.keyexchange.ErrorCode
import fs2.io.net.Network
import io.circe._
import org.http4s._
import org.http4s.circe._
import org.http4s.client.Client
import scalapb.GeneratedMessage

import java.net.InetSocketAddress
import scala.util.Random

trait AccessPoint[F[_]] {

  def authenticate(
      deviceId: String,
      userName: String,
      tpe: AuthenticationType.Recognized,
      authData: Array[Byte],
      errorHandler: Throwable => F[Unit]
  ): F[Session[F]]

}

object AccessPoint {

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
    Decoder(_.downField("accesspoint").as[List[InetSocketAddress]].map(ApResolve))

  implicit private def apResolveEntityDecoder[F[_]: Concurrent]: EntityDecoder[F, ApResolve] =
    jsonOf[F, ApResolve]

  def resolve[F[_]: Async](client: Client[F]): F[InetSocketAddress] = {
    client
      .expect[ApResolve]("http://apresolve.spotify.com?type=accesspoint")
      .map(_.apList)
      .map(Random.shuffle(_))
      .map(_.headOption.getOrElse(DefaultAp))
      .orElse(Sync[F].pure(DefaultAp))
  }

  def client[F[_]: Async: Network](address: InetSocketAddress): Resource[F, AccessPoint[F]] =
    for {
      socket   <- Network[F].client(SocketAddress.fromInetSocketAddress(address))
      apSocket <- AccessPointSocket.client(socket)
    } yield new AccessPoint[F] {

      override def authenticate(
          deviceId: String,
          userName: String,
          tpe: AuthenticationType.Recognized,
          authData: Array[Byte],
          errorHandler: Throwable => F[Unit]
      ): F[Session[F]] = {
        val login = AuthenticationRequest(deviceId, userName, tpe, authData)
        Session(apSocket, login, errorHandler)
      }
    }
}
