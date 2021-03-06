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
import com.spotify.authentication._
import fs2.io.tcp.SocketGroup
import io.circe._
import org.http4s._
import org.http4s.circe._
import org.http4s.client.Client
import scalapb.GeneratedMessage

import java.net.InetSocketAddress
import scala.concurrent.duration._
import scala.util.Random

trait AccessPoint[F[_]] {

  def listen(): fs2.Stream[F, GeneratedMessage]

  def authenticate(deviceId: String, credentials: LoginCredentials): F[Unit]

}

object AccessPoint {

  private val DefaultAp: InetSocketAddress = new InetSocketAddress("ap.spotify.com", 443)

  private case class ApResolve(apList: List[InetSocketAddress])

  implicit private val InetSocketAddressDecoder: Decoder[InetSocketAddress] = Decoder.decodeString
    .map(_.split(':'))
    .map { case Array(host, port) => new InetSocketAddress(host, port.toInt) }

  implicit private val ApResolveDecoder: Decoder[ApResolve] =
    Decoder(_.downField("accesspoint").as[List[InetSocketAddress]].map(ApResolve))

  implicit private def apResolveEntityDecoder[F[_]: Sync]: EntityDecoder[F, ApResolve] =
    jsonOf[F, ApResolve]

  def resolve[F[_]: Sync](client: Client[F]): F[InetSocketAddress] = {
    client
      .expect[ApResolve]("http://apresolve.spotify.com?type=accesspoint")
      .map(_.apList)
      .map(Random.shuffle(_))
      .map(_.headOption.getOrElse(DefaultAp))
      .orElse(Sync[F].pure(DefaultAp))
  }

  def client[F[_]: Concurrent: ContextShift](
      address: InetSocketAddress,
      timeout: Option[FiniteDuration] = None
  ): Resource[F, AccessPoint[F]] =
    for {
      b        <- Blocker[F]
      group    <- SocketGroup[F](b)
      socket   <- group.client(address)
      apSocket <- Resource.liftF(AccessPointContext(socket, timeout))
    } yield new AccessPoint[F] {

      override def listen(): fs2.Stream[F, GeneratedMessage] = apSocket.reads()

      override def authenticate(deviceId: String, credentials: LoginCredentials): F[Unit] = {
        val systemInfo = SystemInfo.defaultInstance
          .withOs(Os.OS_UNKNOWN)
          .withCpuFamily(CpuFamily.CPU_UNKNOWN)
          .withDeviceId(deviceId)

        val clientResponseEncrypted = ClientResponseEncrypted.defaultInstance
          .withLoginCredentials(credentials)
          .withSystemInfo(systemInfo)
          .withVersionString("0.1.0")

        for {
          _       <- apSocket.write(clientResponseEncrypted)
          welcome <- apSocket.read[APWelcome]()
        } yield println(welcome)
      }
    }
}
