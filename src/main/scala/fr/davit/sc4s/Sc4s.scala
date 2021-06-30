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

import cats.Show
import cats.implicits._
import cats.effect._
import fr.davit.sc4s.ap.AccessPoint
import fr.davit.sc4s.security.{DiffieHellman, ShannonCipher}
import fr.davit.scout.Zeroconf
import org.http4s.ember.client.EmberClientBuilder
import org.http4s.ember.server.EmberServerBuilder
import org.http4s.implicits._
import org.http4s.server.Router
import scalapb.GeneratedMessage

import java.net.InetAddress
import java.security.Security
import scala.util.Random

object Sc4s extends IOApp {

  val ZeroconfAppPath = "/zc/0"

  val ZeroconfService = Zeroconf
    .Service("spotify-connect", "tcp")

  val DeviceId = Random.nextBytes(20).map("%02x".format(_)).mkString

  implicit val MessageShow: Show[GeneratedMessage] = Show.fromToString

  Security.addProvider(ShannonCipher.ShannonCipherProvider)

  override def run(args: List[String]): IO[ExitCode] = {

    val resources = for {
      session <- Resource
        .make(Ref.of[IO, Option[Session[IO]]](None))(_.get.flatMap(_.map(_.close()).getOrElse(IO.unit)))
      client  <- EmberClientBuilder.default[IO].build
      address <- Resource.eval(AccessPoint.resolve[IO](client).flatTap(a => IO(println(a))))
      ap      <- AccessPoint.client[IO](address)
      pair    <- Resource.eval(IO(DiffieHellman.generateKeyPair()))
      (priv, pub) = pair
      service     = Discovery.service(session, ap, DeviceId, priv, pub)
      app         = Router(ZeroconfAppPath -> service).orNotFound
      server <- EmberServerBuilder
        .default[IO]
        // .withHost(Host.)
        // .withPort(0)
        .withMaxConcurrency(1) // serve only one client at a time
        .withHttpApp(app)
        .build
    } yield (server, ap)

    resources.use { case (server, _) =>
      val zeroconf = Zeroconf.Instance(
        ZeroconfService,
        "sc4s",
        server.baseUri.port.get,
        s"${InetAddress.getLocalHost.getHostName}.local",
        Map("VERSION" -> "1.0", "CPath" -> ZeroconfAppPath, "Stack" -> "SP")
      )

      for {
        _ <- IO(println(s"zc server listening on ${server.baseUri}"))
        _ <- Zeroconf.register[IO](zeroconf).compile.drain
      } yield ExitCode.Success
    }
  }

}
