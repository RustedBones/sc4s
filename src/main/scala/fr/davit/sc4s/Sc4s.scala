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
import cats.implicits.*
import cats.effect.*
import cats.effect.std.{Hotswap, Mutex}
import com.comcast.ip4s.*
import fr.davit.sc4s.ap.{AccessPoint, Session}
import fr.davit.sc4s.security.{DiffieHellman, ShannonCipher}
import fr.davit.scout.Zeroconf
import org.http4s.ember.client.EmberClientBuilder
import org.http4s.ember.server.EmberServerBuilder
import org.http4s.implicits.*
import org.http4s.server.Router
import scalapb.GeneratedMessage

import java.net.InetAddress
import java.security.Security
import scala.util.Random

object Sc4s extends IOApp:

  val ZeroconfAppPath = "/zc/0"

  val ZeroconfService = Zeroconf
    .Service("spotify-connect", "tcp")

  val DeviceId = Random.nextBytes(20).map("%02x".format(_)).mkString

  implicit val MessageShow: Show[GeneratedMessage] = Show.fromToString

  Security.addProvider(ShannonCipher.ShannonCipherProvider)

  override def run(args: List[String]): IO[ExitCode] =

    val resources = for
      shs    <- Hotswap.create[IO, Session]
      client <- EmberClientBuilder.default[IO].build
      app <- Resource.eval {
        for
          m    <- Mutex[IO]
          s    <- shs.swap(Resource.pure(Session.Idle))
          sr   <- Ref.of[IO, Session](s)
          keys <- IO(DiffieHellman.generateKeyPair())
        yield
          val (priv, pub) = keys
          val service     = Discovery.service(m, client, shs, sr, DeviceId, priv, pub)
          Router(ZeroconfAppPath -> service).orNotFound
      }
      server <- EmberServerBuilder
        .default[IO]
        .withHost(ipv4"0.0.0.0")
        .withPort(port"0")
        .withMaxConnections(1) // serve only one client at a time
        .withHttpApp(app)
        .build
    yield server

    resources.use { server =>
      val zeroconf = Zeroconf.Instance(
        ZeroconfService,
        "sc4s",
        server.baseUri.port.get,
        s"${InetAddress.getLocalHost.getHostName}.local",
        Map("VERSION" -> "1.0", "CPath" -> ZeroconfAppPath, "Stack" -> "SP")
      )

      for
        _ <- IO(println(s"zc server listening on ${server.baseUri}"))
        _ <- Zeroconf.register[IO](zeroconf).compile.drain
      yield ExitCode.Success
    }
