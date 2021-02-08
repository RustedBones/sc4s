package fr.davit.sc4s

import cats.effect._
import fr.davit.sc4s.ap.AccessPoint
import fr.davit.sc4s.security.{DiffieHellman, ShannonCipher}
import fr.davit.scout.Zeroconf
import org.http4s.client.blaze.BlazeClientBuilder
import org.http4s.implicits._
import org.http4s.server.Router
import org.http4s.server.blaze.BlazeServerBuilder

import java.net.InetAddress
import java.security.Security
import java.util.UUID
import scala.concurrent.ExecutionContext.global

object Sc4s extends IOApp {

  val ZeroconfAppPath = "/zc/0"

  val ZeroconfService = Zeroconf
    .Service("spotify-connect", "tcp")

  val DeviceId = UUID.randomUUID().toString

  Security.addProvider(ShannonCipher.ShannonCipherProvider)

  override def run(args: List[String]): IO[ExitCode] = {

    val resources = for {
      ap <- BlazeClientBuilder[IO](executionContext).resource
        .flatMap(c => Resource.liftF(AccessPoint.resolve[IO](c)))
        .flatMap(AccessPoint.client[IO](_))

      pair <- Resource.liftF(DiffieHellman.generateKeyPair[IO]())
      (priv, pub) = pair
      app         = Router(ZeroconfAppPath -> Discovery.service(ap, DeviceId, priv, pub)).orNotFound
      server <- BlazeServerBuilder[IO](global)
        .bindAny("0.0.0.0")
        .withHttpApp(app)
        .resource
    } yield (server, ap)

    resources.use { case (server, ap) =>
      val zeroconf = Zeroconf.Instance(
        ZeroconfService,
        "sc4s",
        server.baseUri.port.get,
        s"${InetAddress.getLocalHost.getHostName}.local",
        Map("VERSION" -> "1.0", "CPath" -> ZeroconfAppPath, "Stack" -> "SP")
      )

      for {
        _ <- IO(println(s"zc server listening on ${server.baseUri}"))
        _ <- IO(println(s"AP $ap"))
        _ <- Zeroconf.register[IO](zeroconf).compile.drain
      } yield ExitCode.Success
    }
  }

}
