package fr.davit.sc4s

import cats.effect.Sync
import cats.implicits.*
import com.spotify.mercury.MercuryHeader
import scodec.{Attempt, Decoder, Err}
import scodec.codecs.utf8
import org.http4s.implicits.*

import scala.concurrent.duration.*

trait TokenProvider[F[_]]:

  def getToken(scope: Seq[String]): F[Token]

object TokenProvider:

  private val KeyMasterClientId = "65b708073fc0480ea92a077233ca87bd"
  final private case class JsonToken(expiresIn: FiniteDuration, accessToken: String, scopes: List[Scope])
  implicit val FiniteDurationDecoder: io.circe.Decoder[FiniteDuration] = io.circe.Decoder.decodeInt.map(_.seconds)
  implicit private val ScopeJsonDecoder: io.circe.Decoder[Scope]     = io.circe.Decoder.decodeString.map(Scope.valueOf)
  implicit private val TokenJsonDecoder: io.circe.Decoder[JsonToken] = io.circe.generic.semiauto.deriveDecoder

  implicit val TokenDecoder: Decoder[Token] =
    utf8.emap { str =>
      io.circe.parser.decode[JsonToken](str) match
        case Left(err) =>
          Attempt.Failure(Err(err.getMessage))
        case Right(token) =>
          Attempt.Successful(Token(token.accessToken, token.scopes, token.expiresIn))
    }

  def apply[F[_]: Sync](deviceId: String, mercury: Mercury.Client[F]): TokenProvider[F] = new TokenProvider[F]:
    override def getToken(scopes: Seq[String]): F[Token] =
      val uri = uri"hm://keymaster/token/authenticated"
        .withQueryParam("scope", scopes.mkString(","))
        .withQueryParam("client_id", KeyMasterClientId)
        .withQueryParam("device_id", deviceId)

      val header = MercuryHeader.defaultInstance
        .withUri(uri.renderString)
        .withMethod("GET")
      val request = Mercury.Message(header, Vector.empty)

      for
        response <- mercury.send(request)
        message  <- response.get
        token    <- Sync[F].delay(TokenDecoder.decode(message.payload.head.bits).require.value)
      yield token
