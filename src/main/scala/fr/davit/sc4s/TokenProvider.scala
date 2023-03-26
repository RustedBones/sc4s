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

import cats.effect.Sync
import cats.implicits.*
import com.spotify.mercury.MercuryHeader
import fr.davit.sc4s.ap.MercuryRequest
import scodec.{Attempt, Decoder, Err}
import scodec.codecs.utf8
import org.http4s.implicits.*

import scala.concurrent.duration.*

trait TokenProvider[F[_]]:

  def getToken(scope: Seq[Scope]): F[Token]

object TokenProvider:

  private val KeyMasterClientId = "65b708073fc0480ea92a077233ca87bd"
  final private case class JsonToken(expiresIn: FiniteDuration, accessToken: String, scope: List[Scope])

  implicit val FiniteDurationDecoder: io.circe.Decoder[FiniteDuration] = io.circe.Decoder.decodeInt.map(_.seconds)
  implicit private val ScopeJsonDecoder: io.circe.Decoder[Scope]     = io.circe.Decoder.decodeString.map(Scope.valueOf)
  implicit private val TokenJsonDecoder: io.circe.Decoder[JsonToken] = io.circe.generic.semiauto.deriveDecoder

  implicit val TokenDecoder: Decoder[Token] =
    utf8.emap { str =>
      io.circe.parser.decode[JsonToken](str) match
        case Left(err) =>
          Attempt.Failure(Err(err.getMessage))
        case Right(token) =>
          Attempt.Successful(Token(token.accessToken, token.scope, token.expiresIn))
    }

  def apply[F[_]](deviceId: String, mercury: Mercury.Client[F])(implicit F: Sync[F]): TokenProvider[F] =
    new TokenProvider[F]:
      override def getToken(scopes: Seq[Scope]): F[Token] =
        val uri = uri"hm://keymaster/token/authenticated"
          .withQueryParam("scope", scopes.map(_.toString).mkString(","))
          .withQueryParam("client_id", KeyMasterClientId)
          .withQueryParam("device_id", deviceId)

        val request = Mercury.Request(uri)

        for
          response <- mercury.send(request)
          message  <- response.get
          token    <- F.delay(TokenDecoder.decode(message.payload.head.bits).require.value)
        yield token
