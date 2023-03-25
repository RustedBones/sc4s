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

import cats.data.OptionT
import cats.effect.implicits.*
import cats.effect.std.Queue
import cats.effect.{Async, Deferred, Ref, Resource, Sync}
import cats.implicits.*
import com.spotify.mercury.MercuryHeader
import fr.davit.sc4s.ap.*
import fs2.concurrent.Topic
import org.http4s.Uri
import scodec.bits.ByteVector

object Mercury:

  final class MercuryException(statusCode: Int) extends Exception(s"status: $statusCode")
  final case class Request(uri: Uri, payload: Vector[ByteVector] = Vector.empty)
  final case class Response(payload: Vector[ByteVector])

  trait Client[F[_]]:
    def send(request: Request): F[Deferred[F, Response]]

  def client[F[_]: Async](
      input: Topic[F, AccessPointResponse],
      output: Queue[F, AccessPointRequest]
  ): Resource[F, Client[F]] =
    for
      sequence <- Resource.eval(Ref.of[F, Long](1L))
      pending  <- Resource.eval(Ref.of[F, Map[Long, Deferred[F, Response]]](Map.empty))
      _ <- input
        .subscribe(10)
        .evalMap {
          case resp: MercuryResponse =>
            if (resp.statusCode >= 200 && resp.statusCode < 300) {
              (for
                p <- OptionT(pending.modify(ps => (ps - resp.sequenceId, ps.get(resp.sequenceId))))
                _ <- OptionT.liftF(p.complete(Response(resp.payload)))
              yield ()).value.void
            } else {
              Sync[F].raiseError(new MercuryException(resp.statusCode))
            }
          case event: MercuryEvent =>
            Sync[F].delay(println(event))
          case _ =>
            Sync[F].unit
        }
        .compile
        .drain
        .background
    yield new Client[F]:
      override def send(request: Request): F[Deferred[F, Response]] = for
        id       <- sequence.modify(s => (s + 1, s))
        response <- Deferred[F, Response]
        _        <- pending.update(_ + (id -> response))
        _        <- output.offer(MercuryRequest(id, request.uri.renderString, request.payload))
      yield response
