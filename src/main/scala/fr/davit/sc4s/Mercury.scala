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
import cats.effect.{Async, Deferred, Ref, Resource}
import cats.implicits.*
import com.spotify.mercury.MercuryHeader
import fr.davit.sc4s.ap.{AccessPointRequest, AccessPointResponse, MercuryMessage}
import fs2.concurrent.Topic
import scodec.bits.ByteVector

object Mercury:

  sealed trait Method
  case object Subscribe   extends Method
  case object Unsubscribe extends Method

  final case class Message(header: MercuryHeader, payload: Vector[ByteVector])

  trait Client[F[_]]:
    def send(request: Message): F[Deferred[F, Message]]

  def client[F[_]: Async](
      input: Topic[F, AccessPointResponse],
      output: Queue[F, AccessPointRequest]
  ): Resource[F, Client[F]] =
    for
      sequence <- Resource.eval(Ref.of[F, Long](1L))
      pending  <- Resource.eval(Ref.of[F, Map[Long, Deferred[F, Message]]](Map.empty))
      _ <- input
        .subscribe(10)
        .collect { case m: MercuryMessage => m }
        .evalMap { message =>
          (for
            p <- OptionT(pending.modify(ps => (ps - message.sequenceId, ps.get(message.sequenceId))))
            _ <- OptionT.liftF(p.complete(Message(message.header, message.payload)))
          yield ()).value
        }
        .compile
        .drain
        .background
    yield new Client[F]:
      override def send(request: Message): F[Deferred[F, Message]] = for
        id       <- sequence.modify(s => (s + 1, s))
        response <- Deferred[F, Message]
        _        <- pending.update(_ + (id -> response))
        _        <- output.offer(MercuryMessage(id, request.header, request.payload))
      yield response
