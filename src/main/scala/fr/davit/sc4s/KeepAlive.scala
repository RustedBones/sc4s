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

import cats.effect.*
import cats.effect.implicits.*
import cats.effect.std.Queue
import fr.davit.sc4s.ap.{AccessPointRequest, AccessPointResponse, KeepAliveMessage, Ping, Pong, PongAck}
import fs2.concurrent.Topic

trait KeepAlive

object KeepAlive:
  def client[F[_]: Spawn](
      in: Topic[F, AccessPointResponse],
      out: Queue[F, AccessPointRequest]
  )(implicit F: Async[F]): Resource[F, KeepAlive] = in
    .subscribe(10)
    .collect { case m: KeepAliveMessage => m }
    .evalTap {
      case Ping(payload) => out.offer(Pong(payload))
      case PongAck       => F.unit
    }
    .compile
    .drain
    .background
    .map(_ => new KeepAlive {})
