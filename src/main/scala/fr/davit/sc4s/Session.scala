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
import cats.implicits.*
import fr.davit.sc4s.ap.AccessPoint.LoginException
import fr.davit.sc4s.ap.{AccessPointSocket, AuthenticationFailure, AuthenticationRequest, AuthenticationSuccess}
import fs2.Stream
import fs2.io.stdoutLines

trait Session[F[_]]:
  def userName: String
  def close(): F[Unit]

object Session:

  def apply[F[_]: Async](
      apSocket: AccessPointSocket[F],
      login: AuthenticationRequest,
      errorHandler: Throwable => F[Unit]
  ): F[Session[F]] = for
    switch <- Deferred[F, Unit]
    server = (Stream.emit(login).through(apSocket.writes()) >> apSocket.reads().head)
      .flatMap {
        case _: AuthenticationSuccess =>
          apSocket
            .reads()
            .map(_.toString + "\n")
            .through(stdoutLines[F, String]())
        case failure: AuthenticationFailure =>
          Stream.raiseError[F](new LoginException(failure.code))
        case response =>
          Stream.raiseError[F](new Exception(s"Unexpected response $response"))
      }
      .interruptWhen(switch.get.attempt)
    fiber <- Async[F].start(server.compile.drain.onError { case e => errorHandler(e) })
  yield new Session[F]:
    override def userName: String = login.userName
    override def close(): F[Unit] = switch.complete(()).map(_ => fiber.joinWithNever)
