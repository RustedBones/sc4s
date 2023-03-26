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
