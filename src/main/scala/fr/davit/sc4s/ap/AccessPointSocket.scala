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

package fr.davit.sc4s.ap

import cats.effect._
import cats.implicits._
import fr.davit.sc4s.security._
import fs2._
import fs2.io.net.Socket
import scodec.bits.{BuildInfo => _, _}
import scodec.{BuildInfo => _, _}

import java.security.Key
import javax.crypto.spec.SecretKeySpec

trait AccessPointSocket[F[_]] {

  def write[T <: AccessPointRequest: Encoder](message: T): F[Unit]

  def read[T <: AccessPointResponse: Decoder](): F[T]

  def writes(): Pipe[F, AccessPointRequest, Unit]

  def reads(): Stream[F, AccessPointResponse]
}

object AccessPointSocket {

  def client[F[_]: Sync](
      socket: Socket[F]
  ): Resource[F, AccessPointSocket[F]] = {

    def encode[T](data: T)(implicit encoder: Encoder[T]): F[ByteVector] =
      Sync[F].delay(encoder.encode(data).require.toByteVector)

    def decode[T](bytes: ByteVector)(implicit decoder: Decoder[T]): F[T] =
      Sync[F].delay(decoder.decode(bytes.toBitVector).require.value)

    def handshake(): F[(Key, Key)] = {
      import AccessPointProtocol.Handshake._

      for {
        keyPair <- Sync[F].delay(DiffieHellman.generateKeyPair())
        (priv, pub) = keyPair
        handshakeHelloMessage     <- encode(HandshakeHello(pub))
        _                         <- socket.write(Chunk.byteVector(handshakeHelloMessage))
        handshakeChallengeHeader  <- socket.readN(4).map(_.toByteVector)
        handshakeChallengeSize    <- decode(handshakeChallengeHeader)(HeaderCodec)
        handshakeChallengePayload <- socket.readN(handshakeChallengeSize).map(_.toByteVector)
        handshakeChallengeMessage = handshakeChallengeHeader ++ handshakeChallengePayload
        handshakeChallenge <- decode[HandshakeChallenge](handshakeChallengeMessage)
        secret             <- Sync[F].delay(DiffieHellman.secret(priv, handshakeChallenge.serverKey))
        sharedKey     = new SecretKeySpec(secret, HmacSHA1.Algorithm)
        challengeData = handshakeHelloMessage ++ handshakeChallengeMessage
        data <- Sync[F].delay {
          (1 to 5)
            .map(i => HmacSHA1.digest(sharedKey, (challengeData ++ ByteVector.fromInt(i, size = 1)).toArray))
            .reduce(_ ++ _)
        }
        secretKey = new SecretKeySpec(data, 0, 20, HmacSHA1.Algorithm)
        encodeKey = new SecretKeySpec(data, 20, 32, Shannon.Algorithm)
        decodeKey = new SecretKeySpec(data, 52, 32, Shannon.Algorithm)
        answer                   <- Sync[F].delay(HmacSHA1.digest(secretKey, challengeData.toArray))
        handshakeResponseMessage <- encode(HandshakeResponse(answer))
        _                        <- socket.write(Chunk.byteVector(handshakeResponseMessage))
        // no response expected in case of success
//        errorSize <- readPayload(4, headerCodec)
//        error     <- readPayload(errorSize, protobufDecoder(APResponseMessage))
//        _         <- Sync[F].raiseError[Unit](new HandshakeException(error.loginFailed.get))
      } yield (encodeKey, decodeKey)
    }

    val apSocket = for {
      keys <- handshake()
      (encryptKey, decryptKey) = keys
      engine <- AccessPointEngine(socket, encryptKey, decryptKey)
    } yield new AccessPointSocket[F] {

      def read[T: Decoder](): F[T] = for {
        payload <- engine.read()
        message <- decode[T](payload)
      } yield message

      override def write[T: Encoder](message: T): F[Unit] = for {
        payload <- encode(message)
        _       <- engine.write(payload)
      } yield ()

      override def writes(): Pipe[F, AccessPointRequest, Unit] =
        _.flatMap(req => Stream.eval(write(req)(AccessPointProtocol.AccessPointRequestEncoder)))

      override def reads(): Stream[F, AccessPointResponse] =
        Stream.repeatEval(read()(AccessPointProtocol.AccessPointResponseDecoder))
    }

    // TODO is there a close action ?
    Resource.eval(apSocket)
  }
}
