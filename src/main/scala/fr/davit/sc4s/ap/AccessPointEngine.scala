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

import cats.effect.{Ref, Sync}
import cats.implicits.*
import fr.davit.sc4s.security.ShannonCipher.ShannonParameterSpec
import fr.davit.sc4s.security.{Shannon, ShannonCipher}
import fs2.Chunk
import fs2.io.net.Socket
import scodec.{Attempt, Codec, Decoder, Encoder, Err}
import scodec.bits.{BitVector, ByteVector}
import scodec.codecs.{bytes, ignore, uint16}

import java.security.Key
import javax.crypto.{BadPaddingException, Cipher, IllegalBlockSizeException}

sealed private[ap] trait AccessPointEngine[F[_]]:

  def read(): F[ByteVector]

  def write(bytes: ByteVector): F[Unit]

private[ap] object AccessPointEngine:

  val HeaderSize              = 3
  val HeaderCodec: Codec[Int] = ignore(8) ~> uint16

  implicit class CryptCodec[T](val codec: Codec[T]) extends AnyVal:

    private def decrypt(cipher: Cipher)(buffer: BitVector): Attempt[BitVector] =
      val blocks = buffer.toByteArray
      try
        val decrypted = if blocks.isEmpty then BitVector.empty else BitVector(cipher.update(blocks))
        Attempt.successful(decrypted)
      catch
        case e @ (_: IllegalBlockSizeException | _: BadPaddingException) =>
          Attempt.failure(Err("Failed to decrypt: " + e.getMessage))

    def decrypted(cipher: Cipher): Decoder[T] = Decoder[T] { (buffer: BitVector) =>
      for
        result  <- decrypt(cipher)(buffer)
        message <- codec.decode(result)
      yield message
    }

    private def encrypt(cipher: Cipher)(bits: BitVector): Attempt[BitVector] =
      val blocks = bits.toByteArray
      try
        val encrypted = if blocks.isEmpty then BitVector.empty else BitVector(cipher.update(blocks))
        Attempt.successful(encrypted)
      catch
        case _: IllegalBlockSizeException =>
          Attempt.failure(Err(s"Failed to encrypt: invalid block size ${blocks.length}"))

    def encrypted(cipher: Cipher): Encoder[T] = Encoder[T] { (message: T) =>
      codec.encode(message).flatMap(encrypt(cipher))
    }

  def apply[F[_]](socket: Socket[F], encryptKey: Key, decryptKey: Key)(implicit F: Sync[F]): F[AccessPointEngine[F]] =
    for
      encryptIv    <- F.delay(Shannon.cipher(Shannon.Encrypt, encryptKey).getIV)
      encryptNonce <- Ref.of[F, Int](0)
      decryptIv    <- F.delay(Shannon.cipher(Shannon.Decrypt, decryptKey).getIV)
      decryptNonce <- Ref.of[F, Int](0)
    yield new AccessPointEngine[F]:

      def readN(numBytes: Int): F[BitVector] =
        for
          chunk <- socket.readN(numBytes)
          _ <-
            if chunk.size != numBytes then F.raiseError(new RuntimeException("Connection closed unexpectedly"))
            else F.unit
        yield chunk.toBitVector

      override def read(): F[ByteVector] = for
        nonce <- decryptNonce.modify(n => (n + 1, n))
        param = new ShannonParameterSpec(decryptIv, nonce)
        cipher      <- F.delay(Shannon.cipher(Shannon.Decrypt, decryptKey, param))
        headerRaw   <- readN(HeaderSize)
        header      <- F.delay(bytes.decrypted(cipher).decodeValue(headerRaw).require)
        payloadSize <- F.delay(HeaderCodec.decodeValue(header.toBitVector).require)
        payloadRaw  <- readN(payloadSize)
        payload     <- F.delay(bytes.decrypted(cipher).decodeValue(payloadRaw).require)
        mac         <- readN(ShannonCipher.BlockSize)
        _           <- F.delay(cipher.doFinal(mac.toByteArray))
      yield header ++ payload

      override def write(message: ByteVector): F[Unit] = for
        nonce <- encryptNonce.modify(n => (n + 1, n))
        param = new ShannonParameterSpec(encryptIv, nonce)
        cipher     <- F.delay(Shannon.cipher(Shannon.Encrypt, encryptKey, param))
        messageRaw <- F.delay(bytes.encrypted(cipher).encode(message).require)
        mac        <- F.delay(ByteVector.view(cipher.doFinal()))
        _          <- socket.write(Chunk.byteVector(messageRaw.toByteVector ++ mac))
      yield ()
