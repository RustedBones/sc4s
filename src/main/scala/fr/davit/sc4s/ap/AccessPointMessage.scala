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

import com.spotify.authentication.AuthenticationType
import com.spotify.keyexchange.ErrorCode
import com.spotify.mercury.MercuryHeader
import scodec.bits.ByteVector

import javax.crypto.interfaces.DHPublicKey

// format: off
sealed trait AccessPointMessage
sealed trait AccessPointRequest extends AccessPointMessage
sealed trait AccessPointResponse extends AccessPointMessage

sealed trait HandshakeMessage
final case class HandshakeHello(clientKey: DHPublicKey) extends HandshakeMessage with AccessPointRequest
final case class HandshakeChallenge(serverKey: DHPublicKey) extends HandshakeMessage with AccessPointResponse
final case class HandshakeResponse(response: Array[Byte]) extends HandshakeMessage with AccessPointRequest

sealed trait AuthenticationMessage
final case class AuthenticationRequest(deviceId: String, userName: String, tpe: AuthenticationType.Recognized, authData: Array[Byte]) extends AuthenticationMessage with AccessPointRequest
final case class AuthenticationSuccess(userName: String) extends AuthenticationMessage with AccessPointResponse
final case class AuthenticationFailure(code: ErrorCode) extends AuthenticationMessage with AccessPointResponse

sealed trait KeepAliveMessage
final case class Ping(payload: ByteVector) extends KeepAliveMessage with AccessPointResponse
final case class Pong(payload: ByteVector) extends KeepAliveMessage with AccessPointRequest

sealed trait SessionMessage
final case class SecretBlock(payload: ByteVector) extends SessionMessage with AccessPointResponse
final case class LicenseVersion(id: Int, version: String) extends SessionMessage with AccessPointResponse
final case class CountryCode(code: String) extends SessionMessage with AccessPointResponse
final case class ProductInfo(info: String) extends SessionMessage with AccessPointResponse
final case class LegacyWelcome(payload: ByteVector) extends SessionMessage with AccessPointResponse
final case class Unknown(payload: ByteVector) extends SessionMessage with AccessPointResponse

final case class MercuryMessage(sequenceId: Long, header: MercuryHeader, payload: Vector[ByteVector]) extends AccessPointRequest with AccessPointResponse
// format: on
