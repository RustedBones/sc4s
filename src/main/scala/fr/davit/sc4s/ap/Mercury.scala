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

object Mercury {

  sealed trait Method
  case object Subscribe extends Method
  case object Unsubscribe extends Method

  final case class TokenRequest(sequenceId: Long, deviceId: String, scopes: List[String])
  final case class TokenResponse(sequenceId: Long, token: Token)

}
