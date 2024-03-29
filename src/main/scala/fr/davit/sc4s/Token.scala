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

import java.time.Instant
import scala.annotation.targetName
import scala.concurrent.duration.*

enum Scope:
  case `playlist-read`

case class Token(value: String, scope: List[Scope], expiresAt: Instant)

object Token:
  private val ValidityThreshold: FiniteDuration = 10.seconds

  def apply(value: String, scopes: Seq[Scope], expiresIn: FiniteDuration): Token =
    Token(value, scopes.toList, Instant.now().plusSeconds((expiresIn - ValidityThreshold).toSeconds))
