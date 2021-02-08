package fr.davit.sc4s.ap

import com.spotify.authentication.ClientResponseEncrypted
import scalapb.GeneratedMessage

sealed trait AccessPointMessage[T <: GeneratedMessage] {
  def message: T
}

case class LoginMessage(message: ClientResponseEncrypted) extends AccessPointMessage[ClientResponseEncrypted]
