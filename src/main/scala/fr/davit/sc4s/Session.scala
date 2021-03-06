package fr.davit.sc4s

sealed trait Session {
  def activeUser: Option[String]
}

object Session {

  case object Disconnected extends Session {
    override def activeUser: Option[String] = None
  }

  final case class Connected(userName: String) extends Session {
    override def activeUser: Option[String] = Some(userName)
  }
}
