import sbt.Keys.*
import sbt.*
import sbtprotoc.ProtocPlugin.autoImport.*

object ScalaPbSettings:

  def defaults: Seq[Setting[?]] = Seq(
    (Compile / PB.targets) := Seq(scalapb.gen() -> (Compile / sourceManaged).value / "proto")
  )
