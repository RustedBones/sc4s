import sbt.Keys._
import sbt._
import sbtprotoc.ProtocPlugin.autoImport._

object ScalaPbSettings {

  def defaults: Seq[Setting[_]] = Seq(
    (Compile / PB.targets) := Seq(scalapb.gen() -> (Compile / sourceManaged).value / "proto")
  )

}
