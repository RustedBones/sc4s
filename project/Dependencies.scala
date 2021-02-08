import sbt._

object Dependencies {

  object Versions {
    val Circe           = "0.14.0-M3"
    val Http4s          = "1.0.0-M9"
    val MUnit           = "0.7.20"
    val MUnitCatsEffect = "0.13.0"
    val ScalaTest       = "3.2.2"
    val Scout           = "0.1.0"
  }

  val CirceGeneric      = "io.circe"   %% "circe-generic"       % Versions.Circe
  val CirceLiteral      = "io.circe"   %% "circe-literal"       % Versions.Circe
  val Http4sBlazeClient = "org.http4s" %% "http4s-blaze-client" % Versions.Http4s
  val Http4sBlazeServer = "org.http4s" %% "http4s-blaze-server" % Versions.Http4s
  val Http4sCirce       = "org.http4s" %% "http4s-circe"        % Versions.Http4s
  val Http4sDsl         = "org.http4s" %% "http4s-dsl"          % Versions.Http4s
  val Scout             = "fr.davit"   %% "scout"               % Versions.Scout

  object Protobuf {
    val ScalaPb = "com.thesamet.scalapb" %% "scalapb-runtime" % scalapb.compiler.Version.scalapbVersion % "protobuf"
  }

  object Test {
    val MUnit           = "org.scalameta" %% "munit"               % Versions.MUnit           % "test"
    val MUnitCatsEffect = "org.typelevel" %% "munit-cats-effect-2" % Versions.MUnitCatsEffect % "test"
  }
}
