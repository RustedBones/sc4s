import sbt._

object Dependencies {

  object Versions {
    val BouncyCastle    = "1.68"
    val Circe           = "0.14.0-M4"
    val Http4s          = "0.21.23"
    val MUnit           = "0.7.23"
    val MUnitCatsEffect = "0.13.1"
    val ScalaTest       = "3.2.2"
    val Scout           = "0.1.0"
    val Tsec            = "0.2.1"
  }

  val CirceGeneric      = "io.circe"           %% "circe-generic"       % Versions.Circe
  val CirceLiteral      = "io.circe"           %% "circe-literal"       % Versions.Circe
  val Http4sCirce       = "org.http4s"         %% "http4s-circe"        % Versions.Http4s
  val Http4sDsl         = "org.http4s"         %% "http4s-dsl"          % Versions.Http4s
  val Http4sEmberClient = "org.http4s"         %% "http4s-ember-client" % Versions.Http4s
  val Http4sEmberServer = "org.http4s"         %% "http4s-ember-server" % Versions.Http4s
  val Scout             = "fr.davit"           %% "scout"               % Versions.Scout
  val TsecCommon        = "io.github.jmcardon" %% "tsec-common"         % Versions.Tsec
  val TsecCipher        = "io.github.jmcardon" %% "tsec-cipher-bouncy"  % Versions.Tsec
  val TsecHash          = "io.github.jmcardon" %% "tsec-hash-bouncy"    % Versions.Tsec
  val TsecMac           = "io.github.jmcardon" %% "tsec-mac"            % Versions.Tsec

  object Protobuf {
    val ScalaPb = "com.thesamet.scalapb" %% "scalapb-runtime" % scalapb.compiler.Version.scalapbVersion % "protobuf"
  }

  object Test {
    val MUnit           = "org.scalameta" %% "munit"               % Versions.MUnit           % "test"
    val MUnitCatsEffect = "org.typelevel" %% "munit-cats-effect-2" % Versions.MUnitCatsEffect % "test"
  }
}
