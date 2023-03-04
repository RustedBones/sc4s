import sbt.*

object Dependencies:

  object Versions:
    val Annotations  = "16.0.2"
    val BouncyCastle = "1.69"
    val Circe        = "0.14.5"
    val Gson         = "2.9.0"
    val Http4s       = "1.0.0-M37"
    val MUnitCE3     = "1.0.7"
    val Scout        = "0.2.1"
    val Slf4j        = "2.0.6"
    // val Tsec         = "0.2.1"

  val BouncyCastle      = "org.bouncycastle" % "bcprov-jdk15on"      % Versions.BouncyCastle
  val CirceGeneric      = "io.circe"        %% "circe-generic"       % Versions.Circe
  val CirceLiteral      = "io.circe"        %% "circe-literal"       % Versions.Circe
  val CirceParser       = "io.circe"        %% "circe-parser"        % Versions.Circe
  val Http4sCirce       = "org.http4s"      %% "http4s-circe"        % Versions.Http4s
  val Http4sDsl         = "org.http4s"      %% "http4s-dsl"          % Versions.Http4s
  val Http4sEmberClient = "org.http4s"      %% "http4s-ember-client" % Versions.Http4s
  val Http4sEmberServer = "org.http4s"      %% "http4s-ember-server" % Versions.Http4s
  val Scout             = "fr.davit"        %% "scout"               % Versions.Scout
//  val TsecCommon        = "io.github.jmcardon" %% "tsec-common"         % Versions.Tsec
//  val TsecCipher        = "io.github.jmcardon" %% "tsec-cipher-bouncy"  % Versions.Tsec
//  val TsecHash          = "io.github.jmcardon" %% "tsec-hash-bouncy"    % Versions.Tsec
//  val TsecMac           = "io.github.jmcardon" %% "tsec-mac"            % Versions.Tsec

  object Protobuf:
    val ScalaPb = "com.thesamet.scalapb" %% "scalapb-runtime" % scalapb.compiler.Version.scalapbVersion % "protobuf"

  object Test:
    val Annotations = "org.jetbrains"        % "annotations"         % Versions.Annotations % "test"
    val MUnitCE3    = "org.typelevel"       %% "munit-cats-effect-3" % Versions.MUnitCE3    % "test"
    val Slf4jApi    = "org.slf4j"            % "slf4j-api"           % Versions.Slf4j       % "test"
    val Gson        = "com.google.code.gson" % "gson"                % Versions.Gson        % "test"
