import scala.annotation.nowarn

// General info
val username = "RustedBones"
val repo     = "sc4s"

lazy val filterScalacOptions = { options: Seq[String] =>
  options.filterNot { o =>
    // get rid of value discard
    o == "-Ywarn-value-discard" || o == "-Wvalue-discard"
  }
}

// for sbt-github-actions
ThisBuild / scalaVersion := "3.2.2"
ThisBuild / githubWorkflowBuild := Seq(
  WorkflowStep.Sbt(name = Some("Check project"), commands = List("scalafmtCheckAll", "headerCheckAll")),
  WorkflowStep.Sbt(name = Some("Build project"), commands = List("compile", "test"))
)
ThisBuild / githubWorkflowTargetBranches        := Seq("main")
ThisBuild / githubWorkflowPublishTargetBranches := Seq.empty

lazy val commonSettings =
  ScalaPbSettings.defaults ++
    Seq(
      organization     := "fr.davit",
      organizationName := "Michel Davit",
      version          := "0.1.0-SNAPSHOT",
      scalaVersion     := (ThisBuild / scalaVersion).value,
      scalacOptions ~= filterScalacOptions,
      homepage := Some(url(s"https://github.com/$username/$repo")),
      licenses += ("Apache-2.0", new URL("https://www.apache.org/licenses/LICENSE-2.0.txt")),
      startYear := Some(2021),
      scmInfo   := Some(ScmInfo(url(s"https://github.com/$username/$repo"), s"git@github.com:$username/$repo.git")),
      developers := List(
        Developer(
          id = s"$username",
          name = "Michel Davit",
          email = "michel@davit.fr",
          url = url(s"https://github.com/$username")
        )
      ),
      publishMavenStyle      := true,
      Test / publishArtifact := false,
      publishTo := {
        val resolver = if (isSnapshot.value) {
          Opts.resolver.sonatypeSnapshots: @nowarn("cat=deprecation")
        } else {
          Opts.resolver.sonatypeStaging
        }
        Some(resolver)
      },
      credentials ++= (for {
        username <- sys.env.get("SONATYPE_USERNAME")
        password <- sys.env.get("SONATYPE_PASSWORD")
      } yield Credentials("Sonatype Nexus Repository Manager", "oss.sonatype.org", username, password)).toSeq,
      testFrameworks += new TestFramework("munit.Framework")
    )

lazy val `sc4s` = (project in file("."))
  .settings(commonSettings: _*)
  .settings(
    headerSources / excludeFilter := HiddenFileFilter || (_.getPath.contains("xyz/gianlu/librespot")),
    libraryDependencies ++= Seq(
      Dependencies.BouncyCastle,
      Dependencies.CirceGeneric,
      Dependencies.CirceLiteral,
      Dependencies.CirceParser,
      Dependencies.Http4sCirce,
      Dependencies.Http4sDsl,
      Dependencies.Http4sEmberClient,
      Dependencies.Http4sEmberServer,
      Dependencies.Http4sJdkClient,
      Dependencies.Log4CatsSlf4j,
      Dependencies.Scout,
      Dependencies.Runtime.LogbackClassic,
      Dependencies.Protobuf.ScalaPb,
//      Dependencies.TsecCommon,
//      Dependencies.TsecCipher,
//      Dependencies.TsecHash,
//      Dependencies.TsecMac,
      Dependencies.Test.Annotations,
      Dependencies.Test.Gson,
      Dependencies.Test.MUnitCE3
    )
  )
