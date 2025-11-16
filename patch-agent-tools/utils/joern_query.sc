import io.joern.dataflowengineoss.language._
import io.shiftleft.semanticcpg.language._

cpg.method.name("__SYMBOL__").take(__LIMIT__).foreach { m =>
  val fname = m.file.name.headOption.getOrElse("")
  val start = m.lineNumber.getOrElse(0)
  val end   = m.lineNumberEnd.getOrElse(start)
  val json  = s"""{"file": "$fname", "start_line": $start, "end_line": $end}"""
  println("OUTPUT: " + json)
}
