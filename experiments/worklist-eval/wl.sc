// harness-anchored reachable-sink worklist (Joern CPG)
// sinks: CWE-676 dangerous funcs (published list) + Joern AST memory-op operators
import scala.util.Using
import java.io.PrintWriter

@main def exec(inPath: String, outFile: String, entryNames: String) = {
  importCode(inputPath=inPath, projectName="p")
  val entryList = entryNames.split(",").toSet
  val entries = cpg.method.filter(m => entryList.contains(m.name)).l
  // CWE-676 / CERT dangerous functions (standard published list)
  val dangerous = Set("memcpy","memmove","memset","strcpy","strncpy","strcat","strncat",
    "sprintf","vsprintf","snprintf","vsnprintf","alloca","malloc","calloc","realloc",
    "gets","scanf","sscanf","strlen","strdup","bcopy")
  // Joern AST memory-op operator nodes (semantic, not textual)
  val memOps = Set("<operator>.indirectIndexAccess","<operator>.indirection",
    "<operator>.pointerShift","<operator>.addressOf")
  def isSink(name: String) = dangerous.contains(name) || memOps.contains(name)

  // call-graph reachable methods from entries (interprocedural closure)
  val reach = scala.collection.mutable.Set[String]()
  var frontier = entries.fullName.toSet
  reach ++= frontier
  var iter = 0
  while (frontier.nonEmpty && iter < 40) {
    val callees = cpg.method.filter(m => frontier.contains(m.fullName))
                     .call.callee.fullName.toSet
    val nw = callees.diff(reach)
    reach ++= nw; frontier = nw; iter += 1
  }
  // sinks inside reachable methods
  val sinks = cpg.call.filter(c => isSink(c.name))
                 .filter(c => reach.contains(c.method.fullName))
                 .map(c => (c.method.filename, c.lineNumber.getOrElse(-1), c.method.name, c.name))
                 .l.distinct
  val pw = new PrintWriter(outFile)
  pw.println(s"#entries=${entries.size} reachable_methods=${reach.size} sinks=${sinks.size}")
  sinks.foreach { case (f,l,m,n) => pw.println(s"$f\t$l\t$m\t$n") }
  pw.close()
  println(s"WROTE ${sinks.size} sinks to $outFile (reachable_methods=${reach.size})")
}
