import io.shiftleft.semanticcpg.language._
val cpg = io.shiftleft.codepropertygraph.cpgloading.CpgLoader.load(sys.env("CPG"))
val entryList = sys.env("ENTRY").split(",").toSet
val bug = sys.env("BUG")
val allMethods = cpg.method.l.map{m => (m.name, m.ast.isCall.name.toSet, (m.ast.isIdentifier.name.l).toSet)}
val byName = allMethods.groupBy(_._1)
val exists = byName.contains(bug)
val reach = scala.collection.mutable.Set[String]()
var frontier = entryList.intersect(byName.keySet)
reach ++= frontier; var it=0
while(frontier.nonEmpty && it<80){
  val nx = frontier.flatMap(n=>byName.getOrElse(n,Nil).flatMap(m=> m._2 ++ m._3))
  val nw = nx.intersect(byName.keySet).diff(reach); reach++=nw; frontier=nw; it+=1
}
// who calls bug (by name) among ALL methods?
val callers = allMethods.filter(_._2.contains(bug)).map(_._1)
println(s"BUG=$bug exists=$exists reachable=${reach.contains(bug)} totalReach=${reach.size} callersOfBug=${callers.take(6).mkString(",")} nCallers=${callers.size}")
