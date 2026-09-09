// harness-anchored reachable-sink worklist — overlay-free (CpgLoader), forward-only traversal
import io.shiftleft.semanticcpg.language._
val cpg = io.shiftleft.codepropertygraph.cpgloading.CpgLoader.load(sys.env("CPG"))
val outFile = sys.env("OUT")
val entryList = sys.env("ENTRY").split(",").toSet
// C: CWE-676 / CERT dangerous funcs (published list)
val dangerous = Set("memcpy","memmove","memset","strcpy","strncpy","strcat","strncat",
  "sprintf","vsprintf","snprintf","vsnprintf","alloca","malloc","calloc","realloc",
  "gets","scanf","sscanf","strlen","strdup","bcopy","wcscpy","wcscat")
// Java OOB-/crash-prone stdlib APIs (JDK CWE-129/CWE-125 surface)
val javaRisky = Set("arraycopy","charAt","substring","copyOf","copyOfRange","get","read",
  "getBytes","toCharArray","valueOf","parseInt","parseLong","codePointAt","setLength",
  "position","put","allocate","getInt","getShort","getLong")
// Joern AST memory-op operator nodes (semantic, language-agnostic)
val memOps = Set("<operator>.indirectIndexAccess","<operator>.indirection",
  "<operator>.pointerShift","<operator>.addressOf","<operator>.indexAccess")
def isSink(n: String) = dangerous.contains(n) || javaRisky.contains(n) || memOps.contains(n)

// Per-method summary via FORWARD traversal only (method -> its own calls; base CPG, no overlay)
case class M(name:String, file:String, line:Int, arity:Int, calleeNames:Set[String],
             sinks:List[(Int,String)], refNames:Set[String], indirectArities:Set[Int])
val allMethods: List[M] = cpg.method.l.map { m =>
  val calls = m.ast.isCall.l
  val callee = calls.map(_.name).toSet
  val sk = calls.filter(c => isSink(c.name)).map(c => (c.lineNumber.getOrElse(-1), c.name))
  // address-taken function pointers: identifiers/methodRefs naming a function (callback dispatch)
  val refs = (m.ast.isIdentifier.name.l ++ m.ast.isMethodRef.methodFullName.l.map(_.split(":").head.split("\\.").last)).toSet
  // indirect call sites in this method -> their argument counts (for arity-matched resolution)
  val ind = calls.filter(c => c.dispatchType == "DYNAMIC_DISPATCH").map(_.argument.size).toSet
  M(m.name, m.filename, m.lineNumber.getOrElse(-1), m.parameter.size, callee, sk, refs, ind)
}
val byName = allMethods.groupBy(_.name)
val allMethodNames = byName.keySet
val arityIndex = allMethods.groupBy(_.arity).map{ case(a,ms) => (a, ms.map(_.name).toSet) }

// name-based interprocedural reachability from entry, with arity-matched indirect resolution:
// an indirect (function-pointer / dynamic-dispatch) call site reached from the entry can target
// only address-taken functions whose parameter count matches the call's argument count.
val cfiMode = sys.env.getOrElse("FBAGENT_CFI","off")  // off | arity | full
val globalAddrTaken = allMethods.flatMap(_.refNames).toSet.intersect(allMethodNames)
val reach = scala.collection.mutable.Set[String]()
val distOf = scala.collection.mutable.Map[String,Int]()
var frontier = entryList.intersect(allMethodNames)
val nEntries = frontier.size
reach ++= frontier; frontier.foreach(n => distOf(n) = 0)
if (cfiMode == "full") { reach ++= globalAddrTaken; frontier = frontier ++ globalAddrTaken }
var it = 0
while (frontier.nonEmpty && it < 80) {
  var nextNames = frontier.flatMap(n => byName.getOrElse(n, Nil).flatMap(m => m.calleeNames ++ m.refNames))
  if (cfiMode == "arity") {
    // arities of indirect call sites in the current frontier's methods
    val arities = frontier.flatMap(n => byName.getOrElse(n, Nil).flatMap(_.indirectArities))
    val targets = arities.flatMap(a => arityIndex.getOrElse(a, Set.empty)).intersect(globalAddrTaken)
    nextNames = nextNames ++ targets
  }
  val nw = nextNames.intersect(allMethodNames).diff(reach)
  nw.foreach(n => distOf(n) = it + 1)
  reach ++= nw; frontier = nw; it += 1
}

// memory/CWE-676 sinks inside reachable methods
val memSinks = allMethods.filter(m => reach.contains(m.name))
  .flatMap(m => m.sinks.map { case (l,n) => (m.file, l, m.name, n) }).distinct
def dist(fn: String) = distOf.getOrElse(fn, 99)

// CWE-674 unbounded recursion: reachable methods on a call-graph cycle (Tarjan SCC)
val adj = scala.collection.mutable.Map[String, scala.collection.mutable.Set[String]]()
allMethods.filter(m => reach.contains(m.name)).foreach { m =>
  adj.getOrElseUpdate(m.name, scala.collection.mutable.Set[String]()) ++= m.calleeNames.intersect(reach.toSet)
}
val idx = scala.collection.mutable.Map[String,Int]()
val low = scala.collection.mutable.Map[String,Int]()
val onst = scala.collection.mutable.Set[String]()
val stack = scala.collection.mutable.Stack[String]()
var counter = 0
val recNames = scala.collection.mutable.Set[String]()
val selfLoop = adj.filter{ case(n,s) => s.contains(n) }.keys.toSet
def strongconnect(root: String): Unit = {
  val work = scala.collection.mutable.Stack[(String,Int)]()
  work.push((root,0))
  while (work.nonEmpty) {
    val (v,pi) = work.pop()
    var i = pi
    if (i == 0) { idx(v)=counter; low(v)=counter; counter+=1; stack.push(v); onst+=v }
    val succs = adj.getOrElse(v, scala.collection.mutable.Set[String]()).toArray
    var recursed = false
    while (i < succs.length && !recursed) {
      val w = succs(i)
      if (!idx.contains(w)) { work.push((v,i+1)); work.push((w,0)); recursed=true }
      else { if (onst.contains(w)) low(v)=math.min(low(v),idx(w)); i+=1 }
    }
    if (!recursed) {
      if (low(v)==idx(v)) {
        val comp = scala.collection.mutable.ArrayBuffer[String]()
        var done = false
        while (!done) { val w = stack.pop(); onst-=w; comp+=w; if (w==v) done=true }
        if (comp.size > 1) recNames ++= comp
      }
      if (work.nonEmpty) { val p = work.top._1; low(p)=math.min(low(p),low(v)) }
    }
  }
}
adj.keys.foreach(n => if (!idx.contains(n)) strongconnect(n))
recNames ++= selfLoop
val recSinks = recNames.toList.flatMap(n => byName.getOrElse(n,Nil).headOption.map(m => (m.file, m.line, n, "<recursion>")))

val allSinks = (memSinks ++ recSinks).distinct.sortBy { case (f,l,m,n) => (dist(m), m, l) }
val pw = new java.io.PrintWriter(outFile)
pw.println(s"#entries=$nEntries reachable=${reach.size} sinks=${allSinks.size} recursion=${recSinks.size}")
allSinks.foreach { case (f,l,m,n) => pw.println(s"$f\t$l\t$m\t$n\t${dist(m)}") }
pw.close()
println(s"WROTE ${allSinks.size} sinks (rec=${recSinks.size}) reachable=${reach.size} entries=$nEntries")
