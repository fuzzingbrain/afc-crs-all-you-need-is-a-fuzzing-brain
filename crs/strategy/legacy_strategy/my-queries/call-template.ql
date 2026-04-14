/**
 * @name Methods called by FUZZER_CLASS_NAME
 * @description Identifies all methods called by the FUZZER_CLASS_NAME with more flexible matching
 * @kind problem
 * @problem.severity recommendation
 * @id java/FUZZER_CLASS_NAME-called-methods
 * @tags fuzzer
 */

import java

/**
 * Identifies potential fuzzer entry point methods with more flexible matching
 */
class FuzzerMethod extends Method {
  FuzzerMethod() {
    // Try to match by class name (with or without package)
    (
      this.getDeclaringType().getName() = "FUZZER_CLASS_NAME" or
      this.getDeclaringType().getQualifiedName().matches("%.FUZZER_CLASS_NAME")
    ) and
    // Try different possible entry point method names
    (
      this.getName() = "fuzzerTestOneInput" or
      this.getName() = "testOneInput" or
      this.getName().matches("%fuzz%")
    )
  }
}

/**
 * Computes the transitive closure of the call graph
 */
predicate callPlus(Callable caller, Callable callee) {
  // Direct calls
  exists(Call call |
    call.getEnclosingCallable() = caller and
    call.getCallee() = callee
  )
  or
  // Transitive calls
  exists(Callable mid |
    exists(Call call |
      call.getEnclosingCallable() = caller and
      call.getCallee() = mid
    ) and
    callPlus(mid, callee)
  )
}

from FuzzerMethod fuzzer, Method target
where 
  callPlus(fuzzer, target) and
  not target.getQualifiedName().matches("java.%") and
  not target.getQualifiedName().matches("javax.%") 
select 
  target.getQualifiedName(), 
  "Called by fuzzer: " + fuzzer.getQualifiedName() + " in file: " + target.getLocation().getFile().getRelativePath()
