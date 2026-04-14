import java

/**
 * Track method calls
 */
predicate callsMethod(Callable caller, Callable callee) {
  exists(Call call |
    call.getEnclosingCallable() = caller and
    call.getCallee() = callee
  )
}

/**
 * Recursively find call paths and include location information for each method in the path
 */
predicate hasCallPathWithLocations(
  Callable source, Callable target, 
  string path, int depth, 
  string locations // Contains location information for all methods in the path, format: file1:line1|file2:line2|...
) {
  // Direct call
  callsMethod(source, target) and
  path = source.getDeclaringType().getQualifiedName() + "." + source.getName() + " -> " + 
         target.getDeclaringType().getQualifiedName() + "." + target.getName() and
  depth = 1 and
  locations = source.getLocation().getFile().getRelativePath() + ":" + 
              source.getLocation().getStartLine() + "|" +
              target.getLocation().getFile().getRelativePath() + ":" +
              target.getLocation().getStartLine()
  or
  // Indirect call
  depth <= 10 and
  exists(Callable mid, string midPath, int midDepth, string midLocations |
    callsMethod(source, mid) and
    mid != source and
    mid != target and
    hasCallPathWithLocations(mid, target, midPath, midDepth, midLocations) and
    depth = midDepth + 1 and
    path = source.getDeclaringType().getQualifiedName() + "." + source.getName() + " -> " + midPath and
    // Add the current method's location information to the front of the path
    locations = source.getLocation().getFile().getRelativePath() + ":" + 
                source.getLocation().getStartLine() + "|" + midLocations
  )
}

from Callable sourceMethod, Callable targetMethod, string callPath, int depth, string locations
where 
  // Source method and file - placeholders for replacement
  sourceMethod.getLocation().getFile().getBaseName() = "{{SOURCE_FILE}}" and
  sourceMethod.getName() = "{{SOURCE_METHOD}}" and
  
  // Target method and file - placeholders for replacement
  targetMethod.getName() = "{{TARGET_METHOD}}" and

  // Find call paths with location information
  hasCallPathWithLocations(sourceMethod, targetMethod, callPath, depth, locations)

select 
  callPath,                                      // Call path
  depth,                                         // Call depth
  locations,                                     // Location information for all methods in the path
  sourceMethod.getLocation().getFile().getRelativePath(),  // Source file path
  sourceMethod.getLocation().getStartLine(),     // Source method start line
  targetMethod.getLocation().getFile().getRelativePath(),  // Target file path
  targetMethod.getLocation().getStartLine()      // Target method start line
