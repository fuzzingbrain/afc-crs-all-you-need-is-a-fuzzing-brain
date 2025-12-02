import re
import os
import json

from clang import cindex
from litellm import completion

from prompt import (
    VulnCheckPrompt, 
    FuzzingInputGeneratorPrompt
)


# Enter your API key here
MODEL = "claude-sonnet-4-5-20250929"
ANTHROPIC_API_KEY=""


def load_codebase_lines(codebase_dir):
    result = {}

    for root, dirs, files in os.walk(codebase_dir):
        for filename in files:
            file_path = os.path.join(root, filename)
            abs_path = os.path.abspath(file_path)

            try:
                with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                    lines = [line.rstrip("\n") for line in lines]

                result[abs_path] = lines

            except Exception as e:
                print(f"Failed to read {abs_path}: {e}")

    return result


def extract_functions_with_libclang(filepath: str):
    # TODO: debug
    index = cindex.Index.create()
    tu = index.parse(filepath, args=["-std=c11"])

    func_dict = {}

    for cursor in tu.cursor.walk_preorder():
        if cursor.kind == cindex.CursorKind.FUNCTION_DECL and cursor.is_definition():
            name = cursor.spelling
            extent = cursor.extent
            start = extent.start
            end = extent.end

            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                func_lines = lines[start.line - 1 : end.line]
                func_code = "".join(func_lines)

                func_dict[name] = func_code

    return func_dict


def get_fuzzer_code_path(codebase_path: str):
    fuzzer_code_path = "/home/ze/CRS/afc-crs-all-you-need-is-a-fuzzing-brain/crs/v1/datasets/challenge-libpng/afc-libpng/contrib/oss-fuzz/libpng_read_fuzzer.cc"
    return fuzzer_code_path


def llm_call(model: str, messages: list, api_key: str):
    response = completion(
        model=model,
        messages=messages,
        api_key=api_key
    )
    resp_str = response.choices[0].message.content
    return resp_str


def workflow(codebase_path: str):
    code_dict = load_codebase_lines(codebase_path)

    print("Total files:", len(code_dict))

    codebase_data = []

    for filepath, _ in list(code_dict.items()):
        if not filepath.endswith(".c") and not filepath.endswith(".h"):
            continue
        print(f"Filepath: {filepath}")
        func_dict = extract_functions_with_libclang(filepath)
        print(f"Functions number: {len(func_dict)}")
        catalog_text = "\n".join(list(func_dict.values()))
        content = VulnCheckPrompt().basic(catalog_text)
        response = llm_call(MODEL, content, ANTHROPIC_API_KEY)
        json_str = re.search(r"```json(.*)```", response, re.DOTALL).group(1)
        result = json.loads(json_str)
        functions_data = result
        for func_data in functions_data:
            function_code = func_dict[func_data['name']]
            func_data["code"] = function_code
            content = VulnCheckPrompt().suspicious_points(function_code)
            response = llm_call(MODEL, content, ANTHROPIC_API_KEY)
            json_str = re.search(r"```json(.*)```", response, re.DOTALL).group(1)
            result = json.loads(json_str)
            susp_data = result
            func_data["suspicious_points"] = susp_data

            content = FuzzingInputGeneratorPrompt().basic(function_code, susp_data[0]['name'])
            response = llm_call(MODEL, content, ANTHROPIC_API_KEY)
            python_str = re.search(r"```python(.*)```", response, re.DOTALL).group(1)
            func_data["pov_code"] = python_str
        file_data = {
            "filepath": filepath,
            "functions_data": functions_data
        }
        codebase_data.append(file_data)

    return codebase_data


if __name__ == "__main__":
    codebase_path = "./datasets/challenge-libpng/afc-libpng"
    workflow(codebase_path)