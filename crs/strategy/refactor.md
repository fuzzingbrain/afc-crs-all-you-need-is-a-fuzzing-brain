26个策略重复函数提取


83:def get_fallback_model(current_model, tried_models):
109:def setup_logging(fuzzer_name):
134:def log_message(log_file, message):
146:def log_time(log_file, start_time, end_time, function_name, description):
151:def truncate_output(output, max_lines=200):
172:def call_gemini_api(log_file, messages, model_name="gemini-2.5-pro-preview-03-25") -> (str, bool):
224:def call_litellm(log_file, messages, model_name) -> (str, bool):
328:def call_llm(log_file, messages, model_name):
347:def extract_python_code_from_response(log_file, text, max_retries=2, timeout=30):
471:def process_large_diff(diff_content, log_file):
661:def get_commit_info(log_file, project_dir, language):
701:def is_likely_source_for_fuzzer(file_base, fuzzer_name, base_name):
741:def strip_license_text(source_code):
820:def find_fuzzer_source(log_file, fuzzer_path, project_name, project_src_dir, language='c'):
1132:def run_python_code(log_file, code, xbin_dir):
1181:def filter_instrumented_lines(text, max_line_length=200):
1204:def run_fuzzer_with_input(log_file, fuzzer_path, project_dir, focus, blob_path):
1370:def extract_and_save_crash_input(log_file, crash_dir, fuzzer_name, out_dir_x, project_name, sanitizer, project_dir, sanitizer_project_dir):
1518:def log_fuzzer_output(log_file, combined_output, max_line_length=200):
1551:def run_fuzzer_with_coverage(log_file, fuzzer_path, project_dir, focus, sanitizer, project_name, seed_corpus_dir):
1807:def generate_pov(log_file, project_dir, messages, model_name):
1867:def extract_java_fallback_location(output):
1879:def extract_crash_location(output, sanitizer):
1946:def extract_asan_fallback_location(output):
1956:def extract_ubsan_fallback_location(output):
1966:def extract_msan_fallback_location(output):
1977:def generate_vulnerability_signature(output, sanitizer):
2006:def extract_crash_trace(fuzzer_output):
2038:def submit_pov_to_endpoint(log_file, project_dir, blob_path, fuzzer_output,sanitizer, vuln_signature, fuzzer_name):
2248:def check_for_successful_patches(log_file, project_dir):
2280:def extract_crash_output(output):
2346:def after_pov_crash_detected(log_file,model_name,iteration,fuzzer_name,sanitizer,project_name,crash_output,vuln_signature,code,blob_path,messages):
2408:def has_successful_pov0(fuzzer_path):
2419:def has_successful_pov(fuzzer_path,project_dir):
2436:def cleanup_seed_corpus(dir_path, max_age_minutes=10):
2445:def doAdvancedPoV0(log_file, initial_msg, fuzzer_path, fuzzer_name, sanitizer, project_dir, project_name, focus, language='c', check_patch_success=False) -> bool:
2659:def parse_commit_diff(project_src_dir, commit_diff):
2789:def extract_function_body(file_path, function_name):
2851:def extract_call_paths_from_analysis_service(fuzzer_path,fuzzer_src_path, focus, project_src_dir, modified_functions, use_qx):
3008:def doAdvancedPoV(log_file,fuzzer_src_path, fuzzer_code, commit_diff, fuzzer_path, fuzzer_name, sanitizer, project_dir, project_name, focus, language='c', check_patch_success=False) -> bool:
3105:def extract_json_from_response_with_4o(log_file,text):
3119:def get_target_functions(log_file, context_info: str, crash_log: str, model_name):
3180:def extract_java_method(file_path, method_name):
3274:def create_commit_based_prompt(fuzzer_code, commit_diff, sanitizer, language):
3386:def strip_comments_and_license(source_code, file_path):
3434:def create_commit_modified_functions_based_prompt(log_file, fuzzer_code, commit_diff, project_src_dir, modified_functions, sanitizer, language):
3499:def create_commit_call_paths_based_prompt(fuzzer_code, commit_diff, project_src_dir, main_call_path, sanitizer, language):
3575:def create_commit_combine_all_call_paths_based_prompt(fuzzer_code, commit_diff, project_src_dir, call_paths, sanitizer, language):
3662:def create_commit_vul_category_based_prompt_for_c(fuzzer_code, commit_diff, sanitizer, category):
3835:def create_commit_vul_category_based_prompt_for_java(fuzzer_code, commit_diff, sanitizer, category):
4168:def create_fullscan_prompt(fuzzer_code: str, suspected_vuln: Dict[str, Any]) -> str:
4204:def load_suspected_vulns(project_dir: str) -> List[Dict[str, Any]]:
4218:def process_full_scan(log_file, fuzzer_src_path, fuzzer_code, fuzzer_path, fuzzer_name, sanitizer, 
4401:def load_task_detail(fuzz_dir):
4441:def main():




89:def get_fallback_model(current_model, tried_models):
121:def setup_logging(fuzzer_name):
146:def log_message(log_file, message):
158:def log_cost(log_file, model_name, cost):
162:def log_time(log_file, start_time, end_time, function_name, description):
167:def truncate_output(output, max_lines=200):
188:def call_gemini_api(log_file, messages, model_name="gemini-1.0-pro") -> (str, bool):
240:def call_litellm(log_file, messages, model_name) -> (str, bool):
344:def call_o1_pro_api(log_file, messages, model_name):
454:def call_llm(log_file, messages, model_name):
481:def extract_python_code_from_response(log_file, text, max_retries=2, timeout=30):
605:def extract_code(text):
614:def is_python_code(text):
619:def process_large_diff(diff_content, log_file):
821:def get_commit_info(log_file, project_dir, language):
867:def is_likely_source_for_fuzzer(file_base, fuzzer_name, base_name):
907:def strip_license_text(source_code):
991:def find_fuzzer_source(log_file, fuzzer_path, project_name, project_src_dir, focus, language='c'):
1348:def run_python_code(log_file, code, xbin_dir,blob_path):
1392:def filter_instrumented_lines(text, max_line_length=200):
1413:def run_fuzzer_with_input_for_c_coverage(
1516:def run_fuzzer_with_input(log_file, fuzzer_path, project_dir, focus, blob_path, is_c_project=True):
1704:def generate_pov(log_file, project_dir, messages, model_name):
1763:def extract_java_fallback_location(output):
1775:def extract_crash_location(output, sanitizer):
1842:def extract_asan_fallback_location(output):
1852:def extract_ubsan_fallback_location(output):
1862:def extract_msan_fallback_location(output):
1873:def generate_vulnerability_signature(output, sanitizer):
1903:def extract_crash_trace(fuzzer_output):
1935:def submit_pov_to_endpoint(log_file, project_dir, pov_metadata):
2095:def check_for_successful_patches(log_file, project_dir):
2127:def extract_crash_output(output):
2194:def has_successful_pov(fuzzer_path):
2206:def extract_diff_functions_using_funtarget(project_src_dir: str, out_dir: str) -> Union[List[Dict[str, Any]], None]:
2252:def extract_control_flow_for_c(
2337:def _pick_fallback_jar(jar_dir: str) -> str | None:
2346:def extract_control_flow_from_coverage_exec(log_file,project_src_dir,project_jar,coverage_exec_dir):
2412:def cleanup_seed_corpus(dir_path, max_age_minutes=10):
2421:def doPoV(log_file, initial_msg, fuzzer_path, fuzzer_name, sanitizer, project_dir, project_name, focus, language='c', check_patch_success=False) -> bool:
2701:def extract_function_name_from_code(code_block):
2726:def create_commit_based_prompt(fuzzer_code, commit_diff, sanitizer, language):
2838:def load_task_detail(fuzz_dir):
2878:def main():


