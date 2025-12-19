# Executor: 执行器设计文档

## 概述

Executor是CRS Worker内部的执行组件，负责运行fuzzer验证POV、执行回归测试、构建项目和应用补丁。每个Worker拥有自己的Executor实例。

```
┌────────────────────────────────────────────────────────┐
│                     CRS Worker                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │                    Strategy                       │  │
│  │   (as0_full.py, patch0_full.py, etc.)            │  │
│  │                                                   │  │
│  │   1. 分析代码 → 生成POV/Patch                    │  │
│  │   2. 调用 executor.fuzz.verify_pov()             │  │
│  │   3. 验证通过 → 提交给VulnManager                │  │
│  └──────────────────────────────────────────────────┘  │
│                          │                              │
│                          ▼                              │
│  ┌──────────────────────────────────────────────────┐  │
│  │                   Executor                        │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐   │  │
│  │  │FuzzExecutor│ │TestExecutor│ │BuildExecutor│   │  │
│  │  └────────────┘ └────────────┘ └────────────┘   │  │
│  └──────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────┘
```

---

## 1. 数据模型

### 1.1 Worker任务分配

```python
from pydantic import BaseModel, Field
from typing import List, Optional
from enum import Enum


class Sanitizer(str, Enum):
    ADDRESS = "address"
    MEMORY = "memory"
    UNDEFINED = "undefined"


class WorkerAssignment(BaseModel):
    """Controller分配给Worker的任务"""
    task_id: str
    worker_id: str

    # 当前Worker负责的fuzzer和sanitizer
    assigned_fuzzer: str          # e.g., "fuzz_png"
    assigned_sanitizer: Sanitizer  # e.g., "address"

    # 所有fuzzer列表（用于跨fuzzer验证）
    all_fuzzers: List[str]        # e.g., ["fuzz_png", "fuzz_jpeg", "fuzz_gif"]

    # 路径信息
    project_dir: str              # workspace根目录
    src_dir: str                  # 源码目录
    fuzz_tooling_dir: str         # fuzz-tooling目录

    # 项目信息
    project_name: str             # e.g., "libpng"
    language: str                 # "c", "cpp", "java"
```

### 1.2 执行结果

```python
from dataclasses import dataclass
from typing import Optional
from datetime import datetime


@dataclass
class ExecResult:
    """命令执行结果"""
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    command: str


@dataclass
class FuzzerResult:
    """Fuzzer运行结果"""
    triggered_bug: bool           # 是否触发了bug
    sanitizer_output: str         # sanitizer报告
    crash_type: Optional[str]     # 崩溃类型: heap-buffer-overflow, use-after-free, etc.
    fuzzer_name: str
    blob_path: str
    exit_code: int
    duration_seconds: float


@dataclass
class BuildResult:
    """构建结果"""
    success: bool
    stdout: str
    stderr: str
    duration_seconds: float
    output_dir: str               # 构建输出目录


@dataclass
class PatchResult:
    """补丁应用结果"""
    apply_success: bool           # 补丁是否成功应用
    build_success: bool           # 应用后是否编译通过
    pov_pass: bool                # 是否通过POV测试（不再触发bug）
    test_pass: bool               # 是否通过回归测试
    error_message: Optional[str]
    diff_content: str             # git diff内容
```

---

## 2. Executor架构

### 2.1 主类设计

```python
# executor/executor.py

import os
import subprocess
import uuid
import shutil
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass

from .fuzz_executor import FuzzExecutor
from .test_executor import TestExecutor
from .build_executor import BuildExecutor
from ..models.executor_models import WorkerAssignment, ExecResult


class Executor:
    """
    执行器 - Worker内部的执行组件

    负责：
    - 运行fuzzer验证POV
    - 执行回归测试
    - 构建项目
    - 应用补丁
    """

    # 崩溃指示器
    CRASH_INDICATORS = [
        "ERROR: AddressSanitizer:",
        "ERROR: MemorySanitizer:",
        "WARNING: MemorySanitizer:",
        "ERROR: ThreadSanitizer:",
        "ERROR: UndefinedBehaviorSanitizer:",
        "SEGV on unknown address",
        "Segmentation fault",
        "runtime error:",
        "AddressSanitizer: heap-buffer-overflow",
        "AddressSanitizer: heap-use-after-free",
        "UndefinedBehaviorSanitizer: undefined-behavior",
        "AddressSanitizer:DEADLYSIGNAL",
        "Java Exception: com.code_intelligence.jazzer",
        "ERROR: HWAddressSanitizer:",
        "WARNING: ThreadSanitizer:",
    ]

    def __init__(self, assignment: WorkerAssignment):
        self.assignment = assignment
        self.task_id = assignment.task_id
        self.worker_id = assignment.worker_id
        self.project_dir = Path(assignment.project_dir)
        self.src_dir = Path(assignment.src_dir)
        self.fuzz_tooling_dir = Path(assignment.fuzz_tooling_dir)

        # 当前负责的fuzzer
        self.current_fuzzer = assignment.assigned_fuzzer
        self.current_sanitizer = assignment.assigned_sanitizer

        # 所有fuzzer（用于跨fuzzer验证）
        self.all_fuzzers = assignment.all_fuzzers

        # 项目信息
        self.project_name = assignment.project_name
        self.language = assignment.language

        # 子执行器
        self.fuzz = FuzzExecutor(self)
        self.test = TestExecutor(self)
        self.build = BuildExecutor(self)

        # Docker镜像缓存
        self._docker_image: Optional[str] = None

    @property
    def docker_image(self) -> str:
        """获取Docker镜像名称（带缓存）"""
        if self._docker_image is None:
            self._docker_image = self._find_docker_image()
        return self._docker_image

    def _find_docker_image(self) -> str:
        """查找项目的Docker镜像"""
        # 尝试 aixcc-afc/{project_name}
        result = subprocess.run(
            ["docker", "images", f"aixcc-afc/{self.project_name}",
             "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().split('\n')[0]

        # 尝试 gcr.io/oss-fuzz/{project_name}
        result = subprocess.run(
            ["docker", "images", f"gcr.io/oss-fuzz/{self.project_name}",
             "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().split('\n')[0]

        raise RuntimeError(f"Docker image not found for {self.project_name}")

    def _get_fuzzer_path(self, fuzzer_name: str) -> Path:
        """获取fuzzer可执行文件路径"""
        out_dir = self.fuzz_tooling_dir / "build" / "out" / f"{self.project_name}-{self.current_sanitizer.value}"
        return out_dir / fuzzer_name

    def _get_out_dir(self, fuzzer_name: str, suffix: str = "") -> Path:
        """获取输出目录"""
        dir_name = f"{self.project_name}-{self.current_sanitizer.value}"
        if suffix:
            dir_name = f"{dir_name}-{suffix}"
        out_dir = self.fuzz_tooling_dir / "build" / "out" / dir_name
        out_dir.mkdir(parents=True, exist_ok=True)
        return out_dir

    def _get_work_dir(self, fuzzer_name: str, suffix: str = "") -> Path:
        """获取工作目录"""
        dir_name = f"{self.project_name}-{self.current_sanitizer.value}"
        if suffix:
            dir_name = f"{dir_name}-{suffix}"
        work_dir = self.fuzz_tooling_dir / "build" / "work" / dir_name
        work_dir.mkdir(parents=True, exist_ok=True)
        return work_dir

    def is_crash_output(self, output: str) -> bool:
        """检查输出是否包含崩溃指示器"""
        return any(indicator in output for indicator in self.CRASH_INDICATORS)

    def extract_crash_type(self, output: str) -> Optional[str]:
        """从输出中提取崩溃类型"""
        crash_types = {
            "heap-buffer-overflow": "AddressSanitizer: heap-buffer-overflow",
            "heap-use-after-free": "AddressSanitizer: heap-use-after-free",
            "stack-buffer-overflow": "AddressSanitizer: stack-buffer-overflow",
            "use-after-free": "use-after-free",
            "null-dereference": "null pointer dereference",
            "undefined-behavior": "UndefinedBehaviorSanitizer",
            "memory-leak": "LeakSanitizer",
            "integer-overflow": "integer overflow",
        }
        for crash_type, indicator in crash_types.items():
            if indicator in output:
                return crash_type
        return None
```

### 2.2 FuzzExecutor - Fuzzer执行

```python
# executor/fuzz_executor.py

import os
import subprocess
import uuid
import shutil
import time
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional

from ..models.executor_models import FuzzerResult

if TYPE_CHECKING:
    from .executor import Executor


class FuzzExecutor:
    """Fuzzer执行器 - 负责运行fuzzer验证POV"""

    def __init__(self, parent: "Executor"):
        self.parent = parent

    async def verify_pov(
        self,
        blob: bytes,
        fuzzer_name: Optional[str] = None,
        timeout: int = 30
    ) -> FuzzerResult:
        """
        验证POV是否能触发bug

        Args:
            blob: POV的二进制内容
            fuzzer_name: 要使用的fuzzer，默认使用当前分配的fuzzer
            timeout: 超时时间（秒）

        Returns:
            FuzzerResult: 验证结果
        """
        fuzzer = fuzzer_name or self.parent.current_fuzzer
        return await self._run_fuzzer_with_blob(blob, fuzzer, timeout)

    async def verify_pov_all_fuzzers(
        self,
        blob: bytes,
        timeout: int = 30
    ) -> Dict[str, FuzzerResult]:
        """
        在所有fuzzer上验证POV

        Args:
            blob: POV的二进制内容
            timeout: 每个fuzzer的超时时间（秒）

        Returns:
            Dict[str, FuzzerResult]: {fuzzer_name: result}
        """
        results = {}
        for fuzzer in self.parent.all_fuzzers:
            results[fuzzer] = await self._run_fuzzer_with_blob(blob, fuzzer, timeout)
        return results

    async def _run_fuzzer_with_blob(
        self,
        blob: bytes,
        fuzzer_name: str,
        timeout: int
    ) -> FuzzerResult:
        """运行fuzzer测试单个blob"""
        start_time = time.time()

        # 生成唯一的blob文件名
        unique_id = str(uuid.uuid4())[:8]
        blob_filename = f"pov_{unique_id}.bin"

        # 获取路径
        out_dir = self.parent._get_out_dir(fuzzer_name)
        work_dir = self.parent._get_work_dir(fuzzer_name)
        blob_path = out_dir / blob_filename

        # 写入blob文件
        blob_path.write_bytes(blob)

        try:
            # 构建Docker命令
            docker_cmd = [
                "docker", "run", "--rm",
                "--platform", "linux/amd64",
                "-e", "FUZZING_ENGINE=libfuzzer",
                "-e", f"SANITIZER={self.parent.current_sanitizer.value}",
                "-e", "ARCHITECTURE=x86_64",
                "-e", f"PROJECT_NAME={self.parent.project_name}",
                "-v", f"{self.parent.src_dir}:/src/{self.parent.project_name}",
                "-v", f"{out_dir}:/out",
                "-v", f"{work_dir}:/work",
                self.parent.docker_image,
                f"/out/{fuzzer_name}",
                f"-timeout={timeout}",
                "-timeout_exitcode=99",
                f"/out/{blob_filename}"
            ]

            # 执行
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 30  # 额外30秒给Docker启动
            )

            duration = time.time() - start_time
            combined_output = result.stderr + "\n" + result.stdout

            # 判断是否触发bug
            triggered_bug = (
                result.returncode != 0 and
                self.parent.is_crash_output(combined_output)
            )

            return FuzzerResult(
                triggered_bug=triggered_bug,
                sanitizer_output=combined_output,
                crash_type=self.parent.extract_crash_type(combined_output) if triggered_bug else None,
                fuzzer_name=fuzzer_name,
                blob_path=str(blob_path),
                exit_code=result.returncode,
                duration_seconds=duration
            )

        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return FuzzerResult(
                triggered_bug=False,
                sanitizer_output="Timeout expired",
                crash_type=None,
                fuzzer_name=fuzzer_name,
                blob_path=str(blob_path),
                exit_code=-1,
                duration_seconds=duration
            )

        finally:
            # 清理blob文件
            if blob_path.exists():
                blob_path.unlink()
```

### 2.3 BuildExecutor - 构建执行

```python
# executor/build_executor.py

import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from ..models.executor_models import BuildResult, PatchResult

if TYPE_CHECKING:
    from .executor import Executor


class BuildExecutor:
    """构建执行器 - 负责构建项目和应用补丁"""

    def __init__(self, parent: "Executor"):
        self.parent = parent

    async def build(
        self,
        sanitizer: Optional[str] = None,
        suffix: str = ""
    ) -> BuildResult:
        """
        构建项目

        Args:
            sanitizer: 使用的sanitizer，默认使用当前分配的
            suffix: 输出目录后缀（用于区分不同的patch构建）

        Returns:
            BuildResult: 构建结果
        """
        start_time = time.time()
        san = sanitizer or self.parent.current_sanitizer.value

        # 获取目录
        out_dir = self.parent._get_out_dir(self.parent.current_fuzzer, suffix)
        work_dir = self.parent._get_work_dir(self.parent.current_fuzzer, suffix)

        # 确定语言
        fuzz_language = "jvm" if self.parent.language == "java" else "c++"

        # 构建Docker命令
        docker_cmd = [
            "docker", "run",
            "--privileged",
            "--shm-size=8g",
            "--platform", "linux/amd64",
            "--rm",
            "-e", "FUZZING_ENGINE=libfuzzer",
            "-e", f"SANITIZER={san}",
            "-e", "ARCHITECTURE=x86_64",
            "-e", f"PROJECT_NAME={self.parent.project_name}",
            "-e", f"FUZZING_LANGUAGE={fuzz_language}",
            "-v", f"{self.parent.src_dir}:/src/{self.parent.project_name}",
            "-v", f"{out_dir}:/out",
            "-v", f"{work_dir}:/work",
            self.parent.docker_image,
            "compile"
        ]

        try:
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10分钟构建超时
            )

            duration = time.time() - start_time
            return BuildResult(
                success=result.returncode == 0,
                stdout=result.stdout,
                stderr=result.stderr,
                duration_seconds=duration,
                output_dir=str(out_dir)
            )

        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return BuildResult(
                success=False,
                stdout="",
                stderr="Build timeout expired",
                duration_seconds=duration,
                output_dir=str(out_dir)
            )

    async def apply_patch(
        self,
        patch_content: str,
        patch_id: str
    ) -> PatchResult:
        """
        应用补丁并验证

        Args:
            patch_content: 补丁内容（可以是unified diff或函数替换）
            patch_id: 补丁ID（用于区分不同的构建目录）

        Returns:
            PatchResult: 补丁应用结果
        """
        # 1. 备份源码
        backup_dir = self.parent.src_dir.parent / f"src_backup_{patch_id}"
        if backup_dir.exists():
            shutil.rmtree(backup_dir)
        shutil.copytree(self.parent.src_dir, backup_dir)

        try:
            # 2. 应用补丁
            apply_success = await self._apply_patch_to_source(patch_content)
            if not apply_success:
                return PatchResult(
                    apply_success=False,
                    build_success=False,
                    pov_pass=False,
                    test_pass=False,
                    error_message="Failed to apply patch",
                    diff_content=""
                )

            # 3. 获取diff
            diff_result = subprocess.run(
                ["git", "diff"],
                cwd=self.parent.src_dir,
                capture_output=True,
                text=True
            )
            diff_content = diff_result.stdout

            # 4. 构建
            build_result = await self.build(suffix=patch_id)
            if not build_result.success:
                return PatchResult(
                    apply_success=True,
                    build_success=False,
                    pov_pass=False,
                    test_pass=False,
                    error_message=f"Build failed: {build_result.stderr}",
                    diff_content=diff_content
                )

            return PatchResult(
                apply_success=True,
                build_success=True,
                pov_pass=False,  # 由调用方单独验证
                test_pass=False,  # 由调用方单独验证
                error_message=None,
                diff_content=diff_content
            )

        finally:
            # 5. 恢复源码
            shutil.rmtree(self.parent.src_dir)
            shutil.move(backup_dir, self.parent.src_dir)

    async def _apply_patch_to_source(self, patch_content: str) -> bool:
        """将补丁应用到源码"""
        # 尝试git apply
        result = subprocess.run(
            ["git", "apply", "--check", "-"],
            input=patch_content,
            cwd=self.parent.src_dir,
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            # 实际应用
            subprocess.run(
                ["git", "apply", "-"],
                input=patch_content,
                cwd=self.parent.src_dir,
                check=True
            )
            return True

        return False
```

### 2.4 TestExecutor - 测试执行

```python
# executor/test_executor.py

import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from ..models.executor_models import ExecResult

if TYPE_CHECKING:
    from .executor import Executor


class TestExecutor:
    """测试执行器 - 负责运行回归测试"""

    def __init__(self, parent: "Executor"):
        self.parent = parent

    async def run_regression_test(
        self,
        test_script: Optional[str] = None,
        timeout: int = 300
    ) -> ExecResult:
        """
        运行回归测试

        Args:
            test_script: 测试脚本路径，默认使用项目的test.sh
            timeout: 超时时间（秒）

        Returns:
            ExecResult: 测试结果
        """
        start_time = time.time()

        # 查找测试脚本
        if test_script:
            script_path = Path(test_script)
        else:
            # 尝试常见的测试脚本位置
            possible_scripts = [
                self.parent.fuzz_tooling_dir / "test.sh",
                self.parent.src_dir / "test.sh",
                self.parent.src_dir / "run_tests.sh",
            ]
            script_path = None
            for p in possible_scripts:
                if p.exists():
                    script_path = p
                    break

        if not script_path or not script_path.exists():
            return ExecResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr="No test script found",
                duration_seconds=0,
                command=""
            )

        # 运行测试
        try:
            result = subprocess.run(
                ["bash", str(script_path)],
                cwd=self.parent.src_dir,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            duration = time.time() - start_time
            return ExecResult(
                success=result.returncode == 0,
                exit_code=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                duration_seconds=duration,
                command=f"bash {script_path}"
            )

        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return ExecResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr="Test timeout expired",
                duration_seconds=duration,
                command=f"bash {script_path}"
            )
```

---

## 3. 使用示例

### 3.1 Strategy中使用Executor

```python
# strategy/example_strategy.py

from executor import Executor
from models import WorkerAssignment, POV, Patch


async def run_strategy(assignment: WorkerAssignment):
    """示例策略"""

    # 创建Executor
    executor = Executor(assignment)

    # ========== POV生成与验证 ==========

    # 1. 生成POV (由LLM生成blob)
    blob = generate_pov_blob(...)  # LLM生成

    # 2. 在当前fuzzer上验证
    result = await executor.fuzz.verify_pov(blob)

    if result.triggered_bug:
        print(f"POV triggered {result.crash_type}!")

        # 3. 可选：在所有fuzzer上验证
        all_results = await executor.fuzz.verify_pov_all_fuzzers(blob)
        for fuzzer, res in all_results.items():
            print(f"  {fuzzer}: {'CRASH' if res.triggered_bug else 'OK'}")

        # 4. 提交给VulnManager
        submit_pov(POV(
            blob=blob,
            description="...",
            sanitizer_output=result.sanitizer_output,
            harness_name=result.fuzzer_name,
        ))

    # ========== Patch生成与验证 ==========

    # 1. 生成Patch (由LLM生成)
    patch_content = generate_patch(...)  # LLM生成

    # 2. 应用并构建
    patch_result = await executor.build.apply_patch(
        patch_content=patch_content,
        patch_id="patch_001"
    )

    if patch_result.build_success:
        print("Patch applied and built successfully!")

        # 3. 验证POV是否被修复
        verify_result = await executor.fuzz.verify_pov(blob)
        patch_result.pov_pass = not verify_result.triggered_bug

        # 4. 运行回归测试
        test_result = await executor.test.run_regression_test()
        patch_result.test_pass = test_result.success

        if patch_result.pov_pass and patch_result.test_pass:
            print("Patch is valid! Submitting...")
            submit_patch(Patch(
                diff=patch_result.diff_content,
                description="...",
            ))
```

### 3.2 完整的验证流程

```python
async def verify_and_submit_pov(
    executor: Executor,
    blob: bytes,
    description: str
) -> bool:
    """验证POV并提交"""

    # 1. 快速验证（当前fuzzer）
    result = await executor.fuzz.verify_pov(blob)

    if not result.triggered_bug:
        return False

    # 2. 全量验证（所有fuzzer）
    all_results = await executor.fuzz.verify_pov_all_fuzzers(blob)
    triggered_fuzzers = [
        name for name, res in all_results.items()
        if res.triggered_bug
    ]

    # 3. 构建POV对象
    pov = POV(
        task_id=executor.task_id,
        blob=base64.b64encode(blob).decode(),
        description=description,
        sanitizer_output=result.sanitizer_output,
        harness_name=executor.current_fuzzer,
        is_successful=True,
        sanitizer=executor.current_sanitizer.value,
        triggered_fuzzers=triggered_fuzzers,
    )

    # 4. 提交给VulnManager
    await vuln_manager.submit_pov(pov)
    return True


async def verify_and_submit_patch(
    executor: Executor,
    patch_content: str,
    target_pov: POV,
    description: str
) -> bool:
    """验证Patch并提交"""

    patch_id = str(uuid.uuid4())[:8]

    # 1. 应用补丁并构建
    patch_result = await executor.build.apply_patch(patch_content, patch_id)

    if not patch_result.build_success:
        return False

    # 2. 验证POV被修复
    blob = base64.b64decode(target_pov.blob)
    verify_result = await executor.fuzz.verify_pov(blob)
    patch_result.pov_pass = not verify_result.triggered_bug

    if not patch_result.pov_pass:
        return False

    # 3. 运行回归测试
    test_result = await executor.test.run_regression_test()
    patch_result.test_pass = test_result.success

    if not patch_result.test_pass:
        return False

    # 4. 构建Patch对象
    patch = Patch(
        task_id=executor.task_id,
        pov_id=target_pov.id,
        diff=patch_result.diff_content,
        description=description,
        apply_check=True,
        compilation_check=True,
        pov_check=True,
        test_check=True,
    )

    # 5. 提交给VulnManager
    await vuln_manager.submit_patch(patch)
    return True
```

---

## 4. 目录结构

```
FuzzingBrain-v2/
└── v2/
    └── executor/
        ├── __init__.py
        ├── executor.py          # 主类
        ├── fuzz_executor.py     # Fuzzer执行
        ├── build_executor.py    # 构建执行
        └── test_executor.py     # 测试执行
```

---

## 5. 配置项

```python
# config/executor_config.py

from pydantic import BaseSettings


class ExecutorConfig(BaseSettings):
    """Executor配置"""

    # 超时设置（秒）
    fuzzer_timeout: int = 30
    build_timeout: int = 600
    test_timeout: int = 300

    # Docker设置
    docker_platform: str = "linux/amd64"
    docker_shm_size: str = "8g"

    # 重试设置
    max_retries: int = 3
    retry_delay: float = 1.0

    class Config:
        env_prefix = "EXECUTOR_"
```

---

## 6. 错误处理

```python
class ExecutorError(Exception):
    """Executor基础异常"""
    pass


class DockerImageNotFoundError(ExecutorError):
    """Docker镜像未找到"""
    pass


class BuildError(ExecutorError):
    """构建失败"""
    pass


class FuzzerError(ExecutorError):
    """Fuzzer执行失败"""
    pass


class PatchApplyError(ExecutorError):
    """补丁应用失败"""
    pass
```
