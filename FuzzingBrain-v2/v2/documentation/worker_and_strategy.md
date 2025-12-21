# Worker & Strategy Architecture

## Overview

Worker 执行 Strategy，Strategy 封装具体的 fuzzing/POV/Patch 生成逻辑。

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Worker (Celery Task)                           │
│  ┌───────────────┐    ┌───────────────┐    ┌───────────────────────────┐   │
│  │ WorkerBuilder │ -> │ WorkerExecutor│ -> │ cleanup_worker_workspace  │   │
│  │   (编译)      │    │  (执行策略)   │    │      (清理)               │   │
│  └───────────────┘    └───────┬───────┘    └───────────────────────────┘   │
│                               │                                             │
│                               ▼                                             │
│                    ┌──────────────────────┐                                 │
│                    │   StrategyLoader     │                                 │
│                    │   (加载/选择策略)    │                                 │
│                    └──────────┬───────────┘                                 │
│                               │                                             │
│         ┌─────────────────────┼─────────────────────┐                       │
│         ▼                     ▼                     ▼                       │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐                  │
│  │DefaultStrat │      │ AIStrategy  │      │CustomStrategy│                 │
│  │(libFuzzer)  │      │(AI-guided)  │      │ (用户自定义) │                 │
│  └─────────────┘      └─────────────┘      └─────────────┘                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Strategy 基类设计

### BaseStrategy (抽象基类)

```python
# fuzzingbrain/worker/strategy/base.py

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Any, List, Optional
from pathlib import Path


@dataclass
class StrategyContext:
    """Strategy 执行上下文"""
    workspace_path: Path
    project_name: str
    fuzzer: str
    sanitizer: str
    job_type: str  # pov | patch | pov-patch | harness
    task_id: str
    worker_id: str

    # 路径
    repo_path: Path
    fuzz_tooling_path: Path
    results_path: Path
    crashes_path: Path
    povs_path: Path
    patches_path: Path

    # 数据库访问
    repos: "RepositoryManager"


@dataclass
class StrategyResult:
    """Strategy 执行结果"""
    success: bool
    crashes: List[str] = None
    povs_found: int = 0
    patches_found: int = 0
    error_msg: Optional[str] = None
    metrics: Dict[str, Any] = None  # 执行指标


class BaseStrategy(ABC):
    """
    Strategy 抽象基类

    用户继承此类实现自定义 fuzzing 策略
    """

    # 策略元信息
    name: str = "base"
    description: str = "Base strategy (abstract)"
    version: str = "1.0.0"

    def __init__(self, context: StrategyContext):
        self.ctx = context
        self.logger = self._setup_logger()

    def _setup_logger(self):
        """获取带策略名称的 logger"""
        from loguru import logger
        return logger.bind(strategy=self.name)

    # ============ 主入口 ============

    def run(self) -> StrategyResult:
        """
        主执行入口 (模板方法)

        子类一般不需要重写此方法，而是重写下面的 hook 方法
        """
        self.logger.info(f"Strategy [{self.name}] starting")

        try:
            # 1. 初始化
            self.setup()

            # 2. 执行 fuzzing
            crashes = self.fuzz()

            if not crashes:
                self.logger.info("No crashes found")
                return StrategyResult(success=True, crashes=[])

            # 3. 生成 POV (if applicable)
            povs = []
            if self.ctx.job_type in ["pov", "pov-patch"]:
                povs = self.generate_povs(crashes)

            # 4. 生成 Patch (if applicable)
            patches = []
            if self.ctx.job_type in ["patch", "pov-patch"]:
                patches = self.generate_patches(crashes)

            # 5. 清理
            self.teardown()

            return StrategyResult(
                success=True,
                crashes=crashes,
                povs_found=len(povs),
                patches_found=len(patches),
            )

        except Exception as e:
            self.logger.exception(f"Strategy failed: {e}")
            return StrategyResult(success=False, error_msg=str(e))

    # ============ Hook 方法 (子类实现) ============

    def setup(self) -> None:
        """初始化，准备环境"""
        pass

    @abstractmethod
    def fuzz(self) -> List[str]:
        """
        执行 fuzzing，返回 crash 文件路径列表

        子类必须实现此方法
        """
        raise NotImplementedError

    def generate_povs(self, crashes: List[str]) -> List[str]:
        """
        从 crashes 生成 POV

        Args:
            crashes: crash 文件路径列表

        Returns:
            POV ID 列表
        """
        return []

    def generate_patches(self, crashes: List[str]) -> List[str]:
        """
        生成补丁

        Returns:
            Patch ID 列表
        """
        return []

    def teardown(self) -> None:
        """清理资源"""
        pass

    # ============ 辅助方法 ============

    def get_fuzzer_binary(self) -> Path:
        """获取编译好的 fuzzer 二进制路径"""
        return (
            self.ctx.fuzz_tooling_path / "build" / "out" /
            self.ctx.project_name / self.ctx.fuzzer
        )

    def save_pov(self, pov_data: bytes, crash_hash: str) -> str:
        """保存 POV 到数据库"""
        from ..core.models import POV
        pov = POV(
            task_id=self.ctx.task_id,
            worker_id=self.ctx.worker_id,
            fuzzer=self.ctx.fuzzer,
            sanitizer=self.ctx.sanitizer,
            blob=pov_data,
            crash_hash=crash_hash,
        )
        self.ctx.repos.povs.save(pov)
        return pov.pov_id

    def save_patch(self, patch_content: str, description: str) -> str:
        """保存 Patch 到数据库"""
        from ..core.models import Patch
        patch = Patch(
            task_id=self.ctx.task_id,
            worker_id=self.ctx.worker_id,
            content=patch_content,
            description=description,
        )
        self.ctx.repos.patches.save(patch)
        return patch.patch_id
```

---

## DefaultStrategy (默认实现)

```python
# fuzzingbrain/worker/strategy/default.py

import subprocess
import os
from pathlib import Path
from typing import List

from .base import BaseStrategy, StrategyResult


class DefaultStrategy(BaseStrategy):
    """
    默认 libFuzzer 策略

    执行标准 libFuzzer fuzzing 流程
    """

    name = "default"
    description = "Standard libFuzzer fuzzing strategy"
    version = "1.0.0"

    # 配置
    FUZZ_TIMEOUT = 300  # 5 minutes per run
    MAX_TOTAL_TIME = 3600  # 1 hour total
    CORPUS_DIR = "corpus"

    def setup(self) -> None:
        """创建必要的目录"""
        (self.ctx.results_path / self.CORPUS_DIR).mkdir(exist_ok=True)

    def fuzz(self) -> List[str]:
        """
        执行 libFuzzer

        Returns:
            crash 文件路径列表
        """
        fuzzer_bin = self.get_fuzzer_binary()

        if not fuzzer_bin.exists():
            raise FileNotFoundError(f"Fuzzer binary not found: {fuzzer_bin}")

        self.logger.info(f"Running fuzzer: {fuzzer_bin}")

        # libFuzzer 参数
        corpus_dir = self.ctx.results_path / self.CORPUS_DIR
        crash_dir = self.ctx.crashes_path

        cmd = [
            str(fuzzer_bin),
            str(corpus_dir),
            f"-artifact_prefix={crash_dir}/",
            f"-max_total_time={self.MAX_TOTAL_TIME}",
            "-print_final_stats=1",
        ]

        # 环境变量
        env = os.environ.copy()
        env["ASAN_OPTIONS"] = "abort_on_error=1:symbolize=1"

        self.logger.info(f"Command: {' '.join(cmd)}")

        try:
            process = subprocess.run(
                cmd,
                cwd=str(self.ctx.workspace_path),
                env=env,
                capture_output=True,
                text=True,
                timeout=self.MAX_TOTAL_TIME + 60,
            )

            # Log output
            if process.stdout:
                self.logger.debug(f"stdout: {process.stdout[-2000:]}")
            if process.stderr:
                self.logger.debug(f"stderr: {process.stderr[-2000:]}")

        except subprocess.TimeoutExpired:
            self.logger.warning("Fuzzing timeout reached")

        # 收集 crash 文件
        crashes = self._collect_crashes()
        self.logger.info(f"Found {len(crashes)} crashes")

        return crashes

    def _collect_crashes(self) -> List[str]:
        """收集 crash 文件"""
        crashes = []
        crash_dir = self.ctx.crashes_path

        for f in crash_dir.iterdir():
            if f.is_file() and f.name.startswith(("crash-", "leak-", "timeout-")):
                crashes.append(str(f))

        return crashes

    def generate_povs(self, crashes: List[str]) -> List[str]:
        """
        从 crash 生成 POV

        简单实现: 直接把 crash input 作为 POV
        """
        povs = []

        for crash_path in crashes:
            crash_file = Path(crash_path)
            crash_data = crash_file.read_bytes()
            crash_hash = crash_file.name.split("-")[-1][:16]

            # 验证 crash 可复现
            if self._verify_crash(crash_data):
                pov_id = self.save_pov(crash_data, crash_hash)
                povs.append(pov_id)
                self.logger.info(f"Generated POV: {pov_id}")

        return povs

    def _verify_crash(self, input_data: bytes) -> bool:
        """验证 crash 是否可复现"""
        fuzzer_bin = self.get_fuzzer_binary()

        try:
            result = subprocess.run(
                [str(fuzzer_bin)],
                input=input_data,
                capture_output=True,
                timeout=10,
            )
            # 如果程序 crash 了 (非 0 退出码)，则验证成功
            return result.returncode != 0
        except subprocess.TimeoutExpired:
            return True  # timeout 也算 crash
        except Exception:
            return False
```

---

## Strategy 加载器

```python
# fuzzingbrain/worker/strategy/loader.py

from typing import Dict, Type, Optional
from pathlib import Path
import importlib.util

from .base import BaseStrategy
from .default import DefaultStrategy


# 内置策略注册表
_BUILTIN_STRATEGIES: Dict[str, Type[BaseStrategy]] = {
    "default": DefaultStrategy,
}


def get_strategy(name: str) -> Type[BaseStrategy]:
    """
    获取策略类

    Args:
        name: 策略名称或自定义策略文件路径

    Returns:
        Strategy 类
    """
    # 1. 检查内置策略
    if name in _BUILTIN_STRATEGIES:
        return _BUILTIN_STRATEGIES[name]

    # 2. 检查是否是文件路径
    if Path(name).exists():
        return _load_custom_strategy(name)

    # 3. 默认策略
    return DefaultStrategy


def _load_custom_strategy(filepath: str) -> Type[BaseStrategy]:
    """
    动态加载自定义策略

    Args:
        filepath: Python 文件路径

    Returns:
        Strategy 类
    """
    spec = importlib.util.spec_from_file_location("custom_strategy", filepath)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    # 查找 BaseStrategy 的子类
    for name in dir(module):
        obj = getattr(module, name)
        if (
            isinstance(obj, type)
            and issubclass(obj, BaseStrategy)
            and obj is not BaseStrategy
        ):
            return obj

    raise ValueError(f"No Strategy class found in {filepath}")


def register_strategy(name: str, strategy_cls: Type[BaseStrategy]) -> None:
    """
    注册自定义策略

    Args:
        name: 策略名称
        strategy_cls: Strategy 类
    """
    _BUILTIN_STRATEGIES[name] = strategy_cls


def list_strategies() -> Dict[str, str]:
    """
    列出所有可用策略

    Returns:
        {name: description} 字典
    """
    return {
        name: cls.description
        for name, cls in _BUILTIN_STRATEGIES.items()
    }
```

---

## WorkerExecutor 集成

```python
# fuzzingbrain/worker/executor.py (更新)

from pathlib import Path
from typing import Dict, Any

from ..core import logger
from ..db import RepositoryManager
from .strategy.base import StrategyContext
from .strategy.loader import get_strategy


class WorkerExecutor:
    """
    Worker 执行器

    负责加载和执行 Strategy
    """

    def __init__(
        self,
        workspace_path: str,
        project_name: str,
        fuzzer: str,
        sanitizer: str,
        job_type: str,
        repos: RepositoryManager,
        task_id: str,
        strategy_name: str = "default",
    ):
        self.workspace_path = Path(workspace_path)
        self.project_name = project_name
        self.fuzzer = fuzzer
        self.sanitizer = sanitizer
        self.job_type = job_type
        self.repos = repos
        self.task_id = task_id
        self.strategy_name = strategy_name

        self.worker_id = f"{task_id}__{fuzzer}__{sanitizer}"

    def run(self) -> Dict[str, Any]:
        """
        执行策略

        Returns:
            执行结果字典
        """
        # 创建执行上下文
        context = StrategyContext(
            workspace_path=self.workspace_path,
            project_name=self.project_name,
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            job_type=self.job_type,
            task_id=self.task_id,
            worker_id=self.worker_id,
            repo_path=self.workspace_path / "repo",
            fuzz_tooling_path=self.workspace_path / "fuzz-tooling",
            results_path=self.workspace_path / "results",
            crashes_path=self.workspace_path / "results" / "crashes",
            povs_path=self.workspace_path / "results" / "povs",
            patches_path=self.workspace_path / "results" / "patches",
            repos=self.repos,
        )

        # 确保目录存在
        context.crashes_path.mkdir(parents=True, exist_ok=True)
        context.povs_path.mkdir(parents=True, exist_ok=True)
        context.patches_path.mkdir(parents=True, exist_ok=True)

        # 加载策略
        strategy_cls = get_strategy(self.strategy_name)
        strategy = strategy_cls(context)

        logger.info(f"Using strategy: {strategy.name} v{strategy.version}")

        # 更新 Worker 记录
        worker = self.repos.workers.find_by_id(self.worker_id)
        if worker:
            worker.current_strategy = strategy.name
            self.repos.workers.save(worker)

        # 执行策略
        result = strategy.run()

        # 更新策略历史
        if worker:
            worker.strategy_history.append(strategy.name)
            self.repos.workers.save(worker)

        return {
            "povs_found": result.povs_found,
            "patches_found": result.patches_found,
            "crashes": result.crashes or [],
            "success": result.success,
            "error": result.error_msg,
        }
```

---

## 文件结构

```
fuzzingbrain/worker/
├── __init__.py
├── builder.py          # 现有: 编译 fuzzer
├── cleanup.py          # 现有: 清理 workspace
├── executor.py         # 更新: 加载并执行 Strategy
└── strategy/
    ├── __init__.py
    ├── base.py         # BaseStrategy 抽象基类
    ├── default.py      # DefaultStrategy (libFuzzer)
    └── loader.py       # 策略加载器
```

---

## 用户自定义 Strategy 示例

```python
# my_custom_strategy.py

from fuzzingbrain.worker.strategy.base import BaseStrategy
from typing import List


class MyAIStrategy(BaseStrategy):
    """
    AI 辅助 Fuzzing 策略示例
    """

    name = "ai-guided"
    description = "AI-guided fuzzing with smart input generation"
    version = "1.0.0"

    def setup(self) -> None:
        # 加载 AI 模型
        self.logger.info("Loading AI model...")
        # self.model = load_my_ai_model()

    def fuzz(self) -> List[str]:
        # 1. 分析目标代码
        # 2. AI 生成测试用例
        # 3. 运行 fuzzer
        # 4. 收集 crash

        self.logger.info("Running AI-guided fuzzing...")

        crashes = []
        # ... AI fuzzing 逻辑 ...

        return crashes

    def generate_povs(self, crashes: List[str]) -> List[str]:
        # AI 优化 POV
        povs = []
        for crash in crashes:
            # 使用 AI 最小化 crash input
            minimized = self._ai_minimize(crash)
            pov_id = self.save_pov(minimized, hash(crash))
            povs.append(pov_id)
        return povs

    def _ai_minimize(self, crash_path: str) -> bytes:
        # AI 最小化逻辑
        return Path(crash_path).read_bytes()
```

**使用方式:**

```python
# 在配置中指定策略
config.strategy = "my_custom_strategy.py"

# 或注册为内置策略
from fuzzingbrain.worker.strategy.loader import register_strategy
register_strategy("ai-guided", MyAIStrategy)
```

---

## 实现步骤

### Phase 1: 基础架构
- [ ] 创建 `fuzzingbrain/worker/strategy/` 目录
- [ ] 实现 `base.py` (BaseStrategy, StrategyContext, StrategyResult)
- [ ] 实现 `loader.py` (策略加载器)

### Phase 2: 默认策略
- [ ] 实现 `default.py` (DefaultStrategy)
- [ ] 包含 libFuzzer 运行逻辑
- [ ] 包含 crash 收集和 POV 生成

### Phase 3: 集成
- [ ] 更新 `executor.py` 使用 Strategy
- [ ] 更新 `tasks.py` 支持策略参数
- [ ] 更新 Worker 模型使用 current_strategy

### Phase 4: 测试
- [ ] 单元测试 BaseStrategy
- [ ] 集成测试 DefaultStrategy
- [ ] 测试自定义策略加载

---

## 配置扩展

```python
# 在 Config 中添加策略配置
class Config:
    # 现有配置...

    # 策略配置
    strategy: str = "default"  # 策略名称或文件路径
    strategy_config: Dict[str, Any] = {}  # 策略特定配置
```

```bash
# 命令行使用
python -m fuzzingbrain.main \
    --project libpng \
    --strategy ai-guided \
    --strategy-config '{"model": "gpt-4"}'
```






