# CLAUDE.md

## 项目
完整架构、阶段划分、验收标准见 `PROJECT_SPEC.md`——开工前先完整读一遍。

## 环境
- Python 版本：3.12
- 包管理器：uv（`uv pip install --python .\.venv\Scripts\python.exe -r requirements.txt`）；同时维护 requirements.txt，让读者也能用纯 pip 装
- 虚拟环境：`./.venv`（已建）。所有命令走 `.\.venv\Scripts\python.exe`，不依赖 activate

## 模型与 API
- Provider：DeepSeek，官方 `openai` Python 包 + `base_url="https://api.deepseek.com"`（DeepSeek API 是 OpenAI 兼容格式，没有独立 SDK）
- API key 环境变量名：`DEEPSEEK_API_KEY`——代码里只引用这个变量名，绝不写死真实值，绝不打印或记录它的值
- 安全审计 / Reader 默认模型：`deepseek-v4-flash`；如果分类判断不够准，换成 `deepseek-v4-pro`
- 结构化输出用 `tool_choice` 强制工具的方式（`{"type": "function", "function": {"name": "..."}}`，见 PROJECT_SPEC.md 第 3.3 节），不用 prefill，不用纯提示词裸 JSON
- 2026-08 切换记录：本项目最初按 Claude/Anthropic 规划，因国内支付/账号门槛切到 DeepSeek。技术核心（tool_choice 强制工具）在两家 API 上是同一类机制，架构未受影响

## 约定
- 代码风格：强制 type hints；数据契约用 `@dataclass(frozen=True)` 表达，不用裸 dict —— 这样"结构性边界在哪几行"能在代码里直接指出来（PROJECT_SPEC.md 第 8 节最后一条）
- 所有源码/注释/文档用英文（仓库对外是英文开源项目），和我对话用中文
- 文件读写一律走 `ibr/sandbox_fs.py`，显式 `encoding="utf-8"`，不直接用 `open()`
- 提交习惯：一个 Phase 一次 commit，message 格式 "Phase N: xxx"

## 提交前
- **推送前必须跑 `python verify.py`**（约 20 秒，不需要 key）。它包含一个关键步骤：在**没有 `.env`** 的 git worktree 里跑一遍离线测试。开发机上有 key，CI 上没有——任何悄悄依赖 key 的"离线"测试在本地会通过、在 CI 会挂，这一步是唯一能发现它的方式
- 改动了 `ibr/llm.py`、`ibr/pipeline.py` 或 `ibr/baseline_agent.py` 之后，再跑 `python verify.py --live`（会真实调用 API、花钱）
- `python tools/install_hooks.py` 装 pre-push hook，把上面第一条自动化
- 新增任何 `# type: ignore` 必须在 `tests/test_suppressions.py` 里登记并写明抑制了什么、为什么安全，否则测试失败

## 永远
- 每个 Phase 完成先给我看，等我确认再继续下一个（见 PROJECT_SPEC.md 0.5）
- 任何环节出错/超时/格式不对，默认拒绝不放行（fail-closed）
- 绝不把真实密钥写进任何文件，包括测试用的
- 报告检查结果时说清**这种检查能发现什么、不能发现什么**，不要把"某种检查没发现问题"说成"没有问题"
