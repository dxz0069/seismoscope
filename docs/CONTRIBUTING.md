# 贡献指南 / Contributing

感谢你考虑为候风 Seismoscope 贡献！本文是上手路线图。

## 快速定位你的兴趣点

| 你想做的 | 从这里开始 | 难度 |
|---|---|---|
| **新增检测规则**（最快上手） | 复制 `core/audit/rules/patterns.yml` 增删规则，设 `VIBE_SEC_RULES_PATH` 本地验证；或直接改该文件（golden 测试强制与内置同步） | ⭐ |
| **扩充 CVE 回放靶场** | 读 `tests/test_cve_replay.py` 顶部注释与 `manifest.json`；流程 = advisory → 修复 diff → vendor 父提交 → 行级命中断言 | ⭐⭐ |
| **新分析器**（如 escape_semantics） | 参考 `core/audit/escape_semantics.py` + 其测试；要求有真实 CVE 形态背书，不收投机规则 | ⭐⭐⭐ |
| **VRTM 建模扩展** | `core/surface/runtime_surface.py`（提取层）与 `core/surface/threat_model.py`（假设生成，14 项技术） | ⭐⭐⭐ |
| **前端工作台** | `frontend-v2/`（Vite + Vue3），`npm ci --prefix frontend-v2 && npm run build --prefix frontend-v2` | ⭐⭐ |
| **文档/双语** | `README.md` ↔ `README.en.md` 双源同步 | ⭐ |

## 开发环境

```bash
pip install -e ".[dev]"          # Python ≥3.11
pytest tests/ -q                 # 全量测试（~1 分钟）
ruff check . --select F,E9,I,UP --ignore UP042   # lint 门禁（与 CI 一致）
python scripts/benchmark_recall.py --compare tests/fixtures/benchmark-baseline.json  # 能力防回退门禁
```

## 不可破坏的约束（CI 会拦）

1. **基准门禁**：检测规则变更不得导致内置靶场召回下降或 safe 靶场出现误报；
2. **CVE 回放**：已命中的目标不得回退（strict xfail 语义见测试文件）；
3. **golden 同步**：`core/audit/rules/patterns.yml` 与内置规则逐条一致；
4. **技术目录对齐**：新增 threat 技术必须同步 `TECHNIQUE_STANDARDS` 映射；
5. **fixture 不可重排**：`tests/fixtures` 已排除 lint——行号是测试契约。

## PR 检查清单

见 `.github/PULL_REQUEST_TEMPLATE.md`（自动出现在 PR 创建页）。

## 发布节奏

维护者按语义化版本发版：tag `v*` 推送后 CI 自动构建、发布 GitHub Release 并经 OIDC Trusted Publishing 发布 PyPI，全程无人工凭据。
