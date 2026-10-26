## 变更说明 / What does this PR change?

<!-- 一段话说清楚做了什么、为什么。 -->

## 自查清单 / Checklist

- [ ] 变更后全量测试通过（`pytest tests/ -q`）
- [ ] 检测规则变更已验证不引入 safe 场景误报（`python scripts/benchmark_recall.py --compare` 基线对比）
- [ ] 新增/变更漏洞类型已同步：`STATIC_CONFIRMABLE` 验证白名单、RemediationProfile 整改画像、CWE/OWASP 映射
- [ ] 文档已更新（README / docs / CHANGELOG）

## 测试证据 / Test evidence

```
<paste pytest / benchmark output>
```
