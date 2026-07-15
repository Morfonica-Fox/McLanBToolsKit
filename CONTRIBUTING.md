# 贡献指南

感谢你对 McLanBToolsKit 的关注。

## 代码格式化

本项目使用 **Black** 进行代码格式化，使用 **isort** 进行 import 排序。提交前务必运行两者。

**当 isort 与 Black 在 import 格式上产生冲突时，以 isort 为准。**

### 安装格式化工具

```bash
pip install black isort
```

### 运行格式化

```bash
# 先运行 isort(import 排序)
isort .

# 再运行 black(代码格式化)
black .
```

两者的配置已写入 `pyproject.toml`，运行时会自动读取，无需额外参数。配置文件已设置 `profile = "black"` 确保 isort 输出与 Black 兼容，同时 `force_sort_within_sections = true` 确保 isort 的排序决策在边界情况下优先。

### 格式化顺序

1. **isort 先行**：处理所有 import 语句的组织、分组、排序
2. **Black 后继**：处理除 import 顺序外的所有代码风格

Black 在 `profile = "black"` 模式下不会重新排列 isort 已经排好的 import，因此 isort 的决策天然具有优先权。

## 提交流程

1. Fork 本仓库
2. 创建特性分支：`git checkout -b feature/your-feature`
3. 编写代码并测试
4. 运行格式化工具
5. 提交：`git commit -m "描述你的改动"`
6. 推送并创建 Pull Request

## 提交信息规范

使用清晰的中文或英文描述改动内容，推荐格式：

```
<类型>: <简短描述>

<详细说明(可选)>
```

类型示例：`feat`(新功能)、`fix`(修复)、`docs`(文档)、`refactor`(重构)、`style`(格式化)。

## 代码风格要点

- 使用 `from __future__ import annotations` 推迟注解求值
- 类型注解使用现代语法(`dict[str, Any]` 而非 `Dict[str, Any]`)
- 注释标记惯例：`[+]` 新增、`[=]` 修改/更正、`[-]` 删除
- 全局状态通过 `kept_data` 字典在模块间共享，避免模块级可变全局变量
- 热重载相关模块需实现 `will_update(timestamp)` 和 `on_updated(timestamp)` 钩子

## 测试

防火墙功能测试需要在 Windows 环境下以管理员权限运行，并确保 WinDivert 驱动已安装。

```bash
# 安装 WinDivert 驱动(首次使用 pydivert 时自动处理)
python -c "import pydivert; pydivert.WinDivert.check_filter('true')"
```

## 问题反馈

遇到问题请提交 Issue，附带以下信息：
- 操作系统版本
- Python 版本及实现(CPython / PyPy)
- pydivert 版本
- 完整的复现步骤
