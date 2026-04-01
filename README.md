# pypi-audit

> Python 依赖安全审计工具 - 一键扫描项目依赖，检测供应链攻击和已知漏洞

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 特性

### 核心功能

- **多格式依赖解析**：支持 `requirements.txt`、`pyproject.toml`、`Pipfile.lock` 三种常见依赖文件格式
- **多数据源聚合**：集成 PyPI Safety API 和 OSV.dev API，自动获取漏洞情报
- **供应链攻击检测**：内置 LiteLLM 2026-03-24 供应链攻击事件 IOC 清单（硬编码）
- **友好终端输出**：使用 Rich 库生成美观的彩色表格和进度条
- **修复建议**：提供具体的升级版本和修复方案

### 支持的依赖文件格式

| 格式 | 文件名 | 状态 |
|------|--------|------|
| pip requirements | `requirements.txt` | ✅ 支持 |
| PEP 621 / Poetry | `pyproject.toml` | ✅ 支持 |
| Pipenv | `Pipfile.lock` | ✅ 支持 |

## 安装

### 从源码安装

```bash
# 克隆仓库
git clone https://github.com/yourusername/pypi-audit.git
cd pypi-audit

# 安装依赖并进入开发模式
pip install -e .

# 或者使用构建脚本
./scripts/build.sh
```

### 使用 pip 安装

```bash
pip install pypi-audit
```

## 使用方法

### 快速开始

```bash
# 扫描当前目录的依赖文件
pypi-audit scan

# 指定依赖文件路径
pypi-audit scan -f requirements.txt
pypi-audit scan -f pyproject.toml
pypi-audit scan -f Pipfile.lock

# 扫描多个文件
pypi-audit scan -f requirements.txt -f dev-requirements.txt

# 指定目录扫描
pypi-audit scan -d ./project
```

### 命令行选项

```bash
pypi-audit scan [OPTIONS]

选项:
  -f, --file PATH        指定依赖文件路径（可指定多次）
  -d, --dir PATH         指定项目目录（自动查找依赖文件）
  -o, --output FILE      输出报告到文件
  -j, --json             输出 JSON 格式报告
  -v, --verbose          显示详细输出
  --no-ioc               跳过 IOC 检测
  --no-api               跳过 API 查询（仅使用本地 IOC）
  --help                 显示帮助信息
```

### 使用示例

#### 扫描 requirements.txt

```bash
$ pypi-audit scan -f requirements.txt
```

输出示例：

```
┌─────────────────────────────────────────────────────────────────┐
│                      pypi-audit Report                          │
├─────────────────────────────────────────────────────────────────┤
│ Scan Time: 2026-04-01 10:30:00                                  │
│ Total Dependencies: 42                                          │
│ Vulnerabilities Found: 3                                        │
│ IOC Matches: 1                                                  │
└─────────────────────────────────────────────────────────────────┘

📦 Vulnerabilities
═══════════════════════════════════════════════════════════════════
 Package      │ Version │ Severity │ Source    │ Description
──────────────┼─────────┼──────────┼───────────┼──────────────────
 requests     │ 2.25.0  │ HIGH     │ PyPI      │ CVE-2023-XXXXX
 pyyaml       │ 5.4.0   │ MEDIUM   │ OSV       │ GHSA-xxxx-xxxx
 some-package │ 1.2.3   │ CRITICAL │ IOC       │ LiteLLM Supply Chain

🔧 Fix Suggestions
═══════════════════════════════════════════════════════════════════
• requests: Upgrade to >= 2.31.0
• pyyaml: Upgrade to >= 6.0.1
• some-package: Remove immediately - known malicious package
```

#### 扫描 pyproject.toml

```bash
$ pypi-audit scan -f pyproject.toml
```

#### 扫描整个项目目录

```bash
$ pypi-audit scan -d ./my-python-project
```

## 输出格式

### 终端输出（默认）

使用 Rich 库渲染美观的彩色表格，包含：
- 扫描概览（时间、依赖数量、问题数量）
- 漏洞列表（包名、版本、严重级别、数据来源）
- IOC 匹配警告（高亮显示）
- 修复建议

### JSON 输出

```bash
$ pypi-audit scan -f requirements.txt -j
```

```json
{
  "scan_time": "2026-04-01T10:30:00",
  "total_dependencies": 42,
  "vulnerabilities": [
    {
      "package": "requests",
      "version": "2.25.0",
      "severity": "HIGH",
      "source": "PyPI Safety",
      "cve_id": "CVE-2023-XXXXX",
      "description": "...",
      "fix_version": ">= 2.31.0"
    }
  ],
  "ioc_matches": [
    {
      "package": "litellm",
      "version": "0.1.0",
      "event": "LiteLLM Supply Chain Attack 2026-03-24",
      "indicators": ["malicious_domain", "suspicious_hash"]
    }
  ],
  "summary": {
    "critical": 1,
    "high": 1,
    "medium": 1,
    "low": 0
  }
}
```

## 工作原理

```
┌─────────────┐     ┌─────────────┐     ┌─────────────────┐
│  依赖文件   │────▶│   解析器    │────▶│   数据模型      │
│  (3种格式)  │     │  (Parser)   │     │  (Dataclass)   │
└─────────────┘     └─────────────┘     └────────┬────────┘
                                                  │
                    ┌─────────────────────────────┼─────────────────────────────┐
                    │                             │                             │
                    ▼                             ▼                             ▼
          ┌─────────────────┐           ┌─────────────────┐           ┌─────────────────┐
          │   本地 IOC      │           │  PyPI Safety    │           │    OSV.dev      │
          │   检测器        │           │     API         │           │      API        │
          └────────┬────────┘           └────────┬────────┘           └────────┬────────┘
                   │                             │                             │
                   └─────────────────────────────┼─────────────────────────────┘
                                                 ▼
                                       ┌─────────────────┐
                                       │    报告生成器    │
                                       │   (Terminal)   │
                                       └─────────────────┘
```

## 技术栈

| 组件 | 技术选型 |
|------|---------|
| 语言 | Python 3.10+ |
| CLI 框架 | [Click](https://click.palletsprojects.com/) 8.x |
| 终端输出 | [Rich](https://rich.readthedocs.io/) 13.x |
| HTTP 客户端 | [httpx](https://www.python-httpx.org/) |
| TOML 解析 | tomli / tomllib |
| Pipfile 解析 | pipfile |
| 版本管理 | [packaging](https://packaging.pypa.io/) |

## 项目结构

```
pypi-audit/
├── src/pypi_audit/           # 源代码
│   ├── __init__.py           # 包初始化
│   ├── __main__.py           # 模块入口
│   ├── cli.py                # CLI 命令定义
│   ├── models.py             # 数据模型
│   ├── scanner.py            # 核心扫描引擎
│   ├── parsers/              # 依赖文件解析器
│   ├── api_clients/          # 安全 API 客户端
│   ├── ioc/                  # IOC 检测
│   └── reports/              # 报告生成器
├── tests/                    # 测试代码
├── scripts/                  # 构建脚本
├── pyproject.toml            # 项目配置
└── README.md                 # 本文档
```

## 测试

```bash
# 运行所有测试
pytest

# 运行特定模块测试
pytest tests/test_parsers/
pytest tests/test_api_clients/

# 查看测试覆盖率
pytest --cov=pypi_audit --cov-report=term-missing
```

## 安全数据源

### PyPI Safety API
PyPI 官方安全接口，提供已知漏洞信息。

### OSV.dev (Open Source Vulnerabilities)
Google 主导的开源漏洞数据库，支持多个生态系统。

### 内置 IOC
- **LiteLLM Supply Chain Attack (2026-03-24)**：恶意包检测清单

## 适用场景

| 用户画像 | 使用场景 |
|---------|---------|
| Python 后端开发者 | CI/CD 流水线集成，每次提交自动扫描 |
| 安全工程师 | 项目安全审计，生成漏洞报告 |
| DevOps 工程师 | 容器镜像安全检查 |
| 开源项目维护者 | 发布前安全自查 |

## 贡献

欢迎提交 Issue 和 Pull Request！

## 许可证

本项目基于 MIT 许可证开源，详见 [LICENSE](LICENSE) 文件。
