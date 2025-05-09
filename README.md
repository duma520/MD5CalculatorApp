# 专业哈希计算工具使用说明书

## 1. 产品概述

**专业哈希计算工具**是一款功能强大、操作简便的哈希值计算软件，适用于各种文件完整性校验、数据验证和安全检查场景。本工具支持多种哈希算法，能够满足不同用户的需求，从普通用户到专业开发人员都能轻松使用。

### 1.1 适用人群
- **普通用户**：验证下载文件的完整性
- **IT专业人员**：系统维护、安全检查
- **开发人员**：数据校验、测试验证
- **安全专家**：文件指纹分析、数据取证

### 1.2 主要特点
- 支持20+种哈希算法
- 多种输入方式（文本/文件/多文件/目录）
- 直观的比对模式
- 自动检测重复文件
- 历史记录功能
- 可自定义界面主题

## 2. 安装与启动

### 2.1 系统要求
- 操作系统：Windows 7/10/11
- Python环境：Python 3.6及以上版本
- 内存：至少512MB可用内存
- 磁盘空间：至少10MB可用空间

### 2.2 安装步骤
1. 确保已安装Python环境
2. 安装必要的依赖库：
   ```
   pip install tkinterdnd2 hashlib blake3 pyhashxx cityhash farmhash mmh3
   ```
3. 运行程序：
   ```
   python MD5CalculatorApp.py
   ```

## 3. 界面介绍

### 3.1 主界面布局
程序主界面分为以下几个区域：

1. **左侧面板**：
   - 输入方式选择
   - 输入内容区域
   - 计算选项设置

2. **右侧面板**：
   - 结果显示区域
   - 多文件结果表格

3. **底部状态栏**：
   - 状态信息显示
   - 布局切换按钮

### 3.2 菜单栏
程序提供完整的菜单系统，包含：
- **文件**：新建、打开、保存、导出等功能
- **编辑**：复制、清空等操作
- **视图**：主题切换、布局调整
- **工具**：计算选项设置
- **帮助**：使用说明和关于信息

## 4. 基本使用

### 4.1 计算文本哈希
1. 选择"文本"输入方式
2. 在文本框中输入或粘贴要计算的内容
3. 选择哈希算法（如MD5、SHA256等）
4. 点击"计算哈希"按钮

**示例**：
```
输入："Hello World"
MD5结果：b10a8db164e0754105b7a99be72e3fe5
```

### 4.2 计算文件哈希
1. 选择"文件"输入方式
2. 点击"..."按钮选择文件，或直接将文件拖入窗口
3. 选择哈希算法
4. 点击"计算哈希"按钮

**专业提示**：计算大文件时，程序会显示进度条，可以随时停止计算。

### 4.3 批量计算多个文件
1. 选择"多文件"输入方式
2. 点击"添加文件"或"添加目录"按钮
3. 选择哈希算法
4. 点击"计算哈希"按钮

**效率技巧**：使用"包含子目录"选项可以快速计算整个文件夹结构中的文件。

### 4.4 计算目录中所有文件
1. 选择"目录"输入方式
2. 选择要计算的目录
3. 设置文件过滤器（可选）
4. 选择是否包含子目录
5. 点击"计算哈希"按钮

**应用场景**：适合需要批量验证大量文件完整性的情况，如备份校验。

## 5. 高级功能

### 5.1 哈希值比对
1. 勾选"比对模式"复选框
2. 在"目标"框中输入要对比的哈希值
3. 计算哈希后会自动显示比对结果

**安全应用**：下载软件后，可与官网提供的哈希值比对，验证文件是否被篡改。

### 5.2 自动检测重复文件
勾选"检测重复"选项后，程序会自动用不同颜色标记哈希值相同的文件。

**颜色编码**：每组重复文件会被分配独特的背景色，便于识别。

### 5.3 结果导出
计算结果可以多种方式导出：
- **复制**：直接复制到剪贴板
- **保存**：保存为文本文件
- **导出**：导出为CSV或JSON格式

**专业建议**：导出JSON格式便于后续程序处理和分析。

### 5.4 历史记录
程序会自动保存最近50条计算记录，可通过"工具"菜单查看。

**隐私提示**：历史记录保存在本地，不会上传到网络。

## 6. 哈希算法详解

### 6.1 常用算法比较

| 算法     | 输出长度 | 安全性 | 速度 | 典型应用场景 |
|----------|---------|--------|------|-------------|
| MD5      | 128位   | 低     | 快   | 文件校验    |
| SHA-1    | 160位   | 中低   | 快   | 版本控制    |
| SHA-256  | 256位   | 高     | 中   | 数字证书    |
| SHA-512  | 512位   | 很高   | 慢   | 密码存储    |
| BLAKE3   | 可变    | 很高   | 很快 | 高性能应用  |

### 6.2 算法选择建议
- **普通校验**：MD5或SHA1足够
- **安全敏感**：使用SHA256或更高
- **大文件**：考虑BLAKE3等快速算法

## 7. 常见问题解答

### 7.1 为什么计算大文件很慢？
哈希计算需要读取整个文件内容，大文件自然耗时更长。建议：
- 使用SSD硬盘加速读取
- 选择BLAKE3等快速算法
- 关闭其他占用磁盘的程序

### 7.2 两个文件内容不同但哈希相同，可能吗？
这种现象称为"哈希碰撞"，概率极低但存在可能。解决方法：
- 使用更长的哈希算法（如SHA512）
- 计算多个不同算法的哈希值交叉验证

### 7.3 如何验证程序计算的哈希值是否正确？
可以使用其他知名工具（如Linux的md5sum命令）进行交叉验证。

## 8. 应用案例

### 8.1 软件下载验证
1. 从官网获取官方哈希值
2. 用本工具计算下载文件的哈希
3. 比对两者是否一致

### 8.2 数据去重
1. 计算文件夹中所有文件的哈希
2. 启用"检测重复"功能
3. 根据标记删除重复文件

### 8.3 文件完整性监控
1. 定期计算重要文件的哈希
2. 保存结果作为基准
3. 后续定期重新计算并比对

## 9. 技术参数

- 支持最大文件大小：理论无限制（受系统内存影响）
- 计算速度：约100MB/s（取决于硬件和算法）
- 多线程支持：是
- 拖放操作支持：是

## 10. 版权声明

本软件版权永久归杜玛所有。未经许可，不得用于商业用途。

---

**作者**：杜玛
**版本**：1.3.8
**最后更新**：2025年04月10日

希望本说明书能帮助您充分利用专业哈希计算工具的各项功能。如有任何问题或建议，欢迎反馈。
