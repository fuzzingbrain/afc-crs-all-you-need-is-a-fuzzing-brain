# 工作目录配置指南

## 概述

本系统使用两个环境变量来控制工作目录的位置，让您可以将 `afc-fwupd.json` 等文件放在任何您想要的文件夹中。

## 环境变量说明

### 1. CRS_WORKDIR
- **用途**: CRS 服务的工作目录
- **默认值**: `/crs-workdir`
- **配置文件**: `crs/.env`

### 2. CRS_WORK_DIR
- **用途**: 静态分析服务的工作目录  
- **默认值**: `/crs-workdir`
- **配置文件**: `static-analysis/.env`

## 配置方法

### 方法1：使用脚本设置（推荐）

1. 使用提供的脚本设置自定义工作目录：

```bash
# 给脚本添加执行权限
chmod +x set_custom_workdir.sh

# 设置自定义工作目录（替换为您的实际路径）
source set_custom_workdir.sh /home/ze/my-project-folder

# 或者设置为包含 afc-fwupd.json 的任何文件夹
source set_custom_workdir.sh /path/to/your/data/folder
```

### 方法2：手动设置环境变量

```bash
# 设置环境变量
export CRS_WORKDIR="/home/ze/my-project-folder"
export CRS_WORK_DIR="/home/ze/my-project-folder"

# 验证设置
echo "CRS_WORKDIR=$CRS_WORKDIR"
echo "CRS_WORK_DIR=$CRS_WORK_DIR"
```

### 方法3：修改 .env 配置文件

1. **修改 CRS 服务配置**：
   编辑 `crs/.env` 文件，添加或修改：
   ```
   CRS_WORKDIR=/path/to/your/custom/folder
   ```

2. **修改静态分析服务配置**：
   编辑 `static-analysis/.env` 文件，添加或修改：
   ```
   CRS_WORK_DIR=/path/to/your/custom/folder
   ```

### 方法4：在启动时设置

```bash
# 启动 CRS 服务时设置
CRS_WORKDIR=/your/custom/path CRS_WORK_DIR=/your/custom/path go run cmd/server/main.go

# 或者启动静态分析服务时设置
CRS_WORK_DIR=/your/custom/path go run cmd/server/main.go
```

## 使用示例

### 示例1：将工作目录设置为用户主目录下的项目文件夹

```bash
# 创建项目文件夹
mkdir -p /home/ze/afc-project-data

# 将 afc-fwupd.json 复制到新文件夹
cp /crs-workdir/afc-fwupd.json /home/ze/afc-project-data/

# 设置环境变量
source set_custom_workdir.sh /home/ze/afc-project-data
```

### 示例2：使用临时工作目录

```bash
# 创建临时工作目录
mkdir -p /tmp/my-afc-work

# 复制必要文件
cp /crs-workdir/afc-fwupd.json /tmp/my-afc-work/

# 设置工作目录
source set_custom_workdir.sh /tmp/my-afc-work
```

## 验证配置

设置完成后，您可以通过以下方式验证配置是否正确：

1. **检查环境变量**：
   ```bash
   echo "CRS_WORKDIR=$CRS_WORKDIR"
   echo "CRS_WORK_DIR=$CRS_WORK_DIR"
   ```

2. **检查文件是否存在**：
   ```bash
   ls -la $CRS_WORKDIR/afc-fwupd.json
   ```

3. **启动服务并查看日志**：
   服务启动时会在日志中显示实际使用的工作目录路径。

## 注意事项

1. **权限问题**: 确保新的工作目录具有适当的读写权限
2. **文件迁移**: 记得将 `afc-fwupd.json` 和其他必要文件复制到新的工作目录
3. **持久化设置**: 如果希望设置永久生效，请将环境变量添加到您的 shell 配置文件（如 `~/.bashrc` 或 `~/.zshrc`）
4. **服务重启**: 修改环境变量后需要重启相关服务才能生效

## 故障排除

如果遇到问题，请检查：

1. **目录权限**: `ls -ld $CRS_WORKDIR`
2. **文件存在性**: `ls -la $CRS_WORKDIR/afc-fwupd.json`
3. **环境变量**: `env | grep CRS`
4. **服务日志**: 查看服务启动日志中的工作目录信息
