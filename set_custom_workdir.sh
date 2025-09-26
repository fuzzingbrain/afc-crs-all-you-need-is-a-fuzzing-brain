#!/bin/bash

# 设置自定义工作目录的脚本
# 使用方法: source set_custom_workdir.sh /path/to/your/custom/workdir

if [ $# -eq 0 ]; then
    echo "使用方法: source $0 /path/to/your/custom/workdir"
    echo "示例: source $0 /home/ze/my-custom-workdir"
    return 1
fi

CUSTOM_WORKDIR="$1"

# 检查目录是否存在，如果不存在则创建
if [ ! -d "$CUSTOM_WORKDIR" ]; then
    echo "创建工作目录: $CUSTOM_WORKDIR"
    mkdir -p "$CUSTOM_WORKDIR"
fi

# 设置环境变量
export CRS_WORKDIR="$CUSTOM_WORKDIR"
export CRS_WORK_DIR="$CUSTOM_WORKDIR"

echo "已设置工作目录环境变量："
echo "  CRS_WORKDIR=$CRS_WORKDIR"
echo "  CRS_WORK_DIR=$CRS_WORK_DIR"

# 检查 afc-fwupd.json 文件是否存在
if [ -f "$CUSTOM_WORKDIR/afc-fwupd.json" ]; then
    echo "✓ 找到 afc-fwupd.json 文件在: $CUSTOM_WORKDIR/afc-fwupd.json"
else
    echo "⚠ 未找到 afc-fwupd.json 文件在: $CUSTOM_WORKDIR/afc-fwupd.json"
    echo "  请确保将 afc-fwupd.json 文件放在新的工作目录中"
fi

echo "环境变量设置完成！现在可以启动服务了。"
