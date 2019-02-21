#!/bin/sh

set -e

export DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER=0

# 编译项目
echo "begin build..."
dotnet build RSAUtil.sln -c Release
echo "build success"

# 创建nuget临时存放目录
publishdir=publish/nuget/$(date +%Y%m%d)

mkdir $publishdir -p

publishdir=$(cd ${publishdir}; pwd)

echo "begin pack..."

# 打包项目 并输出到临时存放目录
echo "pack XC.RSAUtil..."
dotnet pack XC.RSAUtil/XC.RSAUtil.csproj -c Release -o ${publishdir}
echo "pack XC.RSAUtil success"

echo "pack XC.BouncyCastle.Crypto..."
dotnet pack BouncyCastle.Crypto/XC.BouncyCastle.Crypto.csproj -c Release -o ${publishdir}
echo "pack XC.BouncyCastle.Crypto success"

# 发布到nuget.org
echo "begin push..."
for nugetfile in ${publishdir}/*; do
    dotnet nuget push $nugetfile -k ${nugetkey} -s https://api.nuget.org/v3/index.json
done
echo "push success"

# 清理

if [[ $publishdir != "/" ]] ; then
	rm -rf ${publishdir}
fi