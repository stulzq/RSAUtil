# RSAUtil
.NET Core RSA算法使用帮助工具，支持数据加密，解密，签名和验证签名，支持xml，pkcs1，pkcs8三种密钥格式，支持这三种格式的密钥转换。最后还支持pem格式化。

[![Latest version](https://img.shields.io/nuget/v/XC.Framework.Security.RSAUtil.svg)](https://www.nuget.org/packages/XC.Framework.Security.RSAUtil/)

# 文档

### 生成密钥

>使用“RsaKeyGenerator”类。返回的结果是一个有两个元素的字符串的列表，元素1是私钥，元素2是公钥。

格式：XML

```CSHARP
var keyList = RsaKeyGenerator.XmlKey（2048）;
var privateKey = keyList [0];
var publicKey = keyList [1];
```

格式：Pkcs1

```CSHARP
var keyList = RsaKeyGenerator.Pkcs1Key（2048）;
var privateKey = keyList [0];
var publicKey = keyList [1];
```

格式：Pkcs8

```CSHARP
var keyList = RsaKeyGenerator.Pkcs8Key（2048）;
var privateKey = keyList [0];
var publicKey = keyList [1];
```

### RSA密钥转换

>使用“RsaKeyConvert”类。它支持这三种格式的密钥转换，即：xml，pkcs1，pkcs8。

##### XML-> Pkcs1：

- 私钥：`RsaKeyConvert.PrivateKeyXmlToPkcs1（）`
- 公钥：`RsaKeyConvert.PublicKeyXmlToPem（）`

##### XML-> Pkcs8：

- 私钥：`RsaKeyConvert.PrivateKeyXmlToPkcs8（）`
- 公钥：`RsaKeyConvert.PublicKeyXmlToPem（）`

##### Pkcs1-> XML：

- 私钥：`RsaKeyConvert.PrivateKeyPkcs1ToXml（）`
- 公钥：`RsaKeyConvert.PublicKeyPemToXml（）`

##### Pkcs1-> Pkcs8：

- 私钥：`RsaKeyConvert.PrivateKeyPkcs1ToPkcs8（）`
- 公钥：不需要转换

##### Pkcs8-> XML：

- 私钥：`RsaKeyConvert.PrivateKeyPkcs8ToXml（）`
- 公钥：`RsaKeyConvert.PublicKeyPemToXml（）`

##### Pkcs8-> Pkcs1：

- 私钥：`RsaKeyConvert.PrivateKeyPkcs8ToPkcs1（）`
- 公钥：不需要转换

### 加密，解密，签名和验证签名

> XML，Pkcs1，Pkcs8分别对应类：`RsaXmlUtil`，`RsaPkcs1Util`，`RsaPkcs8Util`。它们继承自抽象类`RSAUtilBase`

- 加密：RSAUtilBase.Encrypt（）
- 解密：`RSAUtilBase.Decrypt（）`
- Sign：`RSAUtilBase.SignData（）`
- 验证：`RSAUtilBase.VerifyData（）`

### PEM格式化

>使用类“RsaPemFormatHelper”。

- 格式化Pkcs1格式私钥：`RsaPemFormatHelper.Pkcs1PrivateKeyFormat（）`
- 删除Pkcs1格式私钥格式：`RsaPemFormatHelper.Pkcs1PrivateKeyFormatRemove（）`
- 格式化Pkcs8格式私钥：`RsaPemFormatHelper.Pkcs8PrivateKeyFormat（）`
- 删除Pkcs8格式的私钥格式：`RsaPemFormatHelper.Pkcs8PrivateKeyFormatRemove（）`
