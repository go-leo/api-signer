# api-signer
用于对外接口的通用签名认证包

## 使用

## 签名流程

### 一、获取 ak、sk

### 二、生成签名
**2.1 url参数排序并生成请求字符串**`rawQuery`

 (1) 按字典序对查询参数的键进行排序并构建`rawQuery`, 用户可以借助编程语言中的相关排序函数来实现这一功能，如 PHP 中的 ksort 函数

 (2) 把排序好的请求参数格式化成“参数名称=参数值”的形式, 然后将格式化后的各个参数用"&"拼接在一起,如下:

`Action=DescribeInstances&InstanceIds.0=ins-09dx96dg&Limit=20&Nonce=11886&Offset=0&Region=ap-guangzhou&SecretId=AKIDz8krbsJ5yKBZQpn74WFkmLPx3*******&Timestamp=1465185768&Version=2017-03-12`

**2.2 body内容计算摘要**`bodyDigest`

 使用 sha256 对请求body计算摘要，对其结果转化为十六进制，伪代码为: 

 ``` bodyDigest = hex(sha256(body)) ```

**2.2 生成 `payload`**

请求方法、请求路径、请求排序字符串、请求body摘要通过 '\n' 组合，生成`payload`; 

伪代码为:

``` payload = http.Method+ '\n' + http.Path + '\n' + rawQuery + '\n' + bodyDigest ```

**2.3 生成签名内容`strToSign`**

将签名算法、nonce、date、credential、 通过 '\n' 组合, 生成`strToSign`; 

伪代码为:

``` strToSign = APISIGNER-HMAC-SHA256 + '\n' + x-ca-nonce + '\n' + x-ca-date + '\n' + credential + '\n' + hex(sha256(payload)) ```

**2.4 生成签名 `signature`**

`APISIGNER`字符串+`SK` 进行组合作为密钥，`strToSign`作为内容，通过 `HMAC-SHA256`算法来生成签名；

伪代码为:

``` signature = HmacSha256([]byte("APISIGNER"+secret), []byte(stringToSign)) ```

### 三、设置头字段

(1) 通过第二步计算出来的 `credential`、`signature`，设置 `Authorization` 头字段

`Authorization` = "APISIGNER-HMAC-SHA256" + " Credential=" + AK + "/" + credential + ", " + "Signature=" + signature

(2) 设置 `x-ca-nonce`、 `x-ca-date` 头字段;

`x-ca-nonce` = 随机值（用于防止重放攻击）

`x-ca-date` = RFC 3986 格式的当前时间（如：20060102T150405Z，用于检查签名是否过期）