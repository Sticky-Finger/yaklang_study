好的，我将解析 'official_plugin/Shiro指纹识别_弱密码检测.yak' 程序。

这个 Yak 脚本的主要功能是**检测使用了 Apache Shiro 框架的 Web 应用程序，并检查是否存在弱密钥漏洞（CVE-2016-4437）以及 Shiro 反序列化漏洞**。

以下是该脚本的详细解析：

1. **脚本头部和测试函数 `__test__`**:
   - 脚本开头是 mitm plugin template 的注释，表明这是一个 Yak 的 MITM 插件模板。
   - `__test__` 函数用于本地测试，它模拟了一个 HTTP GET 请求到 `http://192.168.3.113:8085/shiro/`，并调用 `mirrorNewWebsite` 函数来处理这个请求。

2. **弱密钥列表 `keys`**:
   - 定义了一个名为 `keys` 的列表，包含了大量的 Shiro 默认加密密钥。这些密钥是脚本用来进行弱密钥爆破的关键。

3. **数据 `data`**:
   - `data` 变量存储了一段经过 Hex 解码和 PKCS5Padding 填充的 Base64 编码数据。这段数据很可能是用于 Shiro 反序列化漏洞利用的序列化 Java 对象。

4. **计数器和锁 `executingCount`, `executingCountLock`, `add`, `sub`**:
   - `executingCount` 用于跟踪正在检测 Shiro 网站的数量。
   - `executingCountLock` 是一个互斥锁，用于保护 `executingCount` 变量的并发访问安全。
   - `add` 和 `sub` 函数分别用于增加和减少 `executingCount`，并在 Yakit 状态栏显示当前检测数量。

5. **上下文和 WaitGroup `ctx`, `cancel`, `swg`**:
   - `ctx` 和 `cancel` 用于控制 Goroutine 的生命周期，实现取消操作。
   - `swg` 是一个大小为 20 的 SizedWaitGroup，用于控制并发请求的数量，限制最大并发数为 20。

6. **函数 `getRememberMeNumber`**:
   - 该函数用于计算 HTTP 响应头中 `rememberMe` Cookie 的数量。通过替换响应头中的 `rememberMe` 字符串为空，然后计算长度差来得到 `rememberMe` 的数量。

7. **全局变量 `EchoSuccessHost`, `DnsLogSuccessHost`**:
   - `EchoSuccessHost` 和 `DnsLogSuccessHost` 用于存储成功回显和 DNSLog 探测成功的主机列表。

8. **核心函数 `mirrorNewWebsite`**:
   - 这是脚本的核心函数，当 MITM 拦截到新的网站请求时被调用。
   - **Shiro 指纹检测**:  首先发送一个带有随机 `rememberMe` Cookie 值的请求，检查响应头中是否包含 `rememberMe=deleteMe`，以此判断目标网站是否使用了 Shiro 框架。
   - **弱密钥爆破**: 如果检测到 Shiro，则遍历 `keys` 列表中的每个密钥，使用 AES-CBC 和 AES-GCM 两种加密模式，结合 `data` 变量生成不同的 `rememberMe` Cookie 值。然后，对每个 Cookie 值发送请求，检查响应。
   - **漏洞判断**: 如果使用某个弱密钥加密的 Cookie 能够减少 `rememberMe` 的数量（通过 `getRememberMeNumber` 函数判断），则认为该密钥有效，并报告 CVE-2016-4437 漏洞风险。
   - **盲打 RCE 探测 (`blindEcho` 函数)**:  调用 `blindEcho` 函数，尝试使用不同的 Java 反序列化 Gadget（CB183NoCC, CB192NoCC, CCK1, CCK2）进行盲打 RCE 探测，通过检查响应头中是否回显特定的 Key-Value 来判断是否存在 RCE 漏洞。
   - **FindGadgets 探测 (DNSLog)**: 如果弱密钥爆破成功，并且盲打 RCE 没有成功，则尝试使用 DNSLog 技术探测服务器上可用的 Gadget 链，进一步确认是否存在反序列化漏洞。
   - **风险报告**:  使用 `risk.NewRisk` 函数生成风险报告，包括漏洞标题、描述、解决方案、严重程度、请求和响应信息等。

9. **函数 `blindEcho`**:
   - 用于执行盲打 RCE 探测。
   - 加载预编译的 Java bytecode (`bytesCode`)，修改其中的特定字符串为随机生成的 Key-Value (`echoKey`, `echoValue`)。
   - 使用不同的 Gadget 链 (`CB183NoCC`, `CB192NoCC`, `CCK1`, `CCK2`) 和当前测试的弱密钥加密 payload，发送请求。
   - 检查响应头中是否包含回显的 Key-Value，如果包含，则报告 Shiro RCE 漏洞。

10. **函数 `clear`**:
    - 调用 `cancel()` 函数，用于取消正在进行的 Goroutine，实现脚本的清理和停止。

**总结**:

这个 Yak 脚本是一个用于检测 Shiro 框架和相关漏洞的插件。它通过以下步骤工作：

- **指纹识别**: 通过 Cookie 行为初步判断目标网站是否使用了 Shiro。
- **弱密钥爆破**: 使用预定义的弱密钥列表尝试爆破 Shiro 加密密钥。
- **漏洞验证**: 通过弱密钥爆破成功与否，判断是否存在 CVE-2016-4437 漏洞。
- **RCE 盲打和 Gadget 探测**:  使用 Java 反序列化 Gadget 和 DNSLog 技术，尝试进一步探测 Shiro 反序列化 RCE 漏洞。
- **风险报告**:  将检测结果以风险报告的形式输出。

总的来说，这个脚本功能较为完善，能够有效地检测 Shiro 框架的弱密钥和反序列化漏洞，对于 Shiro 安全测试具有一定的实用价值。