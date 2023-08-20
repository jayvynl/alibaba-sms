Alibaba SMS 阿里云短信发送 SDK
===

官方 SDK 过于庞大，如果仅仅是为了发送短信，宁愿自己实现一个。


项目特色
---

- 多次发送复用底层连接。
- 轻量级，只包含短信发送必要代码。
- 适度封装，使用简单，但是可通过参数改变默认行为。


快速上手
---

### 安装

```shell
pip install alibaba-sms
```

### 使用

```python
from alibaba_sms import AliSMS

client = AliSMS("access_key_id", "access_key_secret")
client.send("phone_number", "code", "sign_name", "template_code")
```

更多参数参考源码中的文档和注释。

许可证
---

Alibaba SMS 项目基于 [MIT 许可证](http://www.opensource.org/licenses/mit-license.php) 发布.
