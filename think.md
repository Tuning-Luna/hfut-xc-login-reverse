## 登录逆向思路

### 调用 `/preLogin`

获得：cookie中的`SESSION`字段（同时返回登录 html，包含密码加密方式）



### 调用 `/vercode`

携带：cookie中的`SESSION` 字段

获得：cookie中 `JSESSIONID` 字段

同时获得图形验证码，**不过第一次获得的用不上**



### 调用`/checkInitParams`

携带：Cookie中前面两个字段：`SESSION`字段和`JSESSIONID` 字段

获得：第三个cookie字段`LOGIN_FLAVORING`



### 调用`/vercode?time` （注意这次携带cookie不同，查询参数也加上了时间）

携带：cookie三个字段：`SESSION`字段和`JSESSIONID` 字段 和 `LOGIN_FLAVORING`字段 

获得：图形验证码
