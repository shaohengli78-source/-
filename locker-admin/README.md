# 智存管理台 · 通用智能寄存锁

基于 Flask + SQLite 的管理员后台，面向实验室旧柜改造项目。页面适配电脑和手机。数据库必须使用持久卷；GitHub 只保存源码，不保存学生资料、数据库或密钥。

## 已实现

- 管理员登录、密码哈希、CSRF、登录和敏感密码验证限流、修改密码。
- 柜子登记、空闲/占用状态、占用学生姓名/学号/联系电话、管理员分配。
- 授权学生名单管理（允许/停用）、外部学号上报留存。**格式符合不代表真实学生身份**。只有老师登记的名单才允许使用；不对接教务系统。
- 每位学生累计/日期区间使用次数，上海时区日期筛选，CSV 统计/明细/审计导出（Excel UTF-8 BOM、公式注入防护）。
- 管理员开锁/初始化要求再次输入密码、柜号和申请原因；指令有效期5分钟；成功回执后才结束占用。
- 刷卡存入申请、待执行指令轮询、设备回执、设备屏幕数据、取完释放接口。重复请求幂等，防止同一学生重复分配。
- 数据库事务、单柜和单学生的占用唯一约束、完整使用历史；页面审计展示最近500条，导出全部。

## 硬件边界

本仓库是网站和设备 HTTP 协议，**不含 ESP32/STM32 固件，不是完成了硬件接线的产品**。
固件需要实现读卡、WiFi HTTPS、驱动锁电机、门传感器、显示屏、密码随机生成/安全存储/本地验证/失败限流。
校园卡 UID 不一定等于学号；项目组需确定读卡器输出以及校内名单映射。接口信任已认证的设备网关，不声称防伪验证校园卡。

设备使用 `DEVICE_TOKEN`，外部信息接收使用权限更低的 `INGEST_TOKEN`；二者必须不同，使用随机长令牌。
本版一个设备网关管理全部柜子，令牌仅放在可信网关，不给每个公开终端共用。多网关场景须扩展每设备凭据及柜子绑定。
网站不显示/保存学生取物密码，固件生成密码并通过柜端提供给学生。屏幕可以从占用接口获取姓名、学号、电话；公开展示的具体范围由实验室决定。

## 本地运行

需要 Python 3.12。以下以 Bash 为例（Windows 可在 PowerShell 配置等价环境变量）。

```sh
cd locker-admin
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
export COOKIE_SECURE=0  # 仅本地 HTTP，生产 HTTPS 必须为1
python -m flask --app 'app:create_app()' create-admin admin
python -m flask --app 'app:create_app()' run
```

打开终端显示的本地地址。没有默认密码，不自动创建示例学生或柜子。
`.env.example` 是配置说明，本程序不自动读取 .env，请通过运行环境注入。

```sh
pip install -r requirements-dev.txt
python -m pytest -q
```

## Railway 部署

- GitHub 仓库源，服务根目录 `/locker-admin`，使用目录内 Dockerfile。
- 持久卷挂载 `/data`，环境变量 `DATABASE_PATH=/data/locker.sqlite3`。
- 设置随机 `SECRET_KEY`（至少32字符）、`COOKIE_SECURE=1`。
- 首次可配置 `BOOTSTRAP_ADMIN_USER` 和 Werkzeug 生成的 `BOOTSTRAP_ADMIN_HASH`；只在用户不存在时创建，不覆盖已有密码。可改用控制台 `create-admin`。不要把真实密码/哈希提交仓库。
- 健康检查 `/healthz`，公网 HTTPS 域名，端口使用平台 `PORT`。
- 正式接设备时设置不同的随机 `INGEST_TOKEN` 和 `DEVICE_TOKEN`。未设置时相应接口拒绝访问，管理页面也不允许下发设备指令。
- SQLite 单副本运行（1 worker/4 threads），不要扩容多个独立实例。定期使用 SQLite backup API 备份卷；迁移到多副本时改 PostgreSQL。
- 密码遗失可在容器控制台运行 `python -m flask --app 'app:create_app()' reset-admin-password admin`。轮换 SECRET_KEY 可撤销所有会话。
- 不可通过 GitHub Pages 托管 Flask 后端。

## 操作顺序

1. 管理员登录，右上角修改密码。
2. 「授权学生」登记老师确认的学号、姓名、电话。
3. 「柜子总览」添加实际柜子编号。
4. 未接硬件时可用「分配柜子」测试登记及统计；这不会驱动电机。
5. 固件接入后，刷卡调用存入申请，执行指令并回执；再读取屏幕信息。
6. 忘记密码时老师验证申请，在网页发起开锁或初始化。
7. 「使用统计」选择学期起止日期，导出 CSV。

## HTTP 设备协议 v1

接口只接受 HTTPS；请求 JSON；认证头 `Authorization: Bearer <令牌>`。不要通过 URL 传令牌。下表除学生上报外均使用设备令牌。

| 方法/路径 | 请求/返回 |
|---|---|
| POST `/api/external/students` | INGEST_TOKEN；`{"student_id":"20260001","name":"测试学生","phone":"13800000000"}`；保存但不自动授权，姓名电话可缺省 |
| POST `/api/device/store` | `{"student_id":"20260001","locker_id":1,"request_id":"设备生成的唯一事件ID"}`；202返回 command_id；只预留柜子，未计入成功使用 |
| GET `/api/device/commands` | 返回 pending 指令列表：id、locker_id、label、action、expires（UTC） |
| POST `/api/device/commands/<id>/ack` | `{"success":true,"detail":"门锁及密码初始化完成"}`；success 必须为 JSON 布尔值 |
| GET `/api/device/lockers/<id>` | 占用学生 name、student_id、phone、usage_id；用于屏幕显示及释放 |
| POST `/api/device/release` | `{"usage_id":123}`；设备本地校验密码、取完并确认关门后调用；重复回执不重复计数 |

action 含义：
- `store`：已授权新学生存入。设备开门、完成存放和密码设置后回执成功，后台创建使用记录。柜端应在实际完成之前持续保留待处理状态。
- `unlock`：管理员临时开锁，不结束占用。
- `reset`：管理员初始化。清除设备端密码/当前使用状态，收到成功回执后后台释放柜子；保留历史日志。

指令可能被多次轮询：设备必须将**指令ID及执行结果持久保存**，同一ID只执行一次，丢失回执时仅重发结果。设备执行前校验 expires，不执行已过期指令。网络断开后不要猜测操作成功。

过期或冲突返回409：可能存在“硬件已执行，但回执丢失”的情况，必须由管理员人工核对，不自动把过期指令当成功。生产固件应支持对账/本地持久日志。网站不把开锁等同取物完成。

## 配置学号格式

默认 `STUDENT_ID_PATTERN=[0-9]{8,12}`，它是临时可配置规则，不是学校真实学号规则。请按项目学校规则修改；即使格式正确仍必须属于授权名单。

## 数据时间与频次定义

数据库存储 UTC；网页显示北京时间。频次在管理员登记或设备 `store` 成功时加1，失败/重复回执/远程开锁不加。日期筛选按使用开始时间的北京时间日期（含首尾）计算。初始化和取完释放写入结束时间，不删除使用记录。
