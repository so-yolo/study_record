### 步骤 1：停止 MySQL 服务

```
sudo systemctl stop mysqld
```

### 步骤 2：编辑 MySQL 配置文件

编辑 MySQL 的配置文件 my.cnf 或 mysqld.cnf。

```
vim /etc/my.cnf
```

在 [mysqld] 部分添加以下行：

```
skip-grant-tables
```

### 步骤 3：启动 MySQL 服务

启动 MySQL 服务：

```
sudo systemctl start mysqld
```

### 步骤 4：登录到 MySQL

由于我们已经启用了跳过授权表的模式，现在可以不使用密码登录：

```
mysql -u root
```

### 步骤 5：重置 root 用户密码

在 MySQL 命令行界面中执行以下 SQL 命令来重置 root 用户的密码：

```
FLUSH PRIVILEGES;
ALTER USER 'root'@'localhost' IDENTIFIED BY 'NewPassWord1.';
```

将 newpassword 替换为你希望设置的新密码。

### 步骤 6：退出 MySQL 命令行

```
exit;
```

### 步骤 7：编辑 MySQL 配置文件

再次编辑 MySQL 配置文件 my.cnf 或 mysqld.cnf，移除之前添加的 skip-grant-tables 行：

```
vim /etc/my.cnf
```

### 步骤 8：重新启动 MySQL 服务

```
sudo systemctl restart mysqld
```

### 步骤 9：验证登录

使用新密码登录 MySQL：

```
mysql -u root -p
```