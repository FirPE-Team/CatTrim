# CatTrim

简体中文 | [English](README.md)

## 介绍

`CatTrim`是面向离线 Windows PE 镜像的 CAT 签名检查与清理工具。

按照 CAT 中登记的文件摘要，检查镜像根目录下现存的 PE 和 INF 文件，找出没有覆盖任何现存 PE 或 INF 的 CAT。“无效 CAT”表示“本次扫描中没有命中 PE/INF 摘要”，不表示 CAT 的 PKCS#7 签名、证书链或证书有效期验证失败。

## 功能

- 递归扫描离线 Windows 镜像；
- 自动定位：

  ```text
  <IMAGE_ROOT>\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}
  ```

- 解析 CAT 中的新式 CATALOG_LIST_MEMBER2 成员摘要；
- 按以下入库条件收录旧式成员中的原始 SHA-1/SHA-256：
  - 82 字节 UTF-16 包装不入库；
  - DigestInfo 里的 20/32 字节原始摘要入库；
  - 这些摘要对上现存 PE/INF 时，旧式 CAT 判为有效；
  - 对不上时进入失效清单；
- 对 PE 使用 Authenticode SHA-1/SHA-256；
- 对 INF 文件使用整文件 SHA-1/SHA-256；
- 支持并发哈希扫描；
- 支持扫描、复制、移动和永久删除子命令。

扫描镜像时，默认忽略镜像根目录以下排除项：

```text
\$ntfs.log
\hiberfil.sys
\pagefile.sys
\swapfile.sys
\System Volume Information
\RECYCLER
\Windows\CSC
```

目录排除项会在遍历前直接剪枝，匹配不区分大小写。

不会执行以下操作：

- 验证 CAT 自身的 PKCS#7 签名；
- 验证证书链、有效期或吊销状态；
- 修改离线 SOFTWARE 注册表；
- 没有在线模式，不会自动改用当前系统的 CatRoot；
- 不把普通字体、XML、文本等非 PE/INF 文件纳入匹配。

## 命令行用法

### 扫描

```powershell
CatTrim.exe scan <IMAGE_ROOT> [--jobs <N>] [--log <PATH>]
```

- 不指定 `--log` 时，stdout 只输出失效 CAT 的绝对路径，每行一条，适合直接重定向为 CatLog：

  ```powershell
  CatTrim.exe scan D:\Mount > CatLog.txt
  ```

- 指定 `--log` 时，路径写入文件，stdout 不重复输出路径：

  ```powershell
  CatTrim.exe scan D:\Mount --log D:\Reports\CatLog.txt
  ```

### 复制 CAT

```powershell
CatTrim.exe copy <IMAGE_ROOT> <DEST_DIR> [--select valid|invalid] [--jobs <N>]
```

示例：

```powershell
# 复制有效 CAT
CatTrim.exe copy D:\Mount D:\ValidCat

# 复制无效 CAT
CatTrim.exe copy D:\Mount D:\InvalidCat --select invalid
```

行为：

- 默认复制有效 CAT，指定 `--select invalid` 时复制无效 CAT；
- 不修改源 CAT 文件；
- 自动创建目标目录；
- 不覆盖目标目录中已有的同名文件；
- 同名冲突或复制失败时继续处理其他文件，最终返回退出码 1；
- 扫描存在错误时仍复制所选集合中已经完成分类的 CAT，但由于复制集合可能不完整，最终返回退出码 1。

### 移动无效 CAT

```powershell
CatTrim.exe move <IMAGE_ROOT> <DEST_DIR> [--jobs <N>] [--force]
```

示例：

```powershell
CatTrim.exe move D:\Mount D:\InvalidCat
```

行为：

- 自动创建目标目录；
- 不覆盖目标目录中已有的同名文件；
- stdout 输出移动成功/失败数量；
- 不生成 CatLog；
- 扫描存在解析错误或哈希错误时，默认不修改任何文件，指定 `--force` 后，才会在扫描不完整时继续移动已判定的无效 CAT。

### 删除无效 CAT

```powershell
CatTrim.exe delete <IMAGE_ROOT> [--jobs <N>] [--force] [--clean-registry]
```

示例：

```powershell
# 删除无效 CAT
CatTrim.exe delete D:\Mount

# 删除无效 CAT 并清理注册表
CatTrim.exe delete D:\Mount --clean-registry
```

行为：

- 永久删除扫描判定为无效的 CAT；
- 指定 `--clean-registry` 时挂载离线映像的 SOFTWARE 配置单元，并从 `Packages` 与 `PackageIndex` 清理匹配的 CBS 包项（包括值和嵌套子键）；
- stdout 输出删除成功/失败数量；
- 注册表挂载、枚举、删除或卸载失败时命令返回失败；
- 不生成 CatLog；
- 扫描存在错误时默认不执行删除，指定 `--force` 后才允许在扫描错误状态下继续删除。

> 删除操作不可逆。建议先运行 scan，审阅输出后再执行 move 或 delete。

## 退出码

```text
0  扫描或动作完成且没有错误
1  解析错误、哈希错误、访问错误或复制/移动/删除失败
2  命令行参数错误
```

> 提示：
>
> - `scan`: 即使存在部分错误，也会输出已经确定的失效 CAT，然后返回 1。
> - `copy`: 扫描存在错误时仍复制已经判定的所选 CAT 集合，但由于结果可能不完整而返回 1。
> - `move` 和 `delete`: 在没有 `--force` 时，发现扫描错误会在任何文件修改前退出。

## 判定规则

### CAT 成员

两类摘要会进入签名库，同一个 CAT 内去重。以两个 `0x00` 字节开头的摘要丢弃。

新式成员列表的 OID 是 `1.3.6.1.4.1.311.12.1.3`。找到它之后，收集后续结构里的 20 字节 SHA-1 和 32 字节 SHA-256。

旧式 CAT 使用 OID `1.3.6.1.4.1.311.12.1.2`。程序不靠这个 OID 分支。成员里的文件指纹有两份：

- 82 字节 UTF-16 文本。转成十六进制后长度不是 40 到 64，不入库。
- DigestInfo 中的原始摘要。常见形式是 `SEQUENCE { SEQUENCE { SHA-1 或 SHA-256 OID, NULL }, OCTET STRING }`。同一层依次出现 OID、NULL、OCTET STRING 时同样入库。OCTET STRING 为 20 或 32 字节。

因此旧式 CAT 可以判为有效：原始摘要对上现存 PE 或 INF 即有效，对不上才进入失效清单。

### PE

PE 文件使用 Authenticode 哈希范围：

- 跳过 PE 可选头中的校验和字段；
- 跳过 Security Directory 指向的证书块；
- 对其余文件区间计算 SHA-1 和 SHA-256；
- 使用分块读取处理大型文件。

证书偏移仍在文件内、但声明的证书长度超出文件尾时，从该偏移到文件尾的字节仍然不参与哈希。文件会算出摘要并参与匹配。stderr 记一条 `Hash warning`，它不算扫描错误，也不阻止 `move` 或 `delete`。证书偏移越过文件尾，或与校验和、证书目录项重叠时，仍是 `Hash error`。

### INF

扩展名大小写不敏感。INF 文件直接对整个文件计算 SHA-1 和 SHA-256，不使用 Authenticode 规则。

### 有效和失效

设：

- H(cat) 为 CAT 的成员摘要集合；
- F(image) 为镜像中 PE/INF 产生的摘要集合。

判定为：

```text
H(cat) 与 F(image) 有交集 -> 有效 CAT
H(cat) 与 F(image) 无交集 -> 失效 CAT
```

解析失败的 ASN.1 文件不会进入失效列表，并会单独计入 Parse errors。结构完整但没有任何可入库摘要的 CAT，仍以空成员集合进入失效列表。

## 构建

需要 Rust 和 Cargo。

```powershell
cargo build --release
```

发布文件位于：

```text
target\release\CatTrim.exe
```

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request！

## 参考

[CAT签名批量检查工具](https://bbs.wuyou.net/forum.php?mod=viewthread&tid=423164)
