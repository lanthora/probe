# Go 调用链追踪方法

跟踪从收到一个网络请求到发送出与之对应的响应之间的所有所有网络请求.

根据上述描述,构建一个最简单的 Go 版本的服务.当收到 8080 端口请求时,向上游发送 HTTP 请求, 并根据上游的返回结果设置响应码.
上游是 MySQL, Redis 等服务时与此模型一致.

```golang
package main

import (
	"net/http"
)

func test(w http.ResponseWriter, req *http.Request) {
	resp, err := http.Get("http://localhost")
	if err != nil {
		w.WriteHeader(500)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(200)
}

func main() {
	http.HandleFunc("/", test)
	http.ListenAndServe(":8080", nil)
}
```

对于一个请求,至少包含四个报文.

1. 接收来自外部的请求
2. 作为客户端请求上游
3. 接收来自上游的响应
4. 给外部发送响应

对于不使用协程模型的语言,例如如C, C++ 和 Java 19 前的版本(Java 19 开始支持虚拟线程,即协程),一般在同一个线程内完成上述步骤.
对于 Go 程序,由于其本身的协程调度,已经无法使用线程进行追踪.此外,上述流程也不是在同一个协程中完成的.
本文的目的就是解答如何追踪 Go 程序的调用链,也就是需要一个在 Go 中可以代替其他语言线程号的数据.

## 原始数据与解释

以下数据来源于对上述 Go 服务的探针.

```log
[INFO  probe::golang] newproc: tgid=25670, callerid=1, newid=37
[INFO  probe::syscall] read: goid=37, opid=37, fd=4, ret=78
[INFO  probe::golang] newproc: tgid=25670, callerid=37, newid=38
[INFO  probe::golang] newproc: tgid=25670, callerid=37, newid=39
[INFO  probe::syscall] write: goid=39, opid=37, fd=7, ret=1
[INFO  probe::golang] newproc: tgid=25670, callerid=39, newid=40
[INFO  probe::golang] newproc: tgid=25670, callerid=40, newid=41
[INFO  probe::syscall] read: goid=41, opid=37, fd=8, ret=65
[INFO  probe::syscall] write: goid=39, opid=37, fd=7, ret=1
[INFO  probe::golang] newproc: tgid=25670, callerid=39, newid=42
[INFO  probe::golang] newproc: tgid=25670, callerid=39, newid=43
[INFO  probe::golang] newproc: tgid=25670, callerid=39, newid=44
[INFO  probe::syscall] write: goid=44, opid=37, fd=8, ret=90
[INFO  probe::syscall] read: goid=37, opid=37, fd=6, ret=1
[INFO  probe::syscall] read: goid=43, opid=37, fd=8, ret=853
[INFO  probe::syscall] write: goid=37, opid=37, fd=4, ret=75
```

现在仅需要关注 probe::syscall read 和 write 操作的协程号 goid 和 fd.
上述数据中对 fd 为 6 和 7 的读写操作不是网络操作,略去.
opid 字段是最终的效果, 略去.

```log
[INFO  probe::syscall] read: goid=37, fd=4, ret=78
[INFO  probe::syscall] read: goid=41, fd=8, ret=65
[INFO  probe::syscall] write: goid=44, fd=8, ret=90
[INFO  probe::syscall] read: goid=43, fd=8, ret=853
[INFO  probe::syscall] write: goid=37, fd=4, ret=75
```

fd 为 4 的是处理外部请求相应的 socket, fd 为 8 的是向上游请求响应的 socket.
请求上游时分别使用了 41, 43, 44 三个协程号, 对应代码中的

```golang
http.Get("http://localhost")
```

在 Go 中,作为客户端的实现一般会在 socket 创建后会先创建协程准备获取响应,再发送请求.
而 __这一切的开始都是 goid 为 37 的读操作__.如果我们能把上述操作的 goid 都统一到 37 就可以替代线程号.

于是我们再来看一下协程的创建行为.

```log
[INFO  probe::golang] newproc: tgid=25670, callerid=1, newid=37
[INFO  probe::golang] newproc: tgid=25670, callerid=37, newid=38
[INFO  probe::golang] newproc: tgid=25670, callerid=37, newid=39
[INFO  probe::golang] newproc: tgid=25670, callerid=39, newid=40
[INFO  probe::golang] newproc: tgid=25670, callerid=40, newid=41
[INFO  probe::golang] newproc: tgid=25670, callerid=39, newid=42
[INFO  probe::golang] newproc: tgid=25670, callerid=39, newid=43
[INFO  probe::golang] newproc: tgid=25670, callerid=39, newid=44
```

上述数据用树结构表示.

```txt
- 1 
  - 37
    - 38
    - 39
      - 40
        - 41
      - 42
      - 42
      - 44
```

## 追溯算法描述

可见如果仅通过协程创建行为追踪,必将最终到 1 号协程.当配合上先前的描述: _这一切的开始都是 goid 为 37 的读操作_.

向前追溯的算法描述为:

1. 获取原始协程的父协程
2. 检查父协程是否为最终祖先
3. 如果为最终祖先,跳转到 6
4. 如果当前父协程还存在父协程,更新父协程,跳转到 2
5. 设置原始协程为最终祖先,跳转到 6
6. 返回最终祖先

算法的返回结果也就是日志中的 opid.

```log
[INFO  probe::syscall] read: opid=37, fd=4, ret=78
[INFO  probe::syscall] read: opid=37, fd=8, ret=65
[INFO  probe::syscall] write: opid=37, fd=8, ret=90
[INFO  probe::syscall] read: opid=37, fd=8, ret=853
[INFO  probe::syscall] write: opid=37, fd=4, ret=75
```

## 存在的问题

### 追溯层次过多

追溯的退出条件依赖 __某个协程的读写操作__ ,如果协程号为 1 的协程有一个读写操作,并且被记录为了最终祖先,将导致所有追溯出的协程号都为 1.
因此在进入追溯算法前,应该过滤去除无关请求.

## 追溯层次过少

为了避免追溯层次过多,判定祖先时添加超时时间,这个时间应当略大于业务中可能存在的最长的请求响应时间,超时即认为是无效祖先.
如果这个值设置的小于了正常业务的处理事件,将导致追溯层次过少.

对于算法描述中的第 4 步,是查询当前协程与父协程映射的 map.
但是更新 map 的 Hook 点在协程创建完成后(此时才能知道子协程号)触发.
因此 __可能__ 出现先查 map 再更新 map 的情况,此时 map 查找失败会直接进入步骤 5.
