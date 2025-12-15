# 重构指南：

目的：为了更好的和llm结合，我们决定使用python对整个库进行重写

1. go的部分将完全由python代替
2. static analysis的部分暂时不变
3. competition-api的一部分改写成python，并融入进crs中


## 运行命令
./FuzzingBrain <github_repo_url>


## 重构后的架构：

以下全部内容docker化：

重构后的CRS可以被视为是一个MCP tool，别人可以将

github repo link
commit id （可选）
fuzz-tooling的链接 （可选）

发至我们的服务器（用fastmcp搭建）

然后我们的CRS对其进行解析，以及策略处理

其中，我们的CRS可以又被视为一个MCP，由一个核心的AI Agent控制，通过调用不同的工具来实现漏洞的查找和修补

也可以用户直接在本地运行，传入文件夹路径等参数

除此之外，原来的各种功能将被集合进去当做不同的tool，其中现在我能想到的有：
1. 阅读代码块，函数块
2. 运行fuzzer，并检查输出
3. 生成pov
4. 打包pov
5. 运行动态分析
6. 查看静态分析结果
7. 生成patch
8. pov验证
9. 单元测试验证
10. 多个pov去重

等一系列工具/操作


除此之外，为了Evaluate我们的crs，我们还需要一个evaluator

它会记录：
1. LLM调用的api用量，详细记录类别
2. 每个工具/步骤需要的时间
3. 每个task有多少个策略在跑，有多少个pov，patch找到了？
4. 当前的pov/patch的记录
等等所有的信息

这一部分我们先不用管

总而言之，我们的主要架构由

MainCRS （综合mcp服务）

- Controller（中心CRS， 负责解析任务，分配fuzzer给不同的worker）
- CRS Worker（AI-Agent，负责pov/patch的生成）
- static-analysis模块（负责在项目开始时提供必要信息）
- fuzzing 模块（无LLM，纯fuzzing， 可接受由LLM指导的种子）


Evaluation Service：
- Evaluator：监控crs的健康，运行情况

## 运行逻辑
假设一个repo，是oss-fuzz based的，它有20个fuzzer。

Controller会将 每一个fuzzer单独由{address， memory， UB}构建。并且分配至一个worker。

因此一个worker会拿到一个{address，sanitizer}对

也就是说对于这一个任务，我们动态开60个worker节点

每一个节点都是一个crs

他会根据任务类型，跑相应的策略



## 进度0：技术选型 （参考）

1. 整个软件架构是一个可以被MCP调用的mcp tool，因此我们用fastmcp实现再适合不过了
2. 数据库的话，用mongodb
3. 


## 进度1：搭建fastmcp server (未完成)：

### 目标0：数据模型的搭建 （未完成）
在开始之前，必须明确每个数据模型的参数，意义，这样便于我们监控/统一编程接口

粒度：
1. Task: 一个task就是一次对fuzzingbrain的使用，它可以是：
    - 找pov
    - 找patch
    - 生成harness
    - 根据sarif-report找bug

它应该拥有如下属性
    - task_id: 我们分配，可用于查询当前任务进度
    - task_type: pov, patch, pov-patch, harness, 代表不同的类别
    - task_status: cancelled (用户自己cancel), pending （等待中）, running, completed, error
    - is_sarif_check: 如果输入有sarif，说明可能是根据sarif report进行bug验证（其实就是生成pov）或者修补
    - is_fuzz_tooling_provided: 检测fuzz-tooling是否提供，比如有的项目采用oss-fuzz标准fuzzing框架，可以更好的利用
    - create_time: 创建时间
    - running_time: 当前task运行时间
    - pov (这是个pov的集合，里面放所有找到的pov)
    - patch（patch的集合，里面放所有找到的patch）
    - sarif（sarif的集合，里面放用户输入的，需要验证的sarif）
    - task_path: task的workspace路径
    - src_path: task中，被测试代码的路径
    - fuzz_tooling_path: task中，测试suite的路径
    - diff_path: 对于delta-scan任务，需要提供一个commit_id，然后crs下载下来commit文件后，放入文件夹中，分配给task
    

2. pov (或者叫pov_detail)
    重要：pov在我们这里叫proof-of-Vulnerability，和广义的poc很像，对于当前版本，我们只支持oss-fuzz的项目，因此pov可以简单的理解为一次fuzzing input的生成

    一次fuzzing input的生成，就代表着或许成功触发bug，或许失败，因此我们有一个is_successful的参数

    - _id: 自生成
    - task_id (只有这个是必须的): 隶属于哪个task？
    - description：对于当前pov的描述
    - sanitizer_output: fuzzer在当前sanitizer的基础上的report
    - harness_name: 被什么harness检测到的？
    - gen_blob: Python代码，用于生成该漏洞的输入
    - blob: base64编码过后的blob内容
    - msg_history: LLM在生成这个pov时的聊天记录
    - create_time: 这个pov发现的时间
    - is_successful: 该pov是否是一个成功的
    - is_active: true/false (实际运行中，有可能很多个pov实际上重复，为了减小我们去重系统的开销，我们将所有失败/重复的pov deactive掉)
    - architecture：x86_64 (固定)
    - engine: libfuzzer （固定）
    - sanitizer: address/ubsan/memory, 目前数据集全是address，可以在当前版本固定


3. patch (或者叫patch_detail)
    重要：patch的成功与否，取决于两个要素 - 1.是否通过pov检查，2.是否跑通所有测试（如果提供测试）
    - _id: 自生成
    - pov_id (opt): 注意，这个是可选项，如果用户直接patch，可能没有这个pov_id
    - task_id: 隶属于哪个task？
    - description：对于当前patch的描述
    - pov_detail: 用户传入的pov_detail
    - apply_check: true/false 是否能够正确被打入程序
    - compilation_check: t/f 在打补丁后，程序是否正常编译？
    - pov_check: true/false 是否通过了pov测试？不再触发漏洞为true
    - test_check: t/f 是否通过了所有的回归测试
    - is_active: 用于补丁去重（功能暂时未实现）
    - create_time: 创建时间
    - msg_history: 聊天记录

4. Sarif
（暂不处理）


5. Harness:
    很多开源程序的harness数量很少，导致覆盖率很少，因此对于生成harness的task来说，可能会有多个harness最后被生产，Harness就代表着一个harness
    - _id: 同
    - task_id: 同
    - target_function: 可以是一个函数，也可以是一个模块
    - fuzzing_entry: harness的测试入口 
    - coverage_report: 记录{函数：覆盖率}对
    - build_check: 是否能被构建？
    - source_code: 源代码
    - description: 设计思路&如何构建
Harness的生成逻辑仍需讨论


5. function
    作为可疑点分析的基本，函数分析是原crs的重要的一环，我们可以继续采用老crs的办法，不过这里我们要将函数单独提取出来，作为一个基础单位
    我们将所有fuzzer可达的函数全部列出来，因为我们是基于fuzzer找漏洞，因此可以分析的函数也只是fuzzer可达的。

    但是将函数放入数据库有风险，因为几千个函数同时被建模输入进数据库，会有极大的开销和内存占用。因此这部分需要探讨。

    - _id: 自己产生，但是好像用不到
    - task_id:
    - function_name: 函数名称
    - class_name: java专用，用于记录类
    - file_name: 文件名
    - start_line: 起始行
    - end_line: 终止行
    - suspecious_points: 这个函数里面的可疑点, 可以用id做个list
    - score：分数，有可能产生真实bug的可能性
    - is_important: t/f 如果此flag为true，该函数将会直接放置到队列头部等待进行可疑点分析
    


6. suspicious point：
    可疑点分析是重构后的crs的精髓，以前的crs采用的是函数级分析，因此可能会忽略重合在一个函数里的不同bug，或者是检测不到一些细节性的bug。
    一个可疑点，就是一次行级分析
    - _id: 自生成id
    - task_id: 属于哪个task
    - function_id: 属于哪个function
    - description: 可疑点的细致描述，我们不用具体的行，因为llm不擅长生成行数
    - is_check: 所有可疑点均需二次验证，该验证由LLM完成，LLM通过description获得控制流，然后进行验证
    - is_real: 如果agent认为这是一个真实的bug，则判为real
    - score：分数，用于队列
    - is_important: LLM分析为真实后，如果被认定为可能性非常大的bug，将直接设置为true并进入队首进行pov分析



### 目标1 API搭建：
    所有api命名逻辑应遵循:
    localhost:xxxx/v1/api/pov
    localhost:xxxx/v1/api/patch

    此处的工具，是对外的工具，不是对内（不是我们crs mcp的）

    工具1：POV查找
        工具名称：FuzzingBrain-pov
        对外暴露接口：/api/v1/pov
        描述：对指定github repo进行扫描/输出pov
        参数：repo link, commit id(optional), fuzz-tooling link(optional), fuzz-tooling commit (opt)， sarif-report（opt）
        返回：task_id, 密钥供查询，这是因为任务不可能这么快完成

        最终输出：pov_detail (储存在数据库中)
    
    工具2：patch生成
        工具名称：FuzzingBrain-patch
        对外暴露接口：/api/v1/patch
        描述：对指定repo，pov进行修复，生成patch
        参数：pov_detail
        返回：task_id, 密钥供查询

        最终输出：patch_detail (储存在数据库中)

    工具3: POV + Patch一条龙
        工具名称：FuzzingBrain-pov-patch
        对外暴露接口：/api/v1/pov-patch
        描述：对指定repo进行漏洞检测+修补
        参数：repo link, commit id(optional), fuzz-tooling link(optional), fuzz-tooling commit (opt)， sarif-report（opt）
        返回：task_id, 密钥供查询

        最终输出：上述两个都有

    工具4: harness生成
        工具名称：FuzzingBrain-harness
        对外接口：/api/v1/harness-generation
        描述：对指定repo生成更多的harness从而提高覆盖率
        参数：repo link，commit id（这是用于指定版本，opt）， fuzz-tooling link(optional), fuzz-tooling commit (opt)，个数（默认1），指定函数/module（也就是fuzzing的对象功能）
        返回：task_id, 密钥供查询

        最终输出：harness_report
    


## 进度2：业务相关逻辑 （未完成）

### 目标2 基本任务处理：
这一部分包括，解析任务，构建task，如何跑fuzzer，如何跑test，提交pov，提交patch,等

1. 解析任务
    - 直接照抄原来go的代码即可
    - 注意，现在我们的crs分为本地模式和请求模式
        - 请求模式：用户发送http请求至fuzzingbrain服务器，由我们的服务器处理，比如说克隆，下载代码
        - 本地模式：用户在自己电脑上使用，通过传入文件夹等参数来运行
    
2. 构建任务：
    - 直接照抄原来的代码即可



## 进度3：并发业务相关逻辑 （未完成）


## 进度4：静态分析服务器接口