## 策略（strategy）

策略就是agent的主要实现


一个策略的核心，就是一个核心LLM的对话循环

LLM是核心，可以自由控制工具，获得想要的结果。


目前，我认为我们实现一个非常solid的单独策略即可


pov策略，patch策略是两种不同的策略


# POV寻找逻辑

Controller在创建完worker后（每个worker有自己的fuzzer和sanitizer）

会



这是一个基于