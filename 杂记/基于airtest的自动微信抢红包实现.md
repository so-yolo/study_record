使用的是自动化测试工具airtest由网易出品

使用前请将调试的设备权限调成开发者模式，或搜索MTP调节

本代码通过内置poco功能的图像识别定位实现

```
# -*- encoding=utf8 -*-
__author__ = "Administrator"
import queue
from airtest.core.api import *

auto_setup(__file__)

from poco.drivers.android.uiautomation import AndroidUiautomationPoco
poco=AndroidUiautomationPoco(use_airtest_input=True, screenshot_each_action=False)

#寻找设备中的app的定位名
# dev=device()
# print(dev.list_app(third_only=True))

# start_app('com.tencent.mm')

title_name='黎佳欣'
poco(text=title_name).click()

msg_elements=[]
    
while(True):
    messiage=poco(name='com.tencent.mm:id/b4t')
    for it in messiage:
        msg_elements.insert(0,it)
    
    for msg in msg_elements:
        via=msg.offspring(name='com.tencent.mm:id/a3u')
        jia=msg.offspring(name='com.tencent.mm:id/a3m')
        try:
            print('<<<<'+via.get_text()+'>>>>')
            print('<<<<'+jia.get_text()+'>>>>')
        except:
            print('存在 恭喜发财，大吉大利。正在测试有无领取')
            via.click()
            poco(desc='开').click()
            keyevent("BACK")
            
```

![[Pasted image 20241211154649.png]]
![[Pasted image 20241211154712.png]]

