# 虚拟布展系统后端

# 权限
## 用户类型
- 普通用户User（展品上传者）
    - 可以上传展品  
    - 可以修改自己展品的信息  
    - 不能修改别人展品的信息  
    - 所有展品外链一个普通用户
- 策展团队成员(某个/多个展厅的管理员)
    - 能更改展厅内所有物品
    - 只能更改范围内的展厅
- 展览负责人（能更改所有展厅的信息）
- 超级管理员

## 实现
- 上传展品
    1. 给用户添加object权限
    2. 给对应scene.group添加object权限
- 创建展厅
    1. 添加一个group = Group
- 更改展品作者
    1. 删除源用户的object权限
    2. 设置新用户的object权限
- 删除展品
    1. 删除展品作者的object权限
    2. 删除对应scene.group的object权限
- 结构
    - 普通用户artist不属于任何组，他们只有自己展品的object权限
    - 老师teacher属于scene.group组，该组拥有scene内所有item的object权限，和对应scene的object权限
    - 策展管理员stuff拥有item和scene的全局权限，可以管理所有物体
    - 站点管理员superuser / Site Administrator，is_superuser属性为True，可以登陆django.contrib.admin面板控制整个网站

# todo
1. 注册时选择用户类型
2. 管理用户面板根据用户类型过滤
3. Dashboard右上角显示用户类型
