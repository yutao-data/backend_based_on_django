# 虚拟布展系统后端

# 依赖
- python3
- django `pip install django`
- guardian `pip install django-guardian`
- pymysql `pip install pymysql`
- mysql，具体设置在setting.py中

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
- 展览负责人（能更改所属exhibition下所有展厅的信息）
- 超级管理员

## 实现
- 上传展品
    1. 给用户添加object权限
    2. 给对应scene.group添加object权限
- 查询展品
    1. 检查用户是否有展品的object权限，无关展品属于哪个展厅
- 创建展厅
    1. 添加一个group = Group
- 更改展品作者
    1. 删除源用户的object权限
    2. 设置新用户的object权限
- 删除展品
    1. 删除展品作者的object权限
    2. 删除对应scene.group的object权限
- 结构
    - 所用用户属于对应类型的组，如`artist_group`/`teacher_group`/`stuff_group`/`superuser_group`
    - 普通用户artist不属于任何组，他们只有自己展品的object权限
    - 老师teacher属于scene.group组，该组拥有scene内所有item的object权限，和对应scene的object权限
    - 策展管理员stuff属于特定策展组`exhibition_group`，该组拥有策展内所有scene的object权限
    - 站点管理员`superuser`，`is_superuser`属性为`True`，可以登陆`django.contrib.admin`面板控制整个网站

