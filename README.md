# 虚拟布展系统后端

## configure

## runserver

## 数据库结构

- 没有全局用户组，用户类型是相对于Exhibition的

- 策展 Exhibition
    - 自定权限: `modify_item` `modify_tool` `modify_scene` `modify_exhibition`
    - scene 字段指向一个Scene，表示该策展使用该Scene
    - users 包含所有属于该Exhibition的用户，便于查询
    - aritsts 用户组拥有`modify_item`权限
    - stuffs 用户组拥有`modify_item` `modify_tool`权限
    - managers 用户组拥有`modify_item` `modify_tool` `modify_scene` `modify_exhibition`权限
    - 在用户组内即拥有策展的相应权限

- 展厅 Scene
    - 用于被Exhibition选择
    - author 展厅作者

- 展品 Item
    - author 展品作者

## 权限检查策略
- 展品增删改
    1. 检查exhibition的`item_exhibition`object权限
    2. 对于修改操作，检查是否属于artists组，如果是，检查该展品的作者是不是当前用户
- 道具删改查
    1. 检查exhibition的`tool_exhibition`object权限
- 展厅增删改
    1. 检查exhibition的`scene_exhibition`object权限
    2. 对于修改操作，检查是否属于manager组，如果是，检查该展厅的作者是不是当前用户
- 展览增删改
    1. 检查exhibition的`change_exhibition`object权限

## 实现细节
- 注册
    1. 用户注册提供用户名等基本信息
    2. 用户属于哪个展览为可选
    3. 用户类型artist/stuff/manager/superuser为可选
        - artist: 将用户添加到exhibition的users和artists组
        - stuffs: 将用户添加到exhibition的users和stuffs组
        - manager: 将用户添加到exhibition的users和managers组
        - superuser: 用户`is_superuser`属性设为True
- 添加展品 POST `/gallery/api/exhibition/1/scene/2/itemadd/`
    1. 如果用户在exhibition内的类型为artist，设置item的作者为当前用户
    2. 否则设置item作者为制定用户
- 修改展品 POST `/gallery/api/exhibition/1/item/3/info/`
- 删除展品 DELETE `/gallery/api/exhibition/1/item/3/`
- 增加展厅 POST `/gallery/api/exhibition/1/sceneadd/`
    1. 如果用户在exhibition内的类型为manager，设置scene的作者为当前用户
    2. 否则设置scene作者为当前用户
- 修改展厅 POST `/gallery/api/exhibition/1/scene/3/info/`
- 删除展厅 DELETE `/gallery/api/exhibition/1/scene/3/`
- 添加展览 POST `/gallery/api/exhibitionadd/`
    1. 选择展厅
- 修改展览 POST `/gallery/api/exhibition/1/info/`
- 删除展览 DELETE `/gallery/api/exhibition/1/`
