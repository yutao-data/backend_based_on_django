# API
目录

- `/api/login/`
- `/api/logout/`
- `/api/exhibitionadd/`
- `/api/exhibitionlist/`
- `/api/exhibition/<int:exhibition_id>/info/`
- `/api/sceneadd/`
- `/api/scenelist/`
- `/api/exhibition/<int:exhibition_id>/scene/<int:scene_id>/`
- `/api/exhibition/<int:exhibition_id>/scene/<int:scene_id>/info/`
- `/api/exhibition/<int:exhibition_id>/scene/<int:scene_id>/file/`
- `/api/exhibition/<int:exhibition_id>/scene/<int:scene_id>/itemadd/`
- `/api/exhibition/<int:exhibition_id>/scene/<int:scene_id>/itemlist/`
- `/api/exhibition/<int:exhibition_id>/item/<int:item_id>/`
- `/api/exhibition/<int:exhibition_id>/item/<int:item_id>/info/`
- `/api/exhibition/<int:exhibition_id>/item/<int:item_id>/file/`


# !!!
API最后一定要用/结尾否则引发500错误

## 说明
- POST数据用JSON格式
- 如无特殊说明，成功操作返回 `{ "message": "Success" }`
- 错误返回如无特殊说明，返回`{ "error_type": "Error Type", "error_message": "Error Info" }`

## Reference

### login

#### POST /api/login/
```json
{
  "username": "UserName",
  "password": "woshimima",
}
```

#### 200
```json
{
  "user_type": "aritist/stuff/manager/superuser",
}
```
分别对应展品提供者、策展团队成员、展览负责人、超级管理员
#### 403 用户名或密码错误

### 登出

#### GET /api/logout/

#### 200

### 获取展厅列表

#### GET /api/scenelist/

#### 200
```json
[
    { "name": "SceneName", "id": 3, "file": "upload/scene_model_file_1a2b3c.obj" },
    ...
]
```

#### 403 没有权限


### 下载展厅模型

#### GET /api/exhibition/<int:exhibition_id>/scene/<int:scene_id>/file/

#### 200
传回文件数据流，文件名位于header中  
`Content-Disposition: inline; filename="i_am_file_name_1a2b3c.obj"`

#### 403 没有权限


### 上传展厅模型

#### POST /api/exhibition/<int:exhibition_id>/scene/<int:scene_id>/file/
HTTP Form 类型
"file" -> 文件
"data" -> Json字符串,用于附带额外信息

#### 200
```json
{
  "scene": {
    "name": "SceneName",
    "file": "I_am_file_name_1a2b3c.obj",
    "id": 3,
  }
}
```
如果上传的文件名，已经存在于服务器upload目录，Django会自动在文件名后添加随机字符串，如`filename_1a2b3c.obj`，上传成功后，文件名会在`scene.file`中返回


### 添加展厅

#### POST /api/exhibition/<int:exhibition_id>/sceneadd/
```json
{
  "scene": {
    "name": "SceneName"
  }
}
```

#### 200
```json
{
  "scene": {
    "name": "SceneName",
    "id": 3
  }
}
```

#### 400 添加失败

#### 403 没有权限


### 修改展厅信息

#### POST /api/exhibition/<int:exhibition_id>/scene/<int:scene_id>/info/
```json
{
  "scene": {
    "name": "SceneName"
  }
}
```

#### 403 没有权限

#### 404 找不到展厅


### 删除展厅

#### DELETE /api/exhibition/<int:exhibition_id>/scene/<int:scene_id>/

#### 200

#### 403 没有权限

#### 404没有展厅


### 展品列表

#### GET /api/exhibitioin/<int:exhibition_id>/scene/<int:scene_id>/itemlist/

#### 200
```json
{
  "item_list": [
    {
      "name": "ItemName",
      "id": 3,
      "author": "UserName",
      "author_id": 16,
      "pos_x": 3.9,
      "pos_y": 1.8,
      "pos_z": 6.0,
      "rot_x": 1.0,
      "rot_y": 1.0,
      "rot_z": 1.0,
      "rot_w": 1.0,
      "scl_x": 1.1,
      "scl_y": 1.1,
      "scl_z": 1.1,
    },
    ...
  ]
}
```

#### 403 没有权限


### 添加展品

#### POST /api/exhibition/<int:exhibition_id>/scene/<int:scene_id>/itemadd/
```json
{
  "item": {
    "name": "ItemName",
    "author_id": 16
  }
}
```

#### 200
```json
{
  "item": {
    // 参见展品列表返回数据
}
```

#### 403 没有权限


### 获取展品模型

#### GET /api/exhibition/<int:exhibition_id>/item/<int:item_id>/file/
二进制数据

#### 403 没有权限

#### 404 找不到模型文件


### 修改展品信息

#### POST /api/exhibition/<int:exhibition_id>/item/<int:item_id>/info/
```json
{
  "item": {
    "name": "ItemName",
    "id": 39,
    "author": "UserName",
    "author_id": 16,
    "file": "Item_model_file_1a2b3c.obj"
  }
}
```


### 删除模型

#### DELETE /api/exhibition/<int:exhibition_id>/item/<int:item_id>/

#### 403 没有权限

#### 404 找不到模型

