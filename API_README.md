# API

## 说明
- POST数据用JSON格式
- 如无特殊说明，成功操作返回 `{ "message": string }`
- 错误返回如无特殊说明，返回`{ "error_type": string, "error_message": string }`

## Reference

### login

#### POST /gallery/api/login
```json
{
  "username": string,
  "password": string,
}
```

#### 200
```json
{
  "scene_list": [
    { "id": int, "name": string,},
    ...
  ],
  "user_type": string,
}
```
#### 401 密码错误


### 展厅列表

#### GET gallery/api/scenelist

#### 200
```json
{
  "scene_list": [
    { "name": string, "id": int, "file": string },
    ...
  ],
}
```

#### 403 没有权限


### 下载展厅模型

#### GET gallery/api/scene/<int:id>/file

#### 200
二进制文件数据流

#### 403 没有权限


### 上传展厅模型
待定


### 添加展厅

#### POST gallery/api/sceneadd
```json
{
  "scene": {
    "name": string
  }
}
```

#### 200
```json
{
  "scene": {
    "name": string,
    "id": int
  }
}
```

#### 400 添加失败

#### 403 没有权限


### 修改展厅信息

#### POST gallery/api/scene/<int:scene_id>/info/
```json
{
  "scene": {
    "scene_name": string
  }
}
```

#### 403 没有权限

#### 404 找不到展厅


### 删除展厅

#### DELETE gallery/api/scene/<int:scene_id>/

#### 200

#### 403 没有权限

#### 404没有展厅


### 展品列表

#### GET gallery/api/scene/<int:scene_id>/itemlist/

#### 200
```json
{
  "item_list": [
    {
      "name": string,
      "id": int,
      "author": string(username),
      "x": float,
      "y": float,
      "z": float,
      "roatation": float,
      "scale": float,
    },
    ...
  ]
}
```

#### 403 没有权限


### 添加展品

#### POST gallery/api/scene/<int:scene_id>/itemadd/
```json
{
  "item": {
    "name": string,
    "author": string(username)
  }
}
```

#### 200
```json
{
  "item": {
    "name": string,
    "id": int,
    "author": string(username),
    "file": string
}
```

#### 403 没有权限


### 获取展品模型

#### GET gallery/api/scene/<int:scene_id>/item/<int:item_id>/file/
二进制数据流

#### 403 没有权限

#### 404 找不到模型文件


### 修改展品信息

#### POST gallery/api/scene/<int:scene_id>/item/<int:item_id>/info/
```json
{
  "item": {
    "name": string,
    "id": int,
    "author": string(username),
    "file": string
  }
}
```


### 删除模型

#### DELETE gallery/api/scene/<int:scene_id>/item/<int:item_id>/

#### 403 没有权限

#### 404 找不到模型

