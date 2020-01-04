# LBR_micro_explorer

可配置化的LBR通用子链浏览器

### 准备环境

* 保证您的主机已经安装node环境, 如还未安装，请参考[这里](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm) 
* 保证您的主机已经安装node express环境, 如还未安装，请参考[这里](http://expressjs.com/en/starter/installing.html) 
* 保证您的主机已经安装mongdb, 如还未安装，请参考[这里](https://docs.mongodb.com/manual/installation/) 

此项目发布时，运行环境为node v10.15.3, express v6.9.0, mongo v3.6.4, 请保证安装时不低于此版本。

### 依赖安装

环境配置完成后，到项目的根目录下(/mcExplorer)，执行如下指令，安装依赖包

```
npm install
```

### 配置文件

依赖安装完成后，请根据自己需求，修改项目中配置文件（路径：/mcExplorer/userconfig.json）

* mongoHost - mongodb数据库服务器，格式为ip:port(如121.43.129.11:10010)
* mongoUserName - mongodb数据库服务器用户名
* mongoPwd - mongodb数据库服务器密码
* dbname - 当前项目数据库名称
* vnodeHost - LBR主网节点服务器，格式为ip:port(如120.78.146.128:8545)
* microChainAddress - 当前子链地址(大小写通用，页面显示统一处理为小写)
* monitorHosts - 子链monitor服务器，格式为数组（如["47.106.34.55:8546", "47.106.34.56:8546"]）
* dappName - 子链应用名称
* tunnel - 子链rpc调用方式（rpc或rpc debug）
* community_item1 - 页面header community部分下拉列表一
* community_item1_url - 下拉列表一链接
* community_item2 - 页面header community部分下拉列表二
* community_item2_url - 下拉列表二链接

以上凡涉及host格式，请勿在开头添加http://, 保证“:”前后无空格。

### Logo
如需自定义项目logo，请修改您的logo图片名称为logo.png，并覆盖至/mcExplorer/public/img路径下。

### 启动

以上安装与配置都完成后，可到根目录(/mcExplorer)启动项目，如下：

```
node app
```
启动后在浏览器输入：http://localhost:3001, 方可查看项目启动情况, 默认监听端口为3001，您可在根目录下app.js文件中修改端口。
除此之外，您还可以根据自己情况，配置pm2方式启动，或在第三方IDE中启动项目。

## Version

0.1.0

## License
The project is licensed under the GNU Lesser General Public License v3.0, also included in our repository in the LICENSE file.



