

-------------------------------------------------------------------
IDA Comments Viewer for IDA pro 7.0
===================
Version:1.0 alpha

plugin by obaby

[http://www.h4ck.org.cn](http://www.h4ck.org.cn) 

[http://findu.co](http://findu.co)

![Screenshot](https://github.com/obaby/CommentView-4-IDAPRO-7.0/blob/master/screenshot.png?raw=true)

自从ida升级7.0 之后，hexrays做了很多的改动，以前的插件基本都废掉了。于是想要找个插件就变得很困难，最近分析一个文件需要获取所有的注释，但是那个针对低版本开发的commentview已经无力回天了。虽然晚上有开源的代码，但是实际修改起来比较蛋疼，不知道是不是ida的问题，编译的插件获取的地址基本都是错误的。还是按照以前的使用区段枚举，和inf信息获取的方法获取到的地址都错了，着tm就很尴尬了

于是只好改变思路，使用idapython来做，由于以前没怎么用python写过插件，所以到处找代码折腾了这么个东西。好歹是满足了需求了，如果有更多的需求自己修改代码吧。如果做了修改麻烦提交下改动，谢谢。

文章链接：
[ http://www.h4ck.org.cn/2018/01/commentview-plugin-for-idapro7-0/]( http://www.h4ck.org.cn/2018/01/commentview-plugin-for-idapro7-0/)
