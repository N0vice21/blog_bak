---
title: 记从indigo主题换到next主题的坑
date: 2020-01-19 00:30:41
tags: 笔记
---
一直想把主题换成与大师傅们一样的主题，之前换过一次报错了就索性放弃了，前天开始又捡起来改配置文件  <!--more-->

关于解决“下一页”显示成代码的方法  
![](xyy.png)
进入路径D:/Myblog/themes/next/layout/_partials/pagination.swig  
将代码改成
```javascript
{%- if page.prev or page.next %}
 <nav class="pagination">
   {{
     paginator({
       prev_text: '<i class="fa fa-angle-left" aria-label="'+__('accessibility.prev_page')+'"></i>',
       next_text: '<i class="fa fa-angle-right" aria-label="'+__('accessibility.next_page')+'"></i>',
       mid_size: 1,
       escape: false
     })
   }}
 </nav>
```
关于解决点击菜单栏页面之后404的问题  
本地预览显示
```
Cannot GET /%20/
```
放到github上之后直接404，而且地址栏的地址，本来应该是url/tags/，但是他显示url/tags/%20，好像就是多了一个/，所以我们要把这个/删掉，只需要在主题配置文件里面把
```
tag: / || tags
```
改成
```
tag: /|| tags
```
就可以了，就是把||前面的空格删除就行了  
解决点击日志跳转错误
![](rzcw1.png)
![](rzcw2.png)
进入theme-next/layout/_macro/sidebar.swig文件中找到
```javascript
<a href="{{ url_for(theme.menu.archives).split('||')[0] | trim }}">
```
原因是url_for函数将||转码了，将其改成
```javascript
<a href="{{ url_for(theme.menu.archives.split('||')[0])| trim}}">
```
就可以了  

参考链接:  
https://blog.csdn.net/lihangll/article/details/103335246  
https://www.zhihu.com/question/353097489  
http://theme-next.iissnan.com/theme-settings.html#author-sites  
https://www.jianshu.com/p/9f0e90cc32c2  
https://blog.csdn.net/luxiongzuishuai/article/details/100999129