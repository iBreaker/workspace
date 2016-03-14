#!/usr/bin/env python
#!coding=utf-8


import scrapy
from scrapy.contrib.spiders import CrawlSpider, Rule
from scrapy.contrib.linkextractors import LinkExtractor

class DmozSpider(scrapy.Spider):
    name = "ookcode"
    allowed_domains=["ookcode.com"]
    start_urls = [
            "http://blog.ookcode.com/"
            ]
    rules = (
        # 提取匹配 'category.php' (但不匹配 'subsection.php') 的链接并跟进链接(没有callback意味着follow默认为True)
        Rule(LinkExtractor(deny=('subsection\.php', ))),
    ) 

    def parse(self, response):
        filename = response.url.split("/")[-2]
        with open(filename, 'wb') as f:
            f.write(response.body)
