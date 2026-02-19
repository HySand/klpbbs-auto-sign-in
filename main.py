# GitHub: https://github.com/xyz8848/KLPBBS_auto_sign_in

import http
import logging
import os
import smtplib
import sys
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from http import cookiejar

import cloudscraper
import requests
from bs4 import BeautifulSoup

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

username = os.environ.get("USERNAME")
password = os.environ.get("PASSWORD")

switch_user = int(os.environ.get("SWITCH_USER") or 0)
renewal_vip = int(os.environ.get("RENEWAL_VIP") or 0)
renewal_svip = int(os.environ.get("RENEWAL_SVIP") or 0)

debug = int(os.environ.get("DEBUG") or 0)

mail_enable = int(os.environ.get("MAIL_ENABLE") or 0)
mail_host = os.environ.get("MAIL_HOST")
mail_port = int(os.environ.get("MAIL_PORT") or 0)
mail_username = os.environ.get("MAIL_USERNAME")
mail_password = os.environ.get("MAIL_PASSWORD")
mail_to = os.environ.get("MAIL_TO") or []

wechat_enable = int(os.environ.get("WECHAT_ENABLE") or 0)
wechat_webhook = os.environ.get("WECHAT_WEBHOOK")
wechat_mentioned = os.environ.get("WECHAT_MENTIONED") or []

serverchan_enable = int(os.environ.get("SERVERCHAN_ENABLE") or 0)
serverchan_key = os.environ.get("SERVERCHAN_KEY")

ntfy_enable = int(os.environ.get("NTFY_ENABLE") or 0)
ntfy_url = os.environ.get("NTFY_URL") or "https://ntfy.sh"
ntfy_topic = os.environ.get("NTFY_TOPIC")
ntfy_username = os.environ.get("NTFY_USERNAME")
ntfy_password = os.environ.get("NTFY_PASSWORD")
ntfy_token = os.environ.get("NTFY_TOKEN")

# 设置日志级别和格式
if debug == 1:
    logging.basicConfig(
        level=logging.DEBUG, format="[%(levelname)s] [%(asctime)s] %(message)s"
    )
    logging.info("Debug mode enabled.")
else:
    logging.basicConfig(
        level=logging.INFO, format="[%(levelname)s] [%(asctime)s] %(message)s"
    )
    logging.info("Debug mode disabled.")

userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Edg/116.0.1938.81"

header = {
    "origin": "https://klpbbs.com",
    "Referer": "https://klpbbs.com/",
    "User-Agent": userAgent,
}

session = cloudscraper.create_scraper(
    browser={
        "browser": "chrome",
        "platform": "windows",
        "mobile": False,
    }
)
session.cookies = http.cookiejar.LWPCookieJar()

base_url = "https://klpbbs.com"


def login(username: str, password: str):
    """
    登录苦力怕论坛
    """
    post_url = f"{base_url}/member.php?mod=logging&action=login&loginsubmit=yes"
    post_data = {
        "username": username,
        "password": password,
    }

    response_res = session.post(post_url, data=post_data, headers=header)
    logging.debug(f"statusCode = {response_res.status_code}")
    logging.debug(response_res.text)

    header["Cookie"] = "; ".join(
        [f"{cookie.name}={cookie.value}" for cookie in session.cookies]
    )


def get_url():
    """
    获取签到链接
    """
    html_source = session.get(f"{base_url}/", headers=header)
    logging.debug(html_source.text)
    soup = BeautifulSoup(html_source.text, "html.parser")
    a_tag = soup.find("a", class_="midaben_signpanel JD_sign")
    if a_tag is not None:
        href_value = a_tag["href"]
        sign_in_url = f"{base_url}/{href_value}"

        logging.debug(f"签到链接：{sign_in_url}")

        if sign_in_url == "https://klpbbs.com/member.php?mod=logging&action=login":
            logging.info("签到链接异常（原因：登录失败）")
            exit(1)

        logging.info("已成功获取签到链接")

        return sign_in_url
    else:
        is_sign_in()
        return None


def sign_in(sign_in_url: str):
    """
    签到
    """
    session.get(sign_in_url, headers=header)


def is_sign_in():
    """
    检测是否签到成功
    """
    html_source = session.get(f"{base_url}/", headers=header)
    logging.debug(html_source.text)
    soup = BeautifulSoup(html_source.text, "html.parser")
    a_tag = soup.find("a", class_="midaben_signpanel JD_sign visted")
    if a_tag is not None:
        href_value = a_tag["href"]
        if href_value == "k_misign-sign.html":
            logging.info("已成功签到")
            notice("已成功签到！")
            exit(0)

    logging.info("签到失败")
    notice("签到失败")
    exit(1)


def notice(msg: str):
    if mail_enable == 1:
        email_notice(msg)
    if wechat_enable == 1:
        wechat_notice(msg)
    if serverchan_enable == 1:
        serverchan_notice(msg)
    if ntfy_enable == 1:
        ntfy_notice(msg)


def email_notice(msg: str):
    message = MIMEMultipart()
    message["From"] = mail_username
    message["To"] = mail_to
    message["Subject"] = msg
    body = f"<h1>苦力怕论坛自动签到</h1><br><br>{msg}"
    message.attach(MIMEText(body, "html"))

    try:
        server = smtplib.SMTP(mail_host, mail_port)
        server.starttls()
        server.login(mail_username, mail_password)
        server.send_message(message)
        logging.info("邮件发送成功")
    except smtplib.SMTPException as error:
        logging.error(error)


def wechat_notice(msg: str):
    data = {
        "msgtype": "text",
        "text": {
            "content": f"苦力怕论坛自动签到\n\n{msg}",
            "mentioned_list": wechat_mentioned,
        }
    }
    session.post(wechat_webhook, json=data)


def serverchan_notice(msg: str):
    url = f"https://sctapi.ftqq.com/{serverchan_key}.send"
    data = {"title": "苦力怕论坛自动签到", "desp": msg}
    session.post(url, data=data)


def ntfy_notice(msg: str):
    auth = None
    if ntfy_token:
        auth = requests.auth.HTTPBasicAuth("", ntfy_token)
    elif ntfy_username and ntfy_password:
        auth = requests.auth.HTTPBasicAuth(ntfy_username, ntfy_password)

    url = f"{ntfy_url.rstrip('/')}/{ntfy_topic}"
    headers = {"Title": "苦力怕论坛自动签到"}
    session.post(url, data=msg.encode("utf-8"), headers=headers, auth=auth)


if __name__ == "__main__":
    login(username, password)
    url = get_url()
    sign_in(url)
    is_sign_in()
